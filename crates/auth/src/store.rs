//! Persistance des paired devices dans le vault chiffré.
//!
//! Schéma : namespace `auth`, clés `device:<pubkey_hex>` → JSON
//!
//! Format JSON :
//! ```json
//! {
//!   "pubkey_hex":   "abcd...",
//!   "label":        "Chrome — MacBook",
//!   "paired_at":    1714742400,
//!   "last_seen_at": 1714746000
//! }
//! ```
//!
//! Le vault chiffre tout (cf. `infinity-vault`) — un attaquant qui
//! gagnerait l'accès au disque ne pourrait pas énumérer les devices.

use infinity_vault::Vault;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::AuthError;

/// Namespace vault dédié à l'auth.
const VAULT_NAMESPACE: &str = "auth";

/// Préfixe des clés "device:". Permet le listing scoped + dispose
/// d'une marge si on ajoute d'autres types d'entrées dans `auth`.
const DEVICE_KEY_PREFIX: &str = "device:";

/// Représentation publique d'un appareil appairé.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairedDevice {
    /// Clé publique Ed25519 du device, hex 64 chars.
    pub pubkey_hex: String,
    /// Label user-display (ex. "Chrome — MacBook").
    pub label: String,
    /// Timestamp unix du pairing initial.
    pub paired_at: i64,
    /// Timestamp unix de la dernière requête vérifiée.
    pub last_seen_at: i64,
}

/// Crée et persiste un nouveau paired device.
pub(crate) fn add_device(
    vault: &Vault,
    pubkey_hex: &str,
    label: &str,
) -> Result<PairedDevice, AuthError> {
    let ns = vault.namespace(VAULT_NAMESPACE);
    let key = format!("{DEVICE_KEY_PREFIX}{pubkey_hex}");
    if ns.get(&key)?.is_some() {
        return Err(AuthError::DeviceAlreadyPaired);
    }
    let now = now_unix();
    let device = PairedDevice {
        pubkey_hex: pubkey_hex.to_string(),
        label: label.to_string(),
        paired_at: now,
        last_seen_at: now,
    };
    let json = serde_json::to_vec(&device).map_err(|e| AuthError::Serde(e.to_string()))?;
    ns.put(&key, &json)?;
    Ok(device)
}

/// Lit un device par sa pubkey hex. `Ok(None)` si pas appairé.
pub(crate) fn get_device(
    vault: &Vault,
    pubkey_hex: &str,
) -> Result<Option<PairedDevice>, AuthError> {
    let ns = vault.namespace(VAULT_NAMESPACE);
    let key = format!("{DEVICE_KEY_PREFIX}{pubkey_hex}");
    let Some(bytes) = ns.get(&key)? else {
        return Ok(None);
    };
    let device: PairedDevice =
        serde_json::from_slice(&bytes).map_err(|e| AuthError::Serde(e.to_string()))?;
    Ok(Some(device))
}

/// Met à jour `last_seen_at` au timestamp courant. Best-effort :
/// si la lecture/écriture fail (corruption rare), on log et on continue
/// — ne doit JAMAIS bloquer une requête authentifiée valide.
pub(crate) fn touch_device_last_seen(vault: &Vault, pubkey_hex: &str) {
    let Ok(Some(mut device)) = get_device(vault, pubkey_hex) else {
        return;
    };
    device.last_seen_at = now_unix();
    let Ok(json) = serde_json::to_vec(&device) else {
        return;
    };
    let ns = vault.namespace(VAULT_NAMESPACE);
    let key = format!("{DEVICE_KEY_PREFIX}{pubkey_hex}");
    let _ = ns.put(&key, &json);
}

/// Retire un device — le rend immédiatement non-authentifié.
/// Idempotent : pas d'erreur si déjà absent.
pub(crate) fn remove_device(vault: &Vault, pubkey_hex: &str) -> Result<(), AuthError> {
    let ns = vault.namespace(VAULT_NAMESPACE);
    let key = format!("{DEVICE_KEY_PREFIX}{pubkey_hex}");
    ns.delete(&key)?;
    Ok(())
}

/// Liste tous les paired devices. Triés par `paired_at` ascendant
/// (plus ancien d'abord) pour stabilité d'affichage.
pub(crate) fn list_devices(vault: &Vault) -> Result<Vec<PairedDevice>, AuthError> {
    let ns = vault.namespace(VAULT_NAMESPACE);
    let mut out = Vec::new();
    for k in ns.list()? {
        let Some(pubkey_hex) = k.strip_prefix(DEVICE_KEY_PREFIX) else {
            continue; // pas une entrée device
        };
        if let Some(device) = get_device(vault, pubkey_hex)? {
            out.push(device);
        }
    }
    out.sort_by_key(|d| d.paired_at);
    Ok(out)
}

fn now_unix() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    )
    .unwrap_or(i64::MAX)
}
