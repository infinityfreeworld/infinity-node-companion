//! `AuthService` — façade qui orchestre pairing + verify.
//!
//! Une instance par companion. Tient :
//!   - `Vault` partagé (pour persistance des paired devices)
//!   - `Identity` du companion (utilisée pour signer les acks de pairing
//!     et pour exposer `companion_pubkey` à la PWA)
//!   - `PairingTokenStore` interne (en RAM)
//!
//! Thread-safe : prévu pour être tenu derrière un `Arc<AuthService>`
//! et appelé depuis plusieurs handlers HTTP en parallèle.

use std::sync::Arc;
use std::time::Duration;

use infinity_identity::{Identity, PublicKey};
use infinity_vault::Vault;

use crate::pairing::{PairingToken, PairingTokenStore};
use crate::session::{verify_signature, SignatureHeader};
use crate::store::{
    add_device, get_device, list_devices, remove_device, touch_device_last_seen,
};
use crate::{AuthError, PairedDevice};

/// Façade publique du module auth.
pub struct AuthService {
    vault: Arc<Vault>,
    companion_identity: Arc<Identity>,
    tokens: PairingTokenStore,
}

impl AuthService {
    /// Construit le service. Les `Arc` sont attendus partagés avec
    /// le reste du companion (HTTP handlers, tray, supervisor).
    #[must_use]
    pub fn new(vault: Arc<Vault>, companion_identity: Arc<Identity>) -> Self {
        Self {
            vault,
            companion_identity,
            tokens: PairingTokenStore::new(),
        }
    }

    /// Pubkey du companion (pour que la PWA puisse vérifier les acks
    /// signés ensuite, et pour identifier visuellement à quel
    /// companion elle est appairée).
    #[must_use]
    pub fn companion_public_key(&self) -> PublicKey {
        self.companion_identity.public_key()
    }

    // ── Pairing ──────────────────────────────────────────────────────

    /// Génère un nouveau pairing token éphémère (à afficher dans la tray).
    /// TTL : passe `None` pour utiliser `DEFAULT_PAIRING_TTL` (10 min).
    #[must_use]
    pub fn create_pairing_token(&self, ttl: Option<Duration>) -> PairingToken {
        self.tokens
            .create(ttl.unwrap_or(crate::pairing::DEFAULT_PAIRING_TTL))
    }

    /// Complète le pairing après que l'utilisateur a copié-collé le
    /// token dans la PWA. Persiste la device pubkey dans le vault.
    ///
    /// Renvoie le `PairedDevice` enregistré (peut être affiché côté
    /// PWA pour confirmation visuelle).
    ///
    /// # Errors
    /// - `InvalidPairingToken` si le token est inconnu/expiré
    /// - `DeviceAlreadyPaired` si cette pubkey est déjà appairée
    /// - `Vault` si l'écriture metadata échoue
    pub fn complete_pairing(
        &self,
        token: &str,
        device_pubkey: &PublicKey,
        device_label: &str,
    ) -> Result<PairedDevice, AuthError> {
        // Étape 1 : consume le token (one-shot). Si fail, on n'écrit rien.
        self.tokens.consume(token)?;
        // Étape 2 : persiste le device. Si fail, le token est perdu mais
        // la sécurité est préservée (le user recommence le pairing).
        let pubkey_hex = device_pubkey.to_hex();
        add_device(&self.vault, &pubkey_hex, device_label)
    }

    // ── Verify ───────────────────────────────────────────────────────

    /// Vérifie une requête authentifiée :
    ///   1. Pubkey du header est appairée (lookup vault)
    ///   2. Timestamp dans la fenêtre tolérée
    ///   3. Signature valide sur `(pubkey:ts:sha256(body))`
    ///   4. Touch `last_seen_at` du device (best-effort, non-bloquant)
    ///
    /// Renvoie le `PairedDevice` correspondant (utile pour logger
    /// / autoriser au niveau handler).
    ///
    /// # Errors
    /// - `DeviceNotPaired`, `StaleTimestamp`, `BadSignature`, `MalformedHeader`
    pub fn verify_request(
        &self,
        header: &SignatureHeader,
        body: &[u8],
    ) -> Result<PairedDevice, AuthError> {
        // 1. Device dans vault ? (avant la crypto pour fail fast cheap)
        let device = get_device(&self.vault, &header.pubkey_hex)?
            .ok_or(AuthError::DeviceNotPaired)?;

        // 2 + 3. Crypto + window.
        verify_signature(header, body)?;

        // 4. Best-effort update last_seen.
        touch_device_last_seen(&self.vault, &header.pubkey_hex);

        Ok(device)
    }

    // ── Gestion des devices ──────────────────────────────────────────

    /// Liste tous les paired devices (triés par paired_at ascendant).
    pub fn list_devices(&self) -> Result<Vec<PairedDevice>, AuthError> {
        list_devices(&self.vault)
    }

    /// Révoque un device par sa pubkey hex. Idempotent.
    /// Après révocation, toutes les requêtes futures de ce device
    /// renverront `DeviceNotPaired`.
    pub fn revoke_device(&self, pubkey_hex: &str) -> Result<(), AuthError> {
        remove_device(&self.vault, pubkey_hex)
    }
}
