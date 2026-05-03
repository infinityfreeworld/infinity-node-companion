//! Abstraction sur le secret store OS.
//!
//! En prod : `OsKeyring` qui parle à Apple Keychain / Windows Credential
//! Manager / Linux Secret Service via le crate `keyring`.
//!
//! En tests : `MemoryKeyring` qui simule en RAM. Indispensable pour le
//! CI où aucun Keychain OS n'est disponible (et où on ne veut surtout
//! pas polluer le vrai Keychain de la machine de build).
//!
//! Le trait [`SecretStore`] est intentionnellement **minimal** :
//! `set` / `get` / `delete` sur `(service, account)`. Toute la logique
//! crypto + le hashing du seed Ed25519 vit dans `keypair.rs` —
//! ce module ne fait que stocker des bytes opaques.

use crate::IdentityError;

/// Contrat d'un secret store : mappe `(service, account)` à des bytes
/// opaques. L'implémentation est libre quant au backend (OS Keychain,
/// fichier chiffré, mémoire pour tests, HSM...).
pub trait SecretStore: Send + Sync {
    /// Stocke `secret` sous l'identifiant composite `(service, account)`.
    /// Écrase si la clé existait.
    fn set(&self, service: &str, account: &str, secret: &[u8]) -> Result<(), IdentityError>;

    /// Lit le secret. `None` si la clé n'existe pas.
    /// Le retour est `Vec<u8>` plutôt que `&[u8]` car le keyring OS
    /// alloue à chaque call (la clé peut être dans une enclave HW).
    fn get(&self, service: &str, account: &str) -> Result<Option<Vec<u8>>, IdentityError>;

    /// Supprime le secret. Idempotent — pas d'erreur si absent.
    fn delete(&self, service: &str, account: &str) -> Result<(), IdentityError>;
}

// ── Impl prod : OsKeyring ────────────────────────────────────────────

/// Implémentation backed par le Keychain OS via le crate `keyring`.
///
/// Backends activés (cf. `Cargo.toml`) :
///   - macOS   : Apple Keychain (apple-native)
///   - Windows : Credential Manager (windows-native)
///   - Linux   : Secret Service / D-Bus (linux-native-sync-persistent)
///
/// Sur Linux, requiert un Secret Service runtime (gnome-keyring, KWallet).
/// Si aucun n'est disponible, les opérations renvoient
/// [`IdentityError::SecretStoreUnavailable`].
pub struct OsKeyring;

impl OsKeyring {
    /// Crée une instance OsKeyring (zéro coût, le crate `keyring` ne
    /// connecte le backend qu'au 1ᵉʳ appel `set` / `get`).
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for OsKeyring {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretStore for OsKeyring {
    fn set(&self, service: &str, account: &str, secret: &[u8]) -> Result<(), IdentityError> {
        let entry = keyring::Entry::new(service, account).map_err(map_keyring_err)?;
        // keyring v3 : set_secret pour les bytes raw (vs set_password pour UTF-8).
        // On stocke 32 bytes binaires → set_secret obligatoire.
        entry.set_secret(secret).map_err(map_keyring_err)?;
        Ok(())
    }

    fn get(&self, service: &str, account: &str) -> Result<Option<Vec<u8>>, IdentityError> {
        let entry = keyring::Entry::new(service, account).map_err(map_keyring_err)?;
        match entry.get_secret() {
            Ok(bytes) => Ok(Some(bytes)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(map_keyring_err(e)),
        }
    }

    fn delete(&self, service: &str, account: &str) -> Result<(), IdentityError> {
        let entry = keyring::Entry::new(service, account).map_err(map_keyring_err)?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(map_keyring_err(e)),
        }
    }
}

/// Convertit les erreurs `keyring` en variantes `IdentityError`. On
/// distingue "pas de keyring dispo" (Linux sans daemon) du reste pour
/// donner un message utilisateur exploitable.
fn map_keyring_err(e: keyring::Error) -> IdentityError {
    match e {
        keyring::Error::PlatformFailure(_) | keyring::Error::NoStorageAccess(_) => {
            IdentityError::SecretStoreUnavailable
        }
        keyring::Error::Invalid(_, _) | keyring::Error::BadEncoding(_) => {
            IdentityError::SecretStoreCorrupted
        }
        // NoEntry est filtré en amont (mappé vers Ok(None) / Ok(()) selon op)
        // mais on couvre quand même ici par sécurité.
        keyring::Error::NoEntry => IdentityError::SecretStoreCorrupted,
        other => IdentityError::SecretStoreOther(other.to_string()),
    }
}

// ── Impl tests : MemoryKeyring ───────────────────────────────────────

/// Implémentation in-memory pour les tests. Les secrets vivent dans
/// une `HashMap` protégée par `Mutex` — pas de persistance, pas de
/// vraie sécurité. **Ne JAMAIS utiliser en prod**.
///
/// Disponible aussi en debug builds via la feature default — pratique
/// pour les démos sans dépendre d'un Keychain installé.
pub struct MemoryKeyring {
    inner: std::sync::Mutex<std::collections::HashMap<(String, String), Vec<u8>>>,
}

impl MemoryKeyring {
    /// Crée un secret store in-memory vide.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

impl Default for MemoryKeyring {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretStore for MemoryKeyring {
    fn set(&self, service: &str, account: &str, secret: &[u8]) -> Result<(), IdentityError> {
        let mut map = self
            .inner
            .lock()
            .map_err(|_| IdentityError::SecretStoreOther("mutex poisoned".into()))?;
        map.insert((service.to_string(), account.to_string()), secret.to_vec());
        Ok(())
    }

    fn get(&self, service: &str, account: &str) -> Result<Option<Vec<u8>>, IdentityError> {
        let map = self
            .inner
            .lock()
            .map_err(|_| IdentityError::SecretStoreOther("mutex poisoned".into()))?;
        Ok(map.get(&(service.to_string(), account.to_string())).cloned())
    }

    fn delete(&self, service: &str, account: &str) -> Result<(), IdentityError> {
        let mut map = self
            .inner
            .lock()
            .map_err(|_| IdentityError::SecretStoreOther("mutex poisoned".into()))?;
        map.remove(&(service.to_string(), account.to_string()));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_keyring_set_get_delete() {
        let kr = MemoryKeyring::new();
        assert!(kr.get("svc", "acc").unwrap().is_none());

        kr.set("svc", "acc", b"secret_data").unwrap();
        assert_eq!(kr.get("svc", "acc").unwrap().unwrap(), b"secret_data");

        kr.set("svc", "acc", b"updated").unwrap();
        assert_eq!(kr.get("svc", "acc").unwrap().unwrap(), b"updated");

        kr.delete("svc", "acc").unwrap();
        assert!(kr.get("svc", "acc").unwrap().is_none());

        // delete idempotent
        kr.delete("svc", "acc").unwrap();
    }

    #[test]
    fn memory_keyring_isolates_by_account() {
        let kr = MemoryKeyring::new();
        kr.set("svc", "alice", b"alice_key").unwrap();
        kr.set("svc", "bob", b"bob_key").unwrap();
        assert_eq!(kr.get("svc", "alice").unwrap().unwrap(), b"alice_key");
        assert_eq!(kr.get("svc", "bob").unwrap().unwrap(), b"bob_key");
    }
}
