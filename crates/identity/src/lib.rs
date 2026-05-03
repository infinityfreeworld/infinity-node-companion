//! # infinity-identity — identité Ed25519 souveraine du Bâtisseur
//!
//! Stockage hybride :
//!   - **Clé privée** (32-byte seed) → Keychain OS via `keyring`
//!     (Apple Keychain, Windows Credential Manager, Linux Secret Service)
//!   - **Clé publique + metadata** → vault chiffré (`infinity-vault`)
//!
//! ## Garanties
//!
//! - Le seed ne quitte JAMAIS le secret store en clair, sauf au moment
//!   de signer (fenêtre RAM courte, wipe automatique au Drop).
//! - Sanity check à `load()` : pubkey re-dérivée depuis le seed comparée
//!   à celle du vault → détecte une substitution dans le Keychain.
//! - Signatures Ed25519 déterministes (RFC 8032) — même message + même
//!   clé → toujours même signature.
//! - Atomicité `create()` : rollback Keychain si écriture vault fail.
//!
//! ## Usage
//!
//! ```ignore
//! use infinity_identity::{Identity, OsKeyring};
//! use infinity_vault::Vault;
//!
//! let vault = Vault::open(path, passphrase)?;
//! let kc = OsKeyring::new();
//!
//! // Génère + persiste (1ʳᵉ fois)
//! let id = Identity::create(&vault, &kc, "default", "Mon Bâtisseur")?;
//! println!("pubkey: {}", id.public_key());
//!
//! // Recharge sessions futures
//! let id = Identity::load(&vault, &kc, "default")?;
//! let sig = id.sign(b"challenge from PWA");
//!
//! // Vérification (PWA → companion)
//! Identity::verify(&id.public_key(), b"challenge from PWA", &sig)?;
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::doc_markdown)]

mod identity;
mod keypair;
mod secret_store;

pub use crate::identity::{Identity, IdentityMetadata, SECRET_STORE_SERVICE};
pub use crate::keypair::{
    Keypair, PublicKey, Signature, PUBLIC_KEY_LEN, SECRET_SEED_LEN, SIGNATURE_LEN,
};
pub use crate::secret_store::{MemoryKeyring, OsKeyring, SecretStore};

use thiserror::Error;

/// Erreurs publiques du crate identity.
#[derive(Error, Debug)]
pub enum IdentityError {
    /// Une identité du même nom existe déjà (vault ou Keychain).
    #[error("identity already exists with this name")]
    AlreadyExists,

    /// Identité demandée introuvable (ni vault ni Keychain).
    #[error("identity not found")]
    NotFound,

    /// La pubkey re-dérivée depuis le seed Keychain ne matche pas
    /// celle stockée dans le vault. Indication possible de substitution
    /// du secret dans le Keychain (attaque ou corruption).
    #[error("public key derived from secret store does not match vault — possible tampering")]
    KeyMismatch,

    /// Seed reçu n'a pas la bonne taille (32 bytes attendus pour Ed25519).
    #[error("invalid seed length: expected {expected}, got {got}")]
    InvalidSeedLength {
        /// Taille attendue (32 pour Ed25519).
        expected: usize,
        /// Taille reçue.
        got: usize,
    },

    /// Bytes de clé publique de mauvaise taille.
    #[error("invalid public key length: expected {expected}, got {got}")]
    InvalidPublicKeyLength {
        /// Taille attendue (32 pour Ed25519).
        expected: usize,
        /// Taille reçue.
        got: usize,
    },

    /// Bytes ne sont pas un point valide sur la courbe Ed25519.
    #[error("invalid public key (not on curve)")]
    InvalidPublicKey,

    /// Signature de mauvaise taille.
    #[error("invalid signature length: expected {expected}, got {got}")]
    InvalidSignatureLength {
        /// Taille attendue (64 pour Ed25519).
        expected: usize,
        /// Taille reçue (0 si parse hex a fail avant).
        got: usize,
    },

    /// Signature ne vérifie pas contre `(public_key, message)`.
    /// Erreur générique volontaire (anti enum d'attaque).
    #[error("signature verification failed")]
    BadSignature,

    /// Metadata vault corrompue (JSON invalide, hex pubkey malformé).
    #[error("identity metadata is corrupted")]
    Corrupted,

    /// Le secret store OS n'est pas disponible (Linux sans gnome-keyring,
    /// runtime headless sans D-Bus, etc.). Le user doit installer un
    /// daemon Secret Service pour continuer.
    #[error("OS secret store unavailable (install gnome-keyring or KWallet on Linux)")]
    SecretStoreUnavailable,

    /// Le secret store contient des données qu'on ne peut pas décoder.
    #[error("OS secret store data is corrupted")]
    SecretStoreCorrupted,

    /// Erreur générique du secret store (passe le message du backend).
    #[error("OS secret store error: {0}")]
    SecretStoreOther(String),

    /// Erreur du vault sous-jacent.
    #[error("vault error: {0}")]
    Vault(#[from] infinity_vault::VaultError),

    /// Erreur de (dé)sérialisation JSON.
    #[error("serialization error: {0}")]
    Serde(String),
}
