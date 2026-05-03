//! # infinity-vault — coffre-fort chiffré local
//!
//! Pierre angulaire du Tier 1 d'Infinity Node. Stocke toutes les
//! données sensibles (CIDs pinés, identité Ed25519 *Phase 2.C*,
//! settings modules, secrets app) dans une SQLite chiffrée.
//!
//! ## Stack crypto
//!
//! - **KDF** : Argon2id memory-hard (OWASP 2024 — 64 MiB / 3 iter / 4 lanes)
//! - **Storage** : SQLCipher 4 (AES-256-CBC page-level + HMAC-SHA512)
//! - **Mémoire** : `zeroize` wipe au drop, `secrecy::SecretString` anti-leak
//!
//! La clé maître est dérivée par Argon2id puis passée à SQLCipher en
//! raw key mode → ~1000× plus cher à brute-forcer que PBKDF2 seul.
//!
//! ## Architecture fichier
//!
//! Sur disque : 2 fichiers par vault.
//! - `<name>.ifv`       : DB SQLCipher (chiffrée)
//! - `<name>.salt.json` : header KDF (salt + params, public)
//!
//! ## Modèle de données
//!
//! Une seule table `kv(namespace, key, value, created_at, updated_at)`
//! avec PRIMARY KEY composite. Les **namespaces** isolent logiquement
//! les usages (`identity`, `ipfs`, `nostr`, `module:cube`...).
//!
//! ```ignore
//! use infinity_vault::Vault;
//! use secrecy::SecretString;
//!
//! let vault = Vault::create(
//!     "/path/to/vault.ifv".into(),
//!     SecretString::new("correcthorsebatterystaple".into()),
//! )?;
//!
//! let identity = vault.namespace("identity");
//! identity.put("ed25519_secret", &key_bytes)?;
//!
//! let ipfs = vault.namespace("ipfs");
//! ipfs.put("pin:bafy...", b"metadata")?;
//! assert_eq!(ipfs.list()?.len(), 1);
//!
//! // Wipe ciblé d'un namespace sans toucher aux autres
//! vault.namespace("test").clear()?;
//! ```
//!
//! ## Garanties (testées en `tests/vault_integration.rs`)
//!
//! - Round-trip put/get préservant les bytes exactement
//! - Persistence après drop + open avec la même passphrase
//! - Mauvaise passphrase → `WrongPassphrase` (pas de timing leak)
//! - Tampering du fichier → `Corrupted` (HMAC SQLCipher)
//! - `change_passphrase` atomique (rollback si fail mid-process)
//! - Isolation namespaces : `put("ipfs", k)` invisible depuis "identity"

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]   // documenté au niveau des méthodes
// La doc est en français et mentionne souvent des termes propres
// (SQLCipher, Argon2id, NOSTR, IPFS, OWASP) qui ne sont PAS du code.
// `doc_markdown` veut tout backticker → trop bruyant ici.
#![allow(clippy::doc_markdown)]
// On passe les SecretString PAR VALEUR pour qu'elles soient consommées
// + droppées (donc zeroize) à la fin de la fonction. Référence ferait
// rester la passphrase chez l'appelant inutilement.
#![allow(clippy::needless_pass_by_value)]

mod crypto;
mod namespace;
mod store;
mod vault;

pub use crate::namespace::Namespace;
pub use crate::vault::Vault;

use thiserror::Error;

/// Erreurs publiques du vault. Format simple — jamais ne fuit la
/// passphrase ni la clé dérivée même via `Display`.
#[derive(Error, Debug)]
pub enum VaultError {
    /// Le fichier (ou son sidecar) existe déjà à `create()`.
    #[error("vault file already exists at this path")]
    AlreadyExists,

    /// Le fichier (ou son sidecar) n'existe pas à `open()`.
    #[error("vault file not found")]
    NotFound,

    /// Passphrase incorrecte. Erreur **générique volontaire** : pas
    /// de timing-leak ni de message qui distingue "fichier absent"
    /// vs "mauvaise clé". L'attaquant ne sait pas pourquoi ça fail.
    #[error("invalid passphrase")]
    WrongPassphrase,

    /// Passphrase < `MIN_PASSPHRASE_LEN` chars.
    #[error("passphrase does not meet minimum strength requirements")]
    WeakPassphrase,

    /// Fichier altéré ou corrompu (HMAC mismatch SQLCipher, JSON
    /// sidecar invalide, ou version non supportée).
    #[error("vault data integrity check failed (tampering or corruption)")]
    Corrupted,

    /// Erreur SQL sous-jacente. Détail technique uniquement — ne fuit
    /// jamais des données chiffrées (rusqlite Display est safe).
    #[error("storage error: {0}")]
    Sql(#[from] rusqlite::Error),

    /// Erreur I/O système (permissions, disque plein, etc).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Paramètres Argon2id recommandés OWASP 2024.
/// Référence : <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>
pub mod kdf_params {
    /// Memory cost en KiB (= 64 MiB).
    pub const MEMORY_KIB: u32 = 64 * 1024;
    /// Nombre d'itérations.
    pub const ITERATIONS: u32 = 3;
    /// Parallélisme (lanes).
    pub const PARALLELISM: u32 = 4;
    /// Taille de la clé dérivée (bytes) — 32 = 256 bits, requis par SQLCipher.
    pub const OUTPUT_LEN: usize = 32;
    /// Taille du salt (bytes).
    pub const SALT_LEN: usize = 32;
}

/// Longueur minimale de la passphrase.
/// 8 = compromis usability/sécurité, OK avec Argon2id memory-hard.
pub const MIN_PASSPHRASE_LEN: usize = 8;
