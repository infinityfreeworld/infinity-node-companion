//! # infinity-auth — pont d'auth PWA ↔ Companion
//!
//! ## Threat model
//!
//! Sans auth : `127.0.0.1:7474` est accessible par TOUT site web visité
//! (CSRF + DNS rebinding + extensions navigateur). N'importe quel JS
//! pourrait alors lire le vault chiffré, demander des signatures avec
//! la clé Ed25519 du Bâtisseur, lister les peers IPFS, accéder au
//! cache NOSTR. C'est un trou de sécurité critique inhérent au modèle
//! PWA + service local.
//!
//! Mitigations en place dans ce crate :
//!
//! 1. **Pairing out-of-band** : un token éphémère (32 bytes aléatoires)
//!    est affiché par le companion dans la tray native (popup que SEUL
//!    l'utilisateur assis devant la machine peut voir). Le user le copie
//!    manuellement dans la PWA. Sans posséder le token, impossible de
//!    s'appairer — bloque les attaques drive-by depuis un site malveillant.
//!
//! 2. **Tokens one-shot + expiration courte** : chaque pairing token est
//!    invalidé après usage et expire en 10 min par défaut. Empêche
//!    qu'un token leak (ex. screenshot) reste exploitable longtemps.
//!
//! 3. **Signatures Ed25519 par requête** : après pairing, chaque appel
//!    HTTP/WS embarque une signature `(pubkey, timestamp, body_hash)`
//!    couvrant tout le payload. Anti-tampering + non-replay.
//!
//! 4. **Window timestamp ±60s** : protection replay basique. Une
//!    requête capturée n'est rejouable qu'une fois la fenêtre fermée.
//!
//! 5. **Devices identifiables + révocables** : l'utilisateur peut
//!    voir la liste des appareils appairés et révoquer un device perdu.
//!
//! ## Format du header `Authorization`
//!
//! ```text
//! Authorization: InfinitySig <pubkey_hex>:<timestamp>:<signature_hex>
//!
//! où :
//!   pubkey_hex     = 64 chars (32 bytes Ed25519, hex lower)
//!   timestamp      = i64 unix seconds, ASCII decimal
//!   signature_hex  = 128 chars (64 bytes Ed25519, hex lower)
//! ```
//!
//! ## Message canonique signé
//!
//! ```text
//! <pubkey_hex>:<timestamp>:<sha256(body)_hex>
//! ```
//!
//! Le body_hash est SHA-256(body) en hex lower. Pour les requêtes
//! sans body (GET), body est `b""` → hash est SHA-256 du vide
//! (`e3b0c44...`). C'est canonique : l'attaquant ne peut pas substituer
//! le body sans recalculer la signature → impossible sans la clé privée.
//!
//! ## Workflow complet
//!
//! ```ignore
//! use infinity_auth::AuthService;
//! use std::sync::Arc;
//!
//! let auth = AuthService::new(vault.clone(), companion_identity.clone());
//!
//! // 1. PWA demande un pairing → tray affiche le token
//! let token = auth.create_pairing_token(Duration::from_secs(600))?;
//! tray::show_pairing_popup(&token.token);
//!
//! // 2. User copie le token dans la PWA, qui appelle :
//! let result = auth.complete_pairing(&token_from_user, &device_pubkey, "Chrome — MacBook")?;
//!
//! // 3. Requêtes futures vérifiées :
//! let device = auth.verify_request(&header, body)?;
//! tracing::info!("authenticated as {}", device.label);
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::doc_markdown)]

mod pairing;
mod service;
mod session;
mod store;

pub use crate::pairing::{PairingToken, DEFAULT_PAIRING_TTL};
pub use crate::service::AuthService;
pub use crate::session::{canonical_message, SignatureHeader, MAX_TIMESTAMP_SKEW_SECS};
pub use crate::store::PairedDevice;

use thiserror::Error;

/// Erreurs publiques du crate auth.
#[derive(Error, Debug)]
pub enum AuthError {
    /// Le pairing token fourni est inconnu (expiré ou jamais émis).
    /// Erreur générique : on ne distingue pas pour ne pas leak l'info.
    #[error("invalid pairing token")]
    InvalidPairingToken,

    /// Le pairing token a expiré.
    #[error("pairing token expired")]
    PairingTokenExpired,

    /// La device pubkey n'est pas appairée — appel à `verify_request`
    /// avec une pubkey inconnue (= attaque ou pairing perdu).
    #[error("device is not paired")]
    DeviceNotPaired,

    /// Le timestamp de la requête est trop éloigné de l'heure courante
    /// (anti-replay : fenêtre par défaut ±60s).
    #[error("request timestamp out of acceptable window (±{0}s)")]
    StaleTimestamp(i64),

    /// La signature ne vérifie pas contre `(pubkey, ts, body_hash)`.
    /// Erreur générique anti enum d'attaque.
    #[error("signature verification failed")]
    BadSignature,

    /// Format du header Authorization malformé.
    #[error("malformed Authorization header: {0}")]
    MalformedHeader(String),

    /// Un device avec ce pubkey est déjà appairé.
    #[error("device with this public key is already paired")]
    DeviceAlreadyPaired,

    /// Erreur du vault sous-jacent (lecture/écriture metadata devices).
    #[error("vault error: {0}")]
    Vault(#[from] infinity_vault::VaultError),

    /// Erreur du module identity (signature/verify).
    #[error("identity error: {0}")]
    Identity(#[from] infinity_identity::IdentityError),

    /// Erreur de (dé)sérialisation JSON.
    #[error("serialization error: {0}")]
    Serde(String),
}
