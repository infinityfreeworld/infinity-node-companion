//! Phase 3.A — Endpoints API pour configurer le relai NOSTR privé.
//!
//! ## Routes
//!
//!   GET  /relay/private/info     → public — info de discovery (URL + capabilities)
//!   GET  /relay/private/owner    → protected — lit owner_pubkey actuelle
//!   POST /relay/private/owner    → protected — set owner_pubkey
//!
//! La PWA appelle :
//!   1. GET /info → savoir où le relai écoute
//!   2. POST /owner avec sa pubkey NOSTR Bâtisseur → set la whitelist
//!   3. (restart companion ou attendre prochain boot — la nouvelle
//!      config s'applique au démarrage du subprocess `nostr-rs-relay`)
//!
//! ## Persistance
//!
//! La owner_pubkey vit dans le vault chiffré, namespace `nostr`,
//! clé `owner-pubkey`. Format : 64 chars hex lowercase. Le companion
//! la lit au boot pour configurer le relai (cf. `main.rs::init`).

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::nostr_relay::NostrRelayBackend;
use crate::AppState;

/// Namespace + key dans le vault pour la pubkey du Bâtisseur.
const VAULT_NS:  &str = "nostr";
const VAULT_KEY: &str = "owner-pubkey";

// ── /relay/private/info — PUBLIC ─────────────────────────────────────

/// Info de discovery du relai privé. Renvoyée sans auth — la PWA peut
/// récupérer ces infos avant de pair (cf. `getCompanionPubkey()` côté
/// PWA pour le pattern).
#[derive(Serialize)]
pub struct PrivateRelayInfo {
    /// `ws://...` du relai. None si pas démarré (binaire absent ou crash).
    pub url:           Option<String>,
    /// Pubkey du Bâtisseur autorisée à écrire. None si pas encore configurée.
    pub owner_pubkey:  Option<String>,
    /// `true` si le subprocess relai tourne actuellement.
    pub running:       bool,
    /// Méthode d'auth en place. "pubkey-whitelist" pour MVP 3.A,
    /// "nip42" en Phase 3.B/C.
    pub auth_method:   &'static str,
    /// Port à découvrir (pour mDNS/Tailscale en Phase 3.B).
    pub port:          u16,
}

pub async fn get_private_relay_info(State(state): State<AppState>) -> Response {
    Json(PrivateRelayInfo {
        url:          state.nostr_url.clone(),
        owner_pubkey: read_owner_pubkey(&state),
        running:      state.nostr_url.is_some(),
        auth_method:  "pubkey-whitelist",
        port:         NostrRelayBackend::port(),
    })
    .into_response()
}

// ── /relay/private/owner — PROTECTED ─────────────────────────────────

#[derive(Serialize)]
pub struct OwnerPubkeyResp {
    pub owner_pubkey: Option<String>,
}

pub async fn get_owner_pubkey(State(state): State<AppState>) -> Response {
    Json(OwnerPubkeyResp {
        owner_pubkey: read_owner_pubkey(&state),
    })
    .into_response()
}

#[derive(Deserialize)]
pub struct SetOwnerReq {
    /// Pubkey NOSTR du Bâtisseur, hex 64 chars lowercase ou uppercase.
    /// Validée puis normalisée en lowercase avant persistance.
    pub owner_pubkey: String,
}

#[derive(Serialize)]
pub struct SetOwnerResp {
    pub owner_pubkey: String,
    /// `true` si la valeur diffère de celle appliquée au relai au démarrage —
    /// la PWA peut afficher un bouton "Redémarrer le companion pour appliquer".
    pub restart_required: bool,
}

pub async fn set_owner_pubkey(
    State(state): State<AppState>,
    Json(req): Json<SetOwnerReq>,
) -> Response {
    // Validation : 64 chars hex
    let pk = req.owner_pubkey.trim().to_lowercase();
    if pk.len() != 64 || !pk.chars().all(|c| c.is_ascii_hexdigit()) {
        return (
            StatusCode::BAD_REQUEST,
            "owner_pubkey must be 64 lowercase hex chars",
        )
            .into_response();
    }

    // Persiste dans le vault chiffré
    if let Err(e) = state.vault.namespace(VAULT_NS).put(VAULT_KEY, pk.as_bytes()) {
        warn!("set_owner_pubkey: vault write failed: {e}");
        return (StatusCode::INTERNAL_SERVER_ERROR, "vault write failed").into_response();
    }

    // Compare avec celle qui tourne actuellement dans le relai (lue au boot)
    let restart_required = state
        .nostr_relay_owner
        .as_deref()
        .is_none_or(|applied| applied != pk);

    Json(SetOwnerResp {
        owner_pubkey: pk,
        restart_required,
    })
    .into_response()
}

// ── Helper crate-private ─────────────────────────────────────────────

/// Lit la owner_pubkey persistée dans le vault. None si jamais set
/// ou si erreur de lecture (vault corrompu, namespace inexistant).
pub(crate) fn read_owner_pubkey(state: &AppState) -> Option<String> {
    state
        .vault
        .namespace(VAULT_NS)
        .get(VAULT_KEY)
        .ok()
        .flatten()
        .and_then(|bytes| String::from_utf8(bytes).ok())
}

/// Lit la owner_pubkey directement depuis un Vault (utile au boot
/// avant que AppState soit construit).
pub fn read_owner_pubkey_from_vault(vault: &infinity_vault::Vault) -> Option<String> {
    vault
        .namespace(VAULT_NS)
        .get(VAULT_KEY)
        .ok()
        .flatten()
        .and_then(|bytes| String::from_utf8(bytes).ok())
}
