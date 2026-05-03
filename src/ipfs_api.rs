//! Phase 3-IPFS-A — Endpoints API pour le mode IPFS privé (swarm.key).
//!
//! ## Routes
//!
//!   GET    /ipfs/private/info        → public — info de discovery
//!   GET    /ipfs/private/swarm-key   → protected — lit la swarm.key
//!   POST   /ipfs/private/swarm-key   → protected — set ou génère
//!   DELETE /ipfs/private/swarm-key   → protected — désactive (mode public)
//!
//! ## Workflow PWA
//!
//! 1. PWA appelle `GET /info` → savoir si le nœud est privé
//! 2. Si pas encore privé : `POST /swarm-key { mode: "generate" }`
//!    pour créer une nouvelle swarm.key. Le companion la stocke dans
//!    `~/.infinity-node/ipfs/swarm.key` + backup vault.
//! 3. Pour multi-device : `GET /swarm-key` sur le 1ᵉʳ device → copier
//!    le hex → `POST /swarm-key { mode: "import", hex: "..." }` sur
//!    le 2ᵉ device → cluster IPFS privé fermé.
//! 4. Restart companion requis pour appliquer (Kubo daemon doit
//!    re-démarrer avec LIBP2P_FORCE_PNET).

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::ipfs_private::{
    delete_swarm_key_from_repo, ipfs_repo_path, is_repo_in_private_mode,
    read_swarm_key_from_repo, write_swarm_key_to_repo, SwarmKey,
};
use crate::AppState;

/// Namespace + key dans le vault chiffré pour le backup de swarm.key.
const VAULT_NS:  &str = "ipfs";
const VAULT_KEY: &str = "swarm-key";

// ── /ipfs/private/info — PUBLIC ─────────────────────────────────────

#[derive(Serialize)]
pub struct PrivateIpfsInfo {
    /// `true` si swarm.key présente dans le repo Kubo (mode privé actif).
    pub private:        bool,
    /// Empreinte 12 chars de la swarm.key (vérification visuelle
    /// "même clé sur tous mes devices"). None si mode public.
    pub fingerprint:    Option<String>,
    /// `true` si le subprocess Kubo tourne actuellement.
    pub running:        bool,
    /// Nombre de pairs IPFS connectés (stat live de Kubo).
    pub peers:          u64,
}

pub async fn get_private_ipfs_info(State(state): State<AppState>) -> Response {
    let repo = ipfs_repo_path();
    let private = is_repo_in_private_mode(&repo);
    let fingerprint = if private {
        read_swarm_key_from_repo(&repo).map(|k| k.fingerprint())
    } else {
        None
    };
    let running = state.kubo_metrics.is_some();
    let peers = state
        .kubo_metrics
        .as_ref()
        .map(|m| m.peers.load(std::sync::atomic::Ordering::Relaxed))
        .unwrap_or(0);
    Json(PrivateIpfsInfo { private, fingerprint, running, peers }).into_response()
}

// ── /ipfs/private/swarm-key — PROTECTED ─────────────────────────────

#[derive(Serialize)]
pub struct SwarmKeyResp {
    /// Hex 64 chars de la swarm.key, ou null si pas en mode privé.
    /// **À TRAITER COMME SECRET côté PWA** (afficher derrière "reveal").
    pub swarm_key:   Option<String>,
    pub fingerprint: Option<String>,
}

pub async fn get_swarm_key(State(_state): State<AppState>) -> Response {
    let repo = ipfs_repo_path();
    match read_swarm_key_from_repo(&repo) {
        Some(k) => Json(SwarmKeyResp {
            swarm_key:   Some(k.to_hex()),
            fingerprint: Some(k.fingerprint()),
        })
        .into_response(),
        None => Json(SwarmKeyResp { swarm_key: None, fingerprint: None }).into_response(),
    }
}

#[derive(Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub enum SetSwarmKeyReq {
    /// Génère une nouvelle swarm.key (cas device "primaire" du cluster).
    Generate,
    /// Importe une swarm.key existante (cas device "secondaire" qui
    /// rejoint un cluster existant — l'utilisateur a copié la clé
    /// hex depuis son device primaire).
    Import {
        /// Swarm key hex 64 chars.
        hex: String,
    },
}

#[derive(Serialize)]
pub struct SetSwarmKeyResp {
    pub fingerprint:      String,
    pub mode:             &'static str,
    /// `true` si Kubo doit être redémarré (subprocess) pour appliquer
    /// la nouvelle clé. La PWA peut afficher un bouton "Redémarrer".
    pub restart_required: bool,
}

pub async fn set_swarm_key(
    State(state): State<AppState>,
    Json(req): Json<SetSwarmKeyReq>,
) -> Response {
    let (key, mode_label) = match req {
        SetSwarmKeyReq::Generate => (SwarmKey::generate(), "generated"),
        SetSwarmKeyReq::Import { hex } => match SwarmKey::from_hex(&hex) {
            Ok(k) => (k, "imported"),
            Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
        },
    };

    let repo = ipfs_repo_path();
    if let Err(e) = write_swarm_key_to_repo(&repo, &key) {
        warn!("set_swarm_key: write_swarm_key_to_repo failed: {e}");
        return (StatusCode::INTERNAL_SERVER_ERROR, "failed to write swarm.key").into_response();
    }

    // Backup chiffré dans le vault (namespace "ipfs", clé "swarm-key").
    // Format : hex (texte ASCII), persistant tant que le vault n'est pas wipé.
    let hex = key.to_hex();
    if let Err(e) = state.vault.namespace(VAULT_NS).put(VAULT_KEY, hex.as_bytes()) {
        warn!("set_swarm_key: vault backup failed (non-fatal): {e}");
    }

    let fingerprint = key.fingerprint();
    Json(SetSwarmKeyResp {
        fingerprint,
        mode: mode_label,
        // Toujours true : Kubo doit redémarrer pour piquer la nouvelle clé
        // (LIBP2P_FORCE_PNET est appliqué au lancement du subprocess).
        restart_required: true,
    })
    .into_response()
}

// ── DELETE /ipfs/private/swarm-key — PROTECTED ──────────────────────

#[derive(Serialize)]
pub struct DeleteSwarmKeyResp {
    pub previous_mode:    &'static str,
    pub restart_required: bool,
}

pub async fn delete_swarm_key(State(state): State<AppState>) -> Response {
    let repo = ipfs_repo_path();
    let was_private = is_repo_in_private_mode(&repo);
    if let Err(e) = delete_swarm_key_from_repo(&repo) {
        warn!("delete_swarm_key: filesystem fail: {e}");
        return (StatusCode::INTERNAL_SERVER_ERROR, "failed to delete swarm.key").into_response();
    }
    // Wipe le backup vault aussi
    let _ = state.vault.namespace(VAULT_NS).delete(VAULT_KEY);

    Json(DeleteSwarmKeyResp {
        previous_mode: if was_private { "private" } else { "public" },
        restart_required: was_private,
    })
    .into_response()
}
