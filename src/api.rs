//! Routes axum Phase 2.F : pairing + vault + identity + auth.
//!
//! Ce module expose les nouveaux endpoints sécurisés du companion.
//! Toutes les routes "sensibles" passent par `auth_middleware` qui
//! valide une signature Ed25519 par requête (cf. `infinity-auth`).
//!
//! ## Routes
//!
//! ### Publiques (pas d'auth)
//!
//! - `POST /pair/complete`           → finalise un pairing avec un token
//! - `GET  /pair/companion-pubkey`   → expose la pubkey du companion
//!   (la PWA peut la vérifier visuellement)
//!
//! Note : il n'y a PAS de `POST /pair/request` HTTP. Le token est créé
//! UNIQUEMENT via le menu tray "Pair new device" → s'affiche dans les
//! logs. Cette contrainte out-of-band empêche un site malveillant de
//! s'auto-appairer en silence.
//!
//! ### Protégées par signature
//!
//! - `GET    /auth/devices`            → liste des appareils appairés
//! - `DELETE /auth/devices/:pubkey`    → révoque un device
//! - `GET    /identity/pubkey`         → pubkey du companion (accès auth requis)
//! - `POST   /identity/sign`           → signe le body avec la clé du companion
//! - `PUT    /vault/:ns/:key`          → écrit dans le vault (body = bytes raw)
//! - `GET    /vault/:ns/:key`          → lit le vault (renvoie bytes raw)
//! - `DELETE /vault/:ns/:key`          → supprime
//! - `GET    /vault/:ns`               → liste les clés d'un namespace
//! - `GET    /vault`                   → liste tous les namespaces utilisés

use axum::{
    body::{to_bytes, Body, Bytes},
    extract::{Path, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Json, Response},
};
use infinity_auth::SignatureHeader;
use infinity_identity::PublicKey;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::AppState;

/// Limite max du body en entrée (16 MiB). Au-delà → 413 Payload Too Large.
/// Couvre les usages normaux (upload de fichier vault) sans risque DoS RAM.
const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

// ════════════════════════════════════════════════════════════════════════
// MIDDLEWARE — exige une signature Authorization valide
// ════════════════════════════════════════════════════════════════════════

/// Middleware axum **STRICT** : exige une signature Ed25519 valide.
///
/// Étapes :
///   1. Lit le header `Authorization: InfinitySig <pubkey>:<ts>:<sig>`
///   2. Lit le body en bytes (cap MAX_BODY_BYTES)
///   3. Vérifie la signature via `AuthService::verify_request`
///   4. Reconstruit la requête avec le body conservé pour le handler
///
/// Tous les fail → 401 Unauthorized avec message générique (anti
/// enum d'attaque).
pub async fn auth_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth = state.auth.clone();

    let (parts, body) = request.into_parts();

    let header_value = parts
        .headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?
        .to_string();

    let sig_header = SignatureHeader::parse(&header_value).map_err(|e| {
        warn!("auth: malformed header: {e}");
        StatusCode::UNAUTHORIZED
    })?;

    // Cap mémoire — anti-DoS sur le body.
    let body_bytes = to_bytes(body, MAX_BODY_BYTES)
        .await
        .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;

    auth.verify_request(&sig_header, &body_bytes).map_err(|e| {
        warn!("auth: verify failed: {e}");
        StatusCode::UNAUTHORIZED
    })?;

    // Reconstruit le request avec le body conservé pour les handlers.
    let new_request = Request::from_parts(parts, Body::from(body_bytes));
    Ok(next.run(new_request).await)
}

/// Middleware axum **COMPAT** : migration douce vers la signature Ed25519.
///
/// Comportement à 3 niveaux :
///
///   - **Pas de header Authorization** → pass-through avec un `tracing::warn!`
///     marquant la déprécation. Permet aux versions PWA actuelles
///     (avant Phase 2.G) de continuer à fonctionner sans casse.
///   - **Header présent mais malformé / signature invalide / device non
///     appairé** → **401 strict**. Si quelqu'un essaye de signer mais
///     foire, on refuse — ne pas masquer un bug d'auth en silence.
///   - **Header présent et valide** → pass-through normal, le device est
///     loggé en info (audit trail).
///
/// Cible : `/api/pin*`, `/api/policy`, `/api/stream` — routes legacy
/// du protocole companion qui mutent l'état (pinning, BW). Quand toutes
/// les versions PWA déployées signeront, on basculera ces routes sur
/// `auth_middleware` strict (changer une ligne dans `serve_http`).
///
/// **PAS pour `/api/handshake` ni `/healthz`** — ces routes restent
/// 100% publiques (métriques agrégées, anti-DoS via rate limit futur).
pub async fn auth_compat_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth = state.auth.clone();
    let (parts, body) = request.into_parts();

    let path = parts.uri.path().to_string();
    let method = parts.method.clone();
    let header_value_opt = parts
        .headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(std::string::ToString::to_string);

    let body_bytes = to_bytes(body, MAX_BODY_BYTES)
        .await
        .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;

    if let Some(header_value) = header_value_opt {
        // Header présent → on EXIGE qu'il soit valide. Pas de fallback
        // silencieux : un client qui sait signer doit le faire correctement.
        let sig_header = SignatureHeader::parse(&header_value).map_err(|e| {
            warn!("auth-compat {} {}: malformed header: {}", method, path, e);
            StatusCode::UNAUTHORIZED
        })?;
        let device = auth.verify_request(&sig_header, &body_bytes).map_err(|e| {
            warn!("auth-compat {} {}: verify failed: {}", method, path, e);
            StatusCode::UNAUTHORIZED
        })?;
        tracing::info!(
            device = %device.label,
            "auth-compat {} {}: signed request OK",
            method, path,
        );
    } else {
        /* Pas de header → migration : on log + on laisse passer. Quand toutes
           les PWAs déployées auront migré, on bascule ces routes sur
           `auth_middleware` strict.

           ⚠️ La sévérité dépend de la MÉTHODE, et pas par coquetterie : le
           tableau de bord local relit ces routes toutes les 15 s, ce qui
           noyait le journal du nœud sous des avertissements permanents — au
           point de rendre illisible la seule fenêtre qu'on ait sur un
           démarrage qui se passe mal. Une lecture non signée depuis la page
           du nœud est normale et le restera ; une ÉCRITURE non signée est
           exactement ce que la migration doit faire disparaître, elle garde
           donc son avertissement. */
        if method.is_safe() {
            debug!("auth-compat {} {}: lecture non signée", method, path);
        } else {
            warn!(
                "auth-compat {} {}: ÉCRITURE non signée (obsolète, passer à \
                 l'authentification InfinitySig avant companion v0.3)",
                method, path,
            );
        }
    }

    let new_request = Request::from_parts(parts, Body::from(body_bytes));
    Ok(next.run(new_request).await)
}

// ════════════════════════════════════════════════════════════════════════
// ROUTES PUBLIQUES — pairing
// ════════════════════════════════════════════════════════════════════════

#[derive(Deserialize)]
pub struct PairCompleteReq {
    /// Pairing token (64 chars hex) reçu OUT-OF-BAND via les logs/tray.
    pub token: String,
    /// Clé publique Ed25519 du device PWA, hex 64 chars.
    pub device_pubkey: String,
    /// Label user-display (ex. "Chrome — MacBook").
    pub label: String,
}

#[derive(Serialize)]
pub struct PairCompleteResp {
    pub paired_at: i64,
    pub companion_pubkey: String,
}

pub async fn pair_complete(
    State(state): State<AppState>,
    Json(req): Json<PairCompleteReq>,
) -> Response {
    let device_pubkey = match PublicKey::from_hex(&req.device_pubkey) {
        Ok(pk) => pk,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid device pubkey hex").into_response(),
    };
    if req.label.is_empty() || req.label.len() > 200 {
        return (StatusCode::BAD_REQUEST, "label must be 1..200 chars").into_response();
    }

    match state
        .auth
        .complete_pairing(&req.token, &device_pubkey, &req.label)
    {
        Ok(device) => Json(PairCompleteResp {
            paired_at: device.paired_at,
            companion_pubkey: state.auth.companion_public_key().to_hex(),
        })
        .into_response(),
        Err(e) => {
            warn!("pair_complete failed: {e}");
            (StatusCode::UNAUTHORIZED, e.to_string()).into_response()
        }
    }
}

#[derive(Serialize)]
pub struct CompanionPubkeyResp {
    pub pubkey: String,
}

/// Endpoint public : la PWA peut récupérer la pubkey du companion AVANT
/// le pairing (pour la vérifier visuellement avec celle affichée dans
/// la tray, type "scan QR"). Anti-MITM si plusieurs companions tournent.
pub async fn get_companion_pubkey(State(state): State<AppState>) -> Response {
    Json(CompanionPubkeyResp {
        pubkey: state.auth.companion_public_key().to_hex(),
    })
    .into_response()
}

// ════════════════════════════════════════════════════════════════════════
// ROUTES PROTÉGÉES — devices, identity, vault
// ════════════════════════════════════════════════════════════════════════

pub async fn list_devices(State(state): State<AppState>) -> Response {
    match state.auth.list_devices() {
        Ok(d) => Json(d).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

pub async fn revoke_device(
    State(state): State<AppState>,
    Path(pubkey): Path<String>,
) -> Response {
    match state.auth.revoke_device(&pubkey) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Serialize)]
pub struct IdentityPubkeyResp {
    pub pubkey: String,
    pub label: String,
}

pub async fn identity_pubkey(State(state): State<AppState>) -> Response {
    let m = state.identity.metadata();
    Json(IdentityPubkeyResp {
        pubkey: m.public_key_hex.clone(),
        label: m.label.clone(),
    })
    .into_response()
}

#[derive(Serialize)]
pub struct SignResp {
    pub signature_hex: String,
    pub pubkey_hex: String,
}

/// Signe le body brut avec la clé Ed25519 du companion. Renvoie la
/// signature + la pubkey utilisée. Usage typique : la PWA demande au
/// companion de signer un événement NOSTR avec l'identité du Bâtisseur.
pub async fn identity_sign(State(state): State<AppState>, body: Bytes) -> Response {
    let sig = state.identity.sign(&body);
    Json(SignResp {
        signature_hex: sig.to_hex(),
        pubkey_hex: state.identity.public_key().to_hex(),
    })
    .into_response()
}

// ── Vault routes ─────────────────────────────────────────────────────

pub async fn vault_put(
    State(state): State<AppState>,
    Path((ns, key)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    if let Err(e) = state.vault.namespace(&ns).put(&key, &body) {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }
    StatusCode::NO_CONTENT.into_response()
}

pub async fn vault_get(
    State(state): State<AppState>,
    Path((ns, key)): Path<(String, String)>,
) -> Response {
    match state.vault.namespace(&ns).get(&key) {
        Ok(Some(bytes)) => (StatusCode::OK, bytes).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

pub async fn vault_delete(
    State(state): State<AppState>,
    Path((ns, key)): Path<(String, String)>,
) -> Response {
    match state.vault.namespace(&ns).delete(&key) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Serialize)]
pub struct VaultListResp {
    pub namespace: String,
    pub keys: Vec<String>,
    pub count: usize,
}

pub async fn vault_list(
    State(state): State<AppState>,
    Path(ns): Path<String>,
) -> Response {
    match state.vault.namespace(&ns).list() {
        Ok(keys) => Json(VaultListResp {
            namespace: ns,
            count: keys.len(),
            keys,
        })
        .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Serialize)]
pub struct NamespacesResp {
    pub namespaces: Vec<String>,
}

pub async fn vault_list_namespaces(State(state): State<AppState>) -> Response {
    match state.vault.namespaces() {
        Ok(namespaces) => Json(NamespacesResp { namespaces }).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
