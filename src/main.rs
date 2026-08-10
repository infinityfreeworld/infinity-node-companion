//! # Infinity Node — Companion natif
//!
//! Binaire Rust avec tray icon native qui héberge un serveur HTTP de
//! découverte sur `127.0.0.1:7474` ET supervise les sous-processus
//! kubo + nostr-rs-relay quand ils sont disponibles. La PWA Infinity
//! détecte automatiquement le companion et bascule en mode `companion`.
//!
//! ## Architecture
//!
//!   ┌─────────────────────────┐      ┌──────────────────────────────┐
//!   │  Main thread            │      │  tokio runtime (multi-thread)│
//!   │  ─────────────          │      │  ──────────────────          │
//!   │  tao::EventLoop         │      │  axum::serve()               │
//!   │  ↳ TrayIcon + Menu      │      │  /api/handshake (live mtrx)  │
//!   │  ↳ MenuEvent receiver   │      │                              │
//!   │                         │      │  kubo polling task (5s)      │
//!   │  Hold: backends ◄───────┼──────┤  → metrics: peers/pinned/bw  │
//!   │       (KuboBackend,     │      │                              │
//!   │        NostrRelayBack.) │      │                              │
//!   └─────────────────────────┘      └──────────────────────────────┘
//!
//! ## Lifecycle
//!
//! - Boot : runtime tokio démarré → backends try_start (skip si binaire
//!   absent du PATH) → HTTP server spawn → tray + event loop.
//! - Quit (tray) : drop explicite des backends (Drop = kill child)
//!   AVANT `ControlFlow::Exit`, parce que `tao::run` n'unwind jamais
//!   (process::exit interne, pas de Drop sur la stack).
//!
//! ## Pause sémantique
//!
//! L'utilisateur peut « Mettre en pause » via la tray. Ça flippe juste
//! le flag `enabled` → handshake renvoie 503. Les sous-processus kubo
//! et nostr-rs-relay continuent de tourner (sinon coupure brutale =
//! données pas flush, pairs IPFS perdent leur route, etc.). Pause =
//! « invisible à la PWA », pas « éteint ».

use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    middleware as axum_middleware,
    response::{IntoResponse, Json},
    routing::{delete, get, post, put},
    Router,
};
use image::{ImageBuffer, Rgba};
use serde::{Deserialize, Serialize};
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tao::{
    event::Event,
    event_loop::{ControlFlow, EventLoopBuilder},
};
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use tracing::{info, warn};
use tray_icon::{
    menu::{CheckMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem},
    Icon, TrayIconBuilder,
};

mod api;
mod autostart;
mod bandwidth;
mod ipfs_api;
mod ipfs_private;
mod kubo;
mod nostr_relay;
mod pinning;
mod relay_api;
mod relay_installer;
mod security;
mod stream;
mod supervisor;
mod tiles;

use bandwidth::BandwidthTracker;
use infinity_auth::AuthService;
use infinity_identity::Identity;
use infinity_vault::Vault;
use kubo::{KuboBackend, KuboMetrics};
use nostr_relay::{NostrRelayBackend, NostrRelayConfig};
use pinning::{KuboPinClient, PinPolicy, PinRecord, PinTracker};

// ── Constantes ───────────────────────────────────────────────────────────

/// Bind par défaut du HTTP API. Modifiable via env `INFINITY_BIND_ADDR`.
///
/// Phase 3.B — pour permettre à d'autres devices (tablette, smartphone)
/// du même réseau LAN ou via Tailscale d'atteindre ce companion :
///
///   INFINITY_BIND_ADDR=0.0.0.0:7474 infinity-node          # tout le LAN
///   INFINITY_BIND_ADDR=100.64.1.5:7474 infinity-node       # IP Tailscale
///
/// **Sécurité** : ouvrir 0.0.0.0 expose l'API au réseau local. C'est OK
/// car toutes les routes sensibles (vault/identity/auth) sont protégées
/// par signature Ed25519 (Phase 2.D). La PWA des autres devices doit
/// être appairée séparément (pairing token out-of-band depuis le tray).
const DEFAULT_BIND_ADDR: &str = "127.0.0.1:7474";
const SERVICE_TAG:       &str = "infinity-node";
const VERSION:           &str = env!("CARGO_PKG_VERSION");
const DEFAULT_PWA_URL:   &str = "https://localhost:5173";

/// Cap journalier par défaut, configurable via env `INFINITY_BW_CAP_MB`.
/// 5 Go/jour = ~150 Go/mois — raisonnable pour un nœud résidentiel sur fibre.
const DEFAULT_BW_CAP_MB: u64 = 5_000;

// ── État partagé ─────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AppState {
    pub started_at:    Arc<Instant>,
    pub enabled:       Arc<AtomicBool>,
    pub kubo_metrics:  Option<Arc<KuboMetrics>>,
    pub kubo_gateway:  Option<String>,
    pub nostr_url:     Option<String>,
    pub bandwidth:     Arc<BandwidthTracker>,
    pub pins:          PinTracker,
    pub pin_client:    Option<KuboPinClient>,
    // Phase 2.F — security stack (vault chiffré + identité + auth bridge)
    pub vault:         Arc<Vault>,
    pub identity:      Arc<Identity>,
    pub auth:          Arc<AuthService>,
    // Phase 3.A — owner_pubkey du relai NOSTR appliquée AU DÉMARRAGE.
    // Sert à détecter si la PWA pousse une nouvelle valeur via
    // POST /relay/private/owner → on log un warning "redémarrer".
    // None si jamais set au boot.
    pub nostr_relay_owner: Option<String>,
}

// ── Contrat handshake ────────────────────────────────────────────────────

#[derive(Serialize)]
struct Handshake {
    service:          &'static str,
    version:          &'static str,
    capabilities:     Vec<&'static str>,
    #[serde(rename = "ipfsGateway")]
    ipfs_gateway:     Option<String>,
    #[serde(rename = "nostrRelayUrl")]
    nostr_relay_url:  Option<String>,
    #[serde(rename = "publicRelayUrl")]
    public_relay_url: Option<&'static str>,
    uptime:           u64,
    peers:            u64,
    #[serde(rename = "pinnedCount")]
    pinned_count:     u64,
    #[serde(rename = "bytesServed")]
    bytes_served:     u64,
    // E.1 — pin policy + bandwidth caps (champs optionnels côté PWA pour
    // forward-compat ; un companion D.0 sans E.1 ne les enverra pas)
    #[serde(rename = "managedPins")]
    managed_pins:     u64,
    #[serde(rename = "managedPinsBytes")]
    managed_pins_bytes: u64,
    #[serde(rename = "bandwidthUsedTodayBytes")]
    bandwidth_used_today_bytes: u64,
    #[serde(rename = "bandwidthCapBytes")]
    bandwidth_cap_bytes: u64,
}

// ── Handlers axum ────────────────────────────────────────────────────────

async fn handshake(State(state): State<AppState>) -> impl IntoResponse {
    if !state.enabled.load(Ordering::Relaxed) {
        return (StatusCode::SERVICE_UNAVAILABLE, "paused").into_response();
    }

    let mut caps = Vec::new();
    if state.kubo_metrics.is_some() { caps.push("ipfs"); }
    if state.nostr_url.is_some()    { caps.push("nostr-relay"); }
    /* ⚠️ `capabilities` est une liste BLANCHE : la PWA ne tente QUE ce qui y
       figure. Les 244 Mo d'archives présentes sur le disque n'ont jamais été
       lues faute de cette seule ligne. Et on n'annonce la capacité que si le
       dossier contient vraiment quelque chose — l'annoncer à vide ferait
       basculer la carte sur un fond inexistant, donc noire. */
    if tiles::has_archives()        { caps.push("tiles"); }

    let (peers, pinned, bw) = state.kubo_metrics
        .as_ref()
        .map(|m| (
            m.peers.load(Ordering::Relaxed),
            m.pinned_count.load(Ordering::Relaxed),
            m.bytes_served.load(Ordering::Relaxed),
        ))
        .unwrap_or((0, 0, 0));

    let (managed_pins, managed_bytes) = state.pins.totals();

    let body = Handshake {
        service:          SERVICE_TAG,
        version:          VERSION,
        capabilities:     caps,
        ipfs_gateway:     state.kubo_gateway.clone(),
        nostr_relay_url:  state.nostr_url.clone(),
        public_relay_url: None,                     // Phase F
        uptime:           state.started_at.elapsed().as_secs(),
        peers,
        pinned_count:     pinned,
        bytes_served:     bw,
        managed_pins,
        managed_pins_bytes:         managed_bytes,
        bandwidth_used_today_bytes: state.bandwidth.used(),
        bandwidth_cap_bytes:        state.bandwidth.cap(),
    };
    (StatusCode::OK, Json(body)).into_response()
}

// ── Endpoints pin policy (Phase E.1) ─────────────────────────────────────

#[derive(Deserialize)]
struct PinReq {
    cid:        String,
    module:     String,
    /// Override du TTL par défaut pour ce module. None → utilise default_ttl_hours.
    #[serde(default)]
    ttl_hours:  Option<u32>,
}

#[derive(Serialize)]
struct PinResp {
    cid:        String,
    module:     String,
    pinned_at:  u64,
    ttl_secs:   u64,
    size_bytes: u64,
}

async fn post_pin(
    State(state): State<AppState>,
    Json(req):    Json<PinReq>,
) -> impl IntoResponse {
    if req.cid.is_empty() {
        return (StatusCode::BAD_REQUEST, "cid required").into_response();
    }
    let policy = state.pins.snapshot_policy();
    let rule   = policy.rule_for(&req.module);
    if !rule.enabled {
        return (StatusCode::FORBIDDEN, "module pin disabled by policy").into_response();
    }
    let ttl_hours = req.ttl_hours.unwrap_or(rule.default_ttl_hours);
    let ttl_secs  = (ttl_hours as u64) * 3600;

    // Pin via kubo si dispo
    let size_bytes = if let Some(pc) = state.pin_client.as_ref() {
        if let Err(e) = pc.pin_add(&req.cid).await {
            return (StatusCode::BAD_GATEWAY, format!("kubo pin failed: {e}")).into_response();
        }
        pc.object_size(&req.cid).await
    } else {
        0   // pas de kubo → on track quand même, sera resync au prochain start
    };

    let rec = PinRecord {
        cid:        req.cid.clone(),
        module:     req.module.clone(),
        pinned_at:  pinning::unix_now(),
        ttl_secs,
        size_bytes,
    };
    state.pins.upsert(rec.clone());

    Json(PinResp {
        cid:        rec.cid,
        module:     rec.module,
        pinned_at:  rec.pinned_at,
        ttl_secs:   rec.ttl_secs,
        size_bytes: rec.size_bytes,
    }).into_response()
}

async fn delete_pin(
    State(state): State<AppState>,
    Path(cid):    Path<String>,
) -> impl IntoResponse {
    if let Some(pc) = state.pin_client.as_ref() {
        if let Err(e) = pc.pin_rm(&cid).await {
            warn!("pin_rm via kubo failed (record retiré quand même) : {e}");
        }
    }
    if state.pins.remove(&cid).is_some() {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}

async fn get_pins(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.pins.list_pins())
}

async fn get_policy(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.pins.snapshot_policy())
}

async fn put_policy(
    State(state): State<AppState>,
    Json(p):      Json<PinPolicy>,
) -> impl IntoResponse {
    state.pins.set_policy(p);
    StatusCode::NO_CONTENT
}

async fn healthz() -> &'static str { "ok" }

// ── Icône procédurale 32×32 ─────────────────────────────────────────────

fn build_icon() -> Icon {
    const SIZE: u32 = 32;
    let mut img: ImageBuffer<Rgba<u8>, Vec<u8>> = ImageBuffer::new(SIZE, SIZE);
    let cx = SIZE as f32 / 2.0;
    let cy = SIZE as f32 / 2.0;
    let r_max = (SIZE as f32 / 2.0) - 0.5;
    for (x, y, px) in img.enumerate_pixels_mut() {
        let dx = x as f32 + 0.5 - cx;
        let dy = y as f32 + 0.5 - cy;
        let d  = (dx * dx + dy * dy).sqrt();
        if d > r_max {
            *px = Rgba([0, 0, 0, 0]);
        } else {
            let t = (d / r_max).clamp(0.0, 1.0);
            let r = lerp_u8(6,    20,  t);
            let g = lerp_u8(182,  100, t);
            let b = lerp_u8(212,  140, t);
            let a = lerp_u8(255,  220, t);
            *px = Rgba([r, g, b, a]);
        }
    }
    Icon::from_rgba(img.into_raw(), SIZE, SIZE).expect("build icon")
}

fn lerp_u8(a: u8, b: u8, t: f32) -> u8 {
    (a as f32 + (b as f32 - a as f32) * t).round().clamp(0.0, 255.0) as u8
}

// ── HTTP server (async, runs in shared runtime) ──────────────────────────

async fn serve_http(state: AppState) {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any)
        /* ⚠️ Un navigateur ne laisse lire QUE sept en-têtes de réponse en
           cross-origin ; `Content-Range` et `Accept-Ranges` n'en font pas
           partie. Notre lecteur PMTiles ne juge aujourd'hui que sur le STATUT
           (206), qui reste lisible — mais un serveur qui honore les plages et
           dont personne ne peut le vérifier est exactement le genre de panne
           qu'on met une journée à comprendre : validée en ligne de commande,
           inerte dans l'onglet. On les expose. */
        .expose_headers([
            header::CONTENT_RANGE,
            header::ACCEPT_RANGES,
            header::CONTENT_LENGTH,
        ]);

    // Phase 2.F — sous-router pour les routes PROTÉGÉES par signature.
    // Le middleware `api::auth_middleware` valide le header
    // `Authorization: InfinitySig <pubkey>:<ts>:<sig>` avant de passer
    // au handler. Toutes les routes vault / identity / auth/devices
    // sont scopées ici.
    let protected = Router::new()
        .route("/auth/devices",            get(api::list_devices))
        .route("/auth/devices/:pubkey",    delete(api::revoke_device))
        .route("/identity/pubkey",         get(api::identity_pubkey))
        .route("/identity/sign",           post(api::identity_sign))
        .route("/vault",                   get(api::vault_list_namespaces))
        .route("/vault/:ns",               get(api::vault_list))
        .route("/vault/:ns/:key",
               put(api::vault_put)
                 .get(api::vault_get)
                 .delete(api::vault_delete))
        // Phase 3.A — gestion de la owner_pubkey du relai privé
        // (set/get protégé par signature ; l'info publique reste accessible
        // sans auth via /relay/private/info plus bas).
        .route("/relay/private/owner",
               get(relay_api::get_owner_pubkey)
                 .post(relay_api::set_owner_pubkey))
        // Phase 3-IPFS-A — gestion de la swarm.key (mode IPFS privé).
        // GET = lit la clé en clair (à protéger comme un secret côté UI),
        // POST = générer ou importer une swarm.key,
        // DELETE = retour au mode IPFS public.
        .route("/ipfs/private/swarm-key",
               get(ipfs_api::get_swarm_key)
                 .post(ipfs_api::set_swarm_key)
                 .delete(ipfs_api::delete_swarm_key))
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            api::auth_middleware,
        ));

    // Phase 2.E — sous-router COMPAT pour les routes legacy qui mutent
    // l'état (pinning, policy, stream WS). Migration douce :
    //   - non signé → pass-through + WARN log déprécation
    //   - signé valide → OK + audit info (device label)
    //   - signé invalide → 401 strict (anti silent-bypass)
    // Bascule future vers `auth_middleware` strict quand toutes les
    // PWAs déployées auront migré (Phase 2.G complétée).
    let legacy_compat = Router::new()
        .route("/api/stream",     get(stream::ws_handler))
        .route("/api/tiles",      get(tiles::list_tiles))
        .route("/api/tiles/:nom", get(tiles::get_tile_archive))
        .route("/api/pin",        post(post_pin))
        .route("/api/pin/:cid",   delete(delete_pin))
        .route("/api/pins",       get(get_pins))
        .route("/api/policy",     get(get_policy).put(put_policy))
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            api::auth_compat_middleware,
        ));

    // Phase 2.F — sous-router pour les routes PUBLIQUES de pairing.
    // Pas d'auth ici car c'est l'établissement initial de la confiance.
    // Le `pair/complete` est protégé par le pairing token (généré via
    // tray, distribué out-of-band).
    let pairing = Router::new()
        .route("/pair/complete",        post(api::pair_complete))
        .route("/pair/companion-pubkey", get(api::get_companion_pubkey));

    // Phase 3.A — info publique du relai privé : URL + owner_pubkey
    // appliquée + capabilities. Sans auth car c'est de la discovery —
    // l'écriture de la owner reste protégée plus haut.
    let private_relay_public = Router::new()
        .route("/relay/private/info", get(relay_api::get_private_relay_info));

    // Phase 3-IPFS-A — info publique du nœud IPFS privé (mode actif ?
    // fingerprint de la swarm.key pour vérification visuelle, etc.).
    // Sans auth car c'est juste de la discovery sur l'état du nœud.
    let private_ipfs_public = Router::new()
        .route("/ipfs/private/info", get(ipfs_api::get_private_ipfs_info));

    let app = Router::new()
        // Routes 100 % publiques — métriques agrégées non sensibles
        // (pas d'auth requise pour le service-discovery côté PWA).
        .route("/api/handshake",   get(handshake))
        .route("/healthz",         get(healthz))
        // Phase 2.E — sous-router compat (warn si non signé)
        .merge(legacy_compat)
        // Phase 2.F — sous-routers pairing (public) et protected (strict)
        .merge(pairing)
        .merge(protected)
        // Phase 3.A — info publique du relai privé (discovery)
        .merge(private_relay_public)
        // Phase 3-IPFS-A — info publique du nœud IPFS privé (discovery)
        .merge(private_ipfs_public)
        .with_state(state)
        .layer(cors)
        .layer(TraceLayer::new_for_http());

    let bind_addr = std::env::var("INFINITY_BIND_ADDR")
        .unwrap_or_else(|_| DEFAULT_BIND_ADDR.to_string());
    let addr: SocketAddr = match bind_addr.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("\n  ⚠️  INFINITY_BIND_ADDR='{bind_addr}' invalide : {e}");
            eprintln!("  Format attendu : <ip>:<port>, ex. 0.0.0.0:7474\n");
            std::process::exit(1);
        }
    };
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("\n  ⚠️  Impossible de bind {bind_addr} : {e}");
            eprintln!("  Une autre instance d'Infinity Node tourne déjà ?");
            eprintln!("  (ou port déjà occupé — tente INFINITY_BIND_ADDR=127.0.0.1:7475)\n");
            std::process::exit(1);
        }
    };
    info!("listening on {addr}");
    if let Err(e) = axum::serve(listener, app).await {
        warn!("axum::serve terminated: {e}");
    }
}

// ── Entrée principale ────────────────────────────────────────────────────

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "infinity_node=info,tower_http=warn,child=info,supervisor=info".into()),
        )
        .init();

    // 1. Runtime tokio centralisé (HTTP + polling backends + janitor)
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()?;

    // 2. Bandwidth tracker (cap configurable via env, défaut 5 Go/jour)
    let cap_mb = std::env::var("INFINITY_BW_CAP_MB")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_BW_CAP_MB);
    let bandwidth = BandwidthTracker::new(cap_mb * 1024 * 1024);

    // 3. Phase 2.F + 3.A — security stack EN PREMIER pour que le relai
    // NOSTR puisse lire la owner_pubkey du Bâtisseur dans le vault au
    // démarrage (whitelist write, mode privé).
    // Boot fail si Keychain OS indispo (Linux sans gnome-keyring) —
    // message exploitable + exit 1.
    let security = match security::init() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("\n  ⚠️  Échec init security stack : {e}");
            eprintln!("  Linux : installe gnome-keyring ou KWallet et relance.\n");
            return Err(Box::new(e));
        }
    };
    info!(
        pubkey = %security.identity.public_key(),
        data_dir = ?security.data_dir,
        "security stack ready",
    );

    // 4. Phase 3.A — owner_pubkey du Bâtisseur (lue du vault chiffré).
    // Si présente → relai privé en mode whitelist (seul le Bâtisseur
    // peut écrire). Si None → relai en mode local ouvert (la PWA
    // poussera la pubkey via POST /relay/private/owner au 1ᵉʳ run).
    let nostr_relay_owner = relay_api::read_owner_pubkey_from_vault(&security.vault);
    if let Some(pk) = nostr_relay_owner.as_deref() {
        info!("nostr relay owner_pubkey={pk} (mode privé)");
    } else {
        info!("nostr relay sans owner_pubkey (mode local ouvert — PWA pousseur la valeur au pairing)");
    }

    // 5. Backends — try_start retourne None si binaire absent
    let kubo  = KuboBackend::try_start(rt.handle(), bandwidth.clone());
    let nostr = NostrRelayBackend::try_start_with_config(NostrRelayConfig {
        owner_pubkey: nostr_relay_owner.clone(),
    });

    let kubo_status  = if kubo.is_some()  { "✓" } else { "✗ (ipfs absent)" };
    let nostr_status = if nostr.is_some() { "✓" } else { "✗ (nostr-rs-relay absent)" };

    // 6. Pin tracker + janitor (charge l'état persisté)
    let pins       = PinTracker::load();
    let pin_client = kubo.as_ref().map(|k| k.pin_client());
    pinning::spawn_janitor(rt.handle(), pins.clone(), pin_client.clone());

    // 7. État partagé (capture les Arc/Strings des backends + security)
    let state = AppState {
        started_at:        Arc::new(Instant::now()),
        enabled:           Arc::new(AtomicBool::new(true)),
        kubo_metrics:      kubo.as_ref().map(|k| k.metrics.clone()),
        kubo_gateway:      kubo.as_ref().map(|k| k.gateway.clone()),
        nostr_url:         nostr.as_ref().map(|n| n.url.clone()),
        bandwidth:         bandwidth.clone(),
        pins:              pins.clone(),
        pin_client,
        vault:             security.vault.clone(),
        identity:          security.identity.clone(),
        auth:              security.auth.clone(),
        nostr_relay_owner: nostr.as_ref().and_then(|n| n.applied_owner_pubkey.clone()),
    };

    // 6. HTTP server task
    rt.spawn(serve_http(state.clone()));

    let pwa_url = std::env::var("INFINITY_URL").unwrap_or_else(|_| DEFAULT_PWA_URL.into());

    println!("\n  ┌─────────────────────────────────────────────────┐");
    println!("  │  Infinity Node v{:<32}│", VERSION);
    println!("  │                                                 │");
    let bind_display = std::env::var("INFINITY_BIND_ADDR")
        .unwrap_or_else(|_| DEFAULT_BIND_ADDR.to_string());
    println!("  │  Handshake : http://{}/api/handshake │", bind_display);
    println!("  │  Kubo      : {:<35}│", kubo_status);
    println!("  │  NOSTR     : {:<35}│", nostr_status);
    println!("  │  PWA cible : {:<35}│", pwa_url);
    println!("  │                                                 │");
    println!("  │  Tray icon active dans la barre système.        │");
    println!("  └─────────────────────────────────────────────────┘\n");

    // 5. Auto-launch handle
    let autostart = autostart::handle();
    // Phase D.2b — le défaut s'applique TOUT SEUL, une seule fois.
    //
    // La capacité existait déjà et fonctionnait ; elle attendait qu'on trouve
    // une case à cocher dans ce menu. Personne ne la trouvait, et le Bâtisseur
    // voyait « Carte hors-ligne indisponible » sans comprendre pourquoi son
    // nœud « ne se rend pas opérationnel automatiquement ».
    //
    // ⚠️ Lu AVANT `is_enabled` : sinon le menu afficherait l'état d'avant
    // l'activation, et la case paraîtrait décochée alors qu'elle vient d'être
    // posée — un témoin qui ment dès la première seconde.
    if let Some(auto) = autostart.as_ref() {
        if autostart::appliquer_defaut_une_fois(auto) {
            info!("autostart activé par défaut au premier démarrage (décochable dans le menu)");
        }
    }
    let autostart_initial = autostart.as_ref().map(autostart::is_enabled).unwrap_or(false);

    // 6. Tray + menu
    let event_loop = EventLoopBuilder::new().build();

    let menu               = Menu::new();
    let item_status        = MenuItem::new("Statut : Actif", false, None);
    let item_kubo          = MenuItem::new(format!("IPFS (kubo) : {kubo_status}"), false, None);
    let item_nostr         = MenuItem::new(format!("NOSTR relay : {nostr_status}"), false, None);
    let item_pins          = MenuItem::new("Pins gérés : 0", false, None);
    let item_bw            = MenuItem::new(format!("BP du jour : 0 / {cap_mb} Mo"), false, None);
    let item_open          = MenuItem::new("Ouvrir Infinity", true, None);
    let item_toggle        = MenuItem::new("Mettre en pause", true, None);
    // Phase 2.F — génère un pairing token affiché dans les logs
    // (out-of-band : aucun JS ne peut le lire, seul l'utilisateur
    // assis devant la machine voit la console / fichier de log).
    let item_pair          = MenuItem::new("Appairer un nouvel appareil…", true, None);
    let item_autostart     = CheckMenuItem::new(
        "Démarrer à l'ouverture de session",
        autostart.is_some(),
        autostart_initial,
        None,
    );
    let item_quit          = MenuItem::new("Quitter Infinity Node", true, None);

    menu.append(&item_status)?;
    menu.append(&PredefinedMenuItem::separator())?;
    menu.append(&item_kubo)?;
    menu.append(&item_nostr)?;
    menu.append(&item_pins)?;
    menu.append(&item_bw)?;
    menu.append(&PredefinedMenuItem::separator())?;
    menu.append(&item_open)?;
    menu.append(&item_toggle)?;
    menu.append(&item_pair)?;
    menu.append(&PredefinedMenuItem::separator())?;
    menu.append(&item_autostart)?;
    menu.append(&PredefinedMenuItem::separator())?;
    menu.append(&item_quit)?;

    let id_open      = item_open.id().clone();
    let id_toggle    = item_toggle.id().clone();
    let id_pair      = item_pair.id().clone();
    let id_autostart = item_autostart.id().clone();
    let id_quit      = item_quit.id().clone();

    let _tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip(format!("Infinity Node v{VERSION}"))
        .with_icon(build_icon())
        .build()?;

    let menu_channel = MenuEvent::receiver();
    let enabled_for_loop = state.enabled.clone();
    let pwa_url_owned    = pwa_url.clone();
    let pins_for_loop    = pins.clone();
    let bw_for_loop      = bandwidth.clone();
    let auth_for_loop    = state.auth.clone();
    let mut last_refresh = Instant::now();

    // Backends détenus DANS la closure pour qu'ils survivent jusqu'à Quit.
    // tao::run ne retourne jamais → on doit drop EXPLICITEMENT avant Exit
    // pour que ManagedChild::drop kille les child processes.
    let mut held_backends = Some((kubo, nostr));

    event_loop.run(move |event, _window, control_flow| {
        *control_flow = ControlFlow::Poll;

        if matches!(event, Event::NewEvents(tao::event::StartCause::Init)) {
            info!("event loop initialized");
        }

        // Refresh tray labels (pins + BW) toutes les 2s. Le poll mode
        // tape ce code en continu donc le throttle est nécessaire.
        if last_refresh.elapsed() > Duration::from_secs(2) {
            last_refresh = Instant::now();
            let (count, _bytes) = pins_for_loop.totals();
            item_pins.set_text(format!("Pins gérés : {count}"));
            let used_mb = bw_for_loop.used() / (1024 * 1024);
            let cap     = bw_for_loop.cap() / (1024 * 1024);
            let warn    = if bw_for_loop.is_over_cap() { " ⚠" } else { "" };
            item_bw.set_text(if cap > 0 {
                format!("BP du jour : {used_mb} / {cap} Mo{warn}")
            } else {
                format!("BP du jour : {used_mb} Mo (illimité)")
            });
        }

        while let Ok(ev) = menu_channel.try_recv() {
            match ev.id() {
                id if id == &id_open => {
                    if let Err(e) = open::that_detached(&pwa_url_owned) {
                        warn!("open url failed: {e}");
                    }
                }
                id if id == &id_toggle => {
                    let was = enabled_for_loop.fetch_xor(true, Ordering::Relaxed);
                    let now_enabled = !was;
                    item_toggle.set_text(if now_enabled { "Mettre en pause" } else { "Reprendre" });
                    item_status.set_text(if now_enabled { "Statut : Actif" } else { "Statut : En pause" });
                    info!("companion toggled → enabled={now_enabled}");
                }
                id if id == &id_pair => {
                    // Phase 2.F — out-of-band pairing : on génère le token
                    // et on l'AFFICHE seulement dans la console (logs).
                    // Aucune route HTTP ne le retourne — un site malveillant
                    // ne peut donc PAS s'auto-appairer en silence. Le user
                    // doit avoir accès physique/SSH à la machine pour le
                    // lire, puis le coller manuellement dans la PWA.
                    let token = auth_for_loop.create_pairing_token(None);
                    println!(
                        "\n\
                         ╔══════════════════════════════════════════════════════════════════╗\n\
                         ║  PAIRING TOKEN — valide 10 min, à coller dans la PWA Infinity    ║\n\
                         ╠══════════════════════════════════════════════════════════════════╣\n\
                         ║  {}  ║\n\
                         ╚══════════════════════════════════════════════════════════════════╝\n",
                        token.token
                    );
                    info!("pairing token generated (visible in console only)");
                }
                id if id == &id_autostart => {
                    if let Some(auto) = autostart.as_ref() {
                        let want_enabled = item_autostart.is_checked();
                        let res = if want_enabled {
                            autostart::enable(auto)
                        } else {
                            autostart::disable(auto)
                        };
                        match res {
                            Ok(_) => info!("autostart → enabled={want_enabled}"),
                            Err(e) => {
                                warn!("autostart change failed: {e}");
                                item_autostart.set_checked(!want_enabled);
                            }
                        }
                    }
                }
                id if id == &id_quit => {
                    info!("quit requested via tray — killing backends");
                    // CRITIQUE : drop explicite avant Exit, sinon process::exit
                    // skippe les Drops et kubo/nostr-rs-relay restent orphelins.
                    drop(held_backends.take());
                    *control_flow = ControlFlow::Exit;
                }
                _ => {}
            }
        }
    });
}
