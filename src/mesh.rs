//! Maillage de stockage (P3b) — côté nœud.
//!
//! Active la participation du Compagnon / nœud-graine au maillage Infinity :
//!   - **subscribe** les demandes `MESH_MIRROR` (kind 30211) sur les relais
//!     Infinity → épingle le CID demandé (réutilise kubo + PinTracker) ;
//!   - **publish** une annonce `MESH_NODE` (kind 30210) signée par une clé NOSTR
//!     dédiée au nœud, avec le **gateway public** (env `INFINITY_PUBLIC_GATEWAY`)
//!     → les nœuds-graines deviennent sources de résolution pour la PWA.
//!
//! Client NOSTR minimal fait main (signature NIP-01 via secp256k1 schnorr +
//! WebSocket tokio-tungstenite) pour éviter une dépendance lourde/mouvante.
//!
//! Activation : `INFINITY_MESH=1` (off par défaut). Relais : `INFINITY_MESH_RELAYS`
//! (csv) ou défaut. Gateway public optionnel : `INFINITY_PUBLIC_GATEWAY`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};
use secp256k1::hashes::{sha256, Hash};
use serde_json::{json, Value};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tracing::{info, warn};

use crate::pinning::{KuboPinClient, PinRecord, PinTracker};

const KIND_MESH_NODE:   u64 = 30210;
const KIND_MESH_MIRROR: u64 = 30211;
const REANNOUNCE_SECS:  u64 = 30 * 60;
const RECONNECT_SECS:   u64 = 30;
const KEY_FILE:         &str = "mesh-node.key";

const DEFAULT_RELAYS: &[&str] = &[
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.primal.net",
];

#[derive(Clone)]
pub struct MeshConfig {
    pub relays:         Vec<String>,
    pub public_gateway: Option<String>,
}

impl MeshConfig {
    /// Lit la config depuis l'environnement. `None` si le maillage est désactivé.
    pub fn from_env() -> Option<Self> {
        if std::env::var("INFINITY_MESH").ok().as_deref() != Some("1") {
            return None;
        }
        let relays = match std::env::var("INFINITY_MESH_RELAYS") {
            Ok(s) if !s.trim().is_empty() => s.split(',').map(|r| r.trim().to_string()).filter(|r| !r.is_empty()).collect(),
            _ => DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect(),
        };
        let public_gateway = std::env::var("INFINITY_PUBLIC_GATEWAY").ok()
            .map(|s| s.trim().trim_end_matches('/').to_string())
            .filter(|s| s.starts_with("https://"));
        Some(Self { relays, public_gateway })
    }
}

/// Signataire NOSTR du nœud (clé secp256k1 dédiée, persistée sur disque).
struct Signer {
    secp:       Secp256k1<secp256k1::All>,
    keypair:    Keypair,
    pubkey_hex: String,
}

impl Signer {
    /// Charge la clé depuis `~/.infinity-node/mesh-node.key`, ou en génère une.
    fn load_or_create() -> Result<Self, String> {
        let dir = dirs::home_dir().ok_or("home dir introuvable")?.join(".infinity-node");
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let path = dir.join(KEY_FILE);
        let secp = Secp256k1::new();
        let sk = if let Ok(hexstr) = std::fs::read_to_string(&path) {
            let bytes = hex::decode(hexstr.trim()).map_err(|e| e.to_string())?;
            SecretKey::from_slice(&bytes).map_err(|e| e.to_string())?
        } else {
            let sk = SecretKey::new(&mut secp256k1::rand::thread_rng());
            std::fs::write(&path, hex::encode(sk.secret_bytes())).map_err(|e| e.to_string())?;
            sk
        };
        let keypair = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _parity): (XOnlyPublicKey, _) = keypair.x_only_public_key();
        Ok(Self { secp, keypair, pubkey_hex: hex::encode(xonly.serialize()) })
    }

    /// Construit + signe un event NOSTR (NIP-01) → JSON de l'objet event.
    fn sign_event(&self, kind: u64, tags: &Value, content: &str) -> Value {
        let created_at = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        // id = sha256(json([0, pubkey, created_at, kind, tags, content]))
        let serial = json!([0, self.pubkey_hex, created_at, kind, tags, content]);
        let serial_str = serde_json::to_string(&serial).unwrap_or_default();
        let digest = sha256::Hash::hash(serial_str.as_bytes());
        let id_bytes = digest.to_byte_array();
        let msg = Message::from_digest(id_bytes);
        let sig = self.secp.sign_schnorr_no_aux_rand(&msg, &self.keypair);
        json!({
            "id":         hex::encode(id_bytes),
            "pubkey":     self.pubkey_hex,
            "created_at": created_at,
            "kind":       kind,
            "tags":       tags,
            "content":    content,
            "sig":        hex::encode(sig.serialize()),
        })
    }
}

/// Lance le maillage (tâche longue). Idempotent à l'échelle process (un appel).
pub async fn run(cfg: MeshConfig, pins: PinTracker, pin_client: Option<KuboPinClient>) {
    let signer = match Signer::load_or_create() {
        Ok(s) => std::sync::Arc::new(s),
        Err(e) => { warn!("[mesh] clé NOSTR du nœud indisponible : {e} — maillage désactivé"); return; }
    };
    info!("[mesh] actif — npubkey {} — {} relais — gateway public {}",
        &signer.pubkey_hex[..16.min(signer.pubkey_hex.len())],
        cfg.relays.len(),
        cfg.public_gateway.as_deref().unwrap_or("(aucun)"));

    let pins = std::sync::Arc::new(pins);
    let pin_client = std::sync::Arc::new(pin_client);
    let cfg = std::sync::Arc::new(cfg);

    let mut handles = Vec::new();
    for relay in cfg.relays.iter().cloned() {
        let signer = signer.clone();
        let pins = pins.clone();
        let pin_client = pin_client.clone();
        let cfg = cfg.clone();
        handles.push(tokio::spawn(async move {
            relay_loop(relay, signer, pins, pin_client, cfg).await;
        }));
    }
    for h in handles { let _ = h.await; }
}

/// Boucle de connexion/reconnexion à UN relai.
async fn relay_loop(
    url: String,
    signer: std::sync::Arc<Signer>,
    pins: std::sync::Arc<PinTracker>,
    pin_client: std::sync::Arc<Option<KuboPinClient>>,
    cfg: std::sync::Arc<MeshConfig>,
) {
    loop {
        match connect_async(url.as_str()).await {
            Ok((ws, _)) => {
                info!("[mesh] connecté à {url}");
                let (mut write, mut read) = ws.split();

                // Souscription aux demandes de mirror.
                let req = json!(["REQ", "mesh-mirror", { "kinds": [KIND_MESH_MIRROR] }]);
                if write.send(WsMessage::Text(req.to_string())).await.is_err() { continue; }

                // Annonce initiale de mon nœud.
                let _ = write.send(WsMessage::Text(json!(["EVENT", announce(&signer, &cfg)]).to_string())).await;

                let mut tick = tokio::time::interval(Duration::from_secs(REANNOUNCE_SECS));
                tick.tick().await; // consomme le tick immédiat

                loop {
                    tokio::select! {
                        _ = tick.tick() => {
                            if write.send(WsMessage::Text(json!(["EVENT", announce(&signer, &cfg)]).to_string())).await.is_err() { break; }
                        }
                        msg = read.next() => {
                            match msg {
                                Some(Ok(WsMessage::Text(txt))) => handle_message(&txt, &pins, &pin_client).await,
                                Some(Ok(WsMessage::Ping(_))) | Some(Ok(WsMessage::Pong(_))) => {}
                                Some(Ok(WsMessage::Close(_))) | None => break,
                                Some(Err(e)) => { warn!("[mesh] {url} erreur lecture : {e}"); break; }
                                _ => {}
                            }
                        }
                    }
                }
            }
            Err(e) => warn!("[mesh] connexion {url} échouée : {e}"),
        }
        tokio::time::sleep(Duration::from_secs(RECONNECT_SECS)).await;
    }
}

/// Construit l'annonce MESH_NODE signée (created_at frais à chaque appel).
fn announce(signer: &Signer, cfg: &MeshConfig) -> Value {
    let mut tags: Vec<Value> = vec![
        json!(["d", "primary"]),
        json!(["cap", "ipfs"]),
        json!(["mirror", "1"]),
    ];
    if let Some(gw) = &cfg.public_gateway {
        tags.push(json!(["gateway", gw]));
    }
    signer.sign_event(KIND_MESH_NODE, &Value::Array(tags), "")
}

/// Traite un message relai : sur EVENT MESH_MIRROR, épingle le CID.
async fn handle_message(txt: &str, pins: &PinTracker, pin_client: &Option<KuboPinClient>) {
    let v: Value = match serde_json::from_str(txt) { Ok(v) => v, Err(_) => return };
    let arr = match v.as_array() { Some(a) => a, None => return };
    if arr.first().and_then(|x| x.as_str()) != Some("EVENT") || arr.len() < 3 { return; }
    let ev = &arr[2];
    if ev.get("kind").and_then(|k| k.as_u64()) != Some(KIND_MESH_MIRROR) { return; }
    let tags = match ev.get("tags").and_then(|t| t.as_array()) { Some(t) => t, None => return };
    let cid = tags.iter().find_map(|t| {
        let pair = t.as_array()?;
        if pair.first()?.as_str()? == "cid" { pair.get(1)?.as_str() } else { None }
    });
    let cid = match cid { Some(c) if !c.is_empty() => c.to_string(), _ => return };
    mirror_pin(&cid, pins, pin_client).await;
}

/// Épingle un CID demandé par le maillage (respecte la pin policy du module « mesh »).
async fn mirror_pin(cid: &str, pins: &PinTracker, pin_client: &Option<KuboPinClient>) {
    let rule = pins.snapshot_policy().rule_for("mesh");
    if !rule.enabled { return; }
    // Déjà épinglé ? on évite le travail redondant.
    if pins.list_pins().iter().any(|p| p.cid == cid) { return; }
    let size = if let Some(pc) = pin_client.as_ref() {
        if let Err(e) = pc.pin_add(cid).await { warn!("[mesh] pin {cid} échoué : {e}"); return; }
        pc.object_size(cid).await
    } else { 0 };
    pins.upsert(PinRecord {
        cid:        cid.to_string(),
        module:     "mesh".to_string(),
        pinned_at:  crate::pinning::unix_now(),
        ttl_secs:   (rule.default_ttl_hours as u64) * 3600,
        size_bytes: size,
    });
    info!("[mesh] CID épinglé pour le maillage : {cid} ({size} o)");
}
