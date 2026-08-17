//! # WebSocket stream — Phase Status (sprint 1.1)
//!
//! Endpoint `/api/stream` qui pousse en temps réel les snapshots de
//! métriques à toutes les PWAs connectées. Le contrat de la frame est
//! identique au handshake HTTP — comme ça, le client PWA passe ses
//! données par le même type quel que soit le canal (push WS ou poll
//! HTTP fallback).
//!
//! ## Cadence
//!
//! Tick toutes les **500 ms**. À chaque tick on calcule un snapshot ;
//! on n'envoie que si différent du dernier envoyé (change-detection
//! par hash sérialisé). En pratique :
//!   - quand kubo polle (5 s) → 1 frame envoyée
//!   - quand un pin est ajouté → frame envoyée immédiatement (au prochain tick)
//!   - sinon → silence radio
//!
//! Pas de broadcast channel : chaque connexion WS a sa propre task,
//! avec son propre last_hash. Simple, scale jusqu'à ~10 connexions
//! sans souci (le user n'en aura jamais que 1-2 onglets ouverts).
//!
//! ## Frame format
//!
//! ```json
//! { "type": "snapshot", "ts": 1234, "data": { ... } }
//! { "type": "paused" }
//! ```
//!
//! ## Pause sémantique
//!
//! Quand `enabled=false`, on envoie une seule frame `{"type":"paused"}`
//! puis on garde la connexion ouverte sans rien envoyer. Reprise = on
//! recommence à pousser des snapshots.

use axum::{
    extract::{ws::{Message, WebSocket, WebSocketUpgrade}, State},
    response::IntoResponse,
};
use serde::Serialize;
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    sync::atomic::Ordering,
    time::Duration,
};
use tracing::{debug, warn};

use crate::AppState;

const TICK_MS: u64 = 500;

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum Frame {
    Snapshot { ts: u64, data: serde_json::Value },
    Paused,
}

pub async fn ws_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(mut socket: WebSocket, state: AppState) {
    let mut last_hash: u64 = 0;
    let mut last_paused = false;
    let mut interval = tokio::time::interval(Duration::from_millis(TICK_MS));

    loop {
        tokio::select! {
            _ = interval.tick() => {
                if !state.enabled.load(Ordering::Relaxed) {
                    if !last_paused {
                        if socket.send(Message::Text(serde_json::to_string(&Frame::Paused).unwrap_or_default())).await.is_err() {
                            return;
                        }
                        last_paused = true;
                    }
                    continue;
                }
                last_paused = false;

                let snapshot = build_snapshot(&state);
                let h = hash_value(&snapshot);
                if h == last_hash {
                    continue;       // change-detection : on n'envoie que si différent
                }
                last_hash = h;

                let frame = Frame::Snapshot {
                    ts:   chrono_now_ms(),
                    data: snapshot,
                };
                let json = match serde_json::to_string(&frame) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                if socket.send(Message::Text(json)).await.is_err() {
                    debug!("ws client disconnected");
                    return;
                }
            }
            // Lit aussi côté client : ping/pong/close. Sinon le socket
            // garde des frames en buffer et finit par mourir.
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => return,
                    Some(Ok(Message::Ping(p)))  => {
                        if socket.send(Message::Pong(p)).await.is_err() { return; }
                    }
                    Some(Ok(_)) => {}
                    Some(Err(e)) => {
                        warn!("ws recv error: {e}");
                        return;
                    }
                }
            }
        }
    }
}

/// Construit un snapshot identique en forme à la réponse `/api/handshake`.
/// On copie la logique du handler HTTP plutôt que de l'appeler — éviter
/// un import cyclique main.rs ↔ stream.rs.
fn build_snapshot(state: &AppState) -> serde_json::Value {
    let (peers, pinned, bw) = state.kubo_metrics
        .as_ref()
        .map(|m| (
            m.peers.load(Ordering::Relaxed),
            m.pinned_count.load(Ordering::Relaxed),
            m.bytes_served.load(Ordering::Relaxed),
        ))
        .unwrap_or((0, 0, 0));
    let (managed_pins, managed_bytes) = state.pins.totals();
    let managed_pins_held = state.pins.held_count();

    let mut caps: Vec<&str> = Vec::new();
    if state.kubo_metrics.is_some() { caps.push("ipfs"); }
    if state.nostr_url.is_some()    { caps.push("nostr-relay"); }

    serde_json::json!({
        "service":          "infinity-node",
        "version":          env!("CARGO_PKG_VERSION"),
        "capabilities":     caps,
        "ipfsGateway":      state.kubo_gateway,
        "nostrRelayUrl":    state.nostr_url,
        "publicRelayUrl":   serde_json::Value::Null,
        "uptime":           state.started_at.elapsed().as_secs(),
        "peers":            peers,
        "pinnedCount":      pinned,
        "bytesServed":      bw,
        "managedPins":      managed_pins,
        "managedPinsBytes": managed_bytes,
        "managedPinsHeld":  managed_pins_held,
        "bandwidthUsedTodayBytes": state.bandwidth.used(),
        "bandwidthCapBytes":       state.bandwidth.cap(),
    })
}

fn hash_value(v: &serde_json::Value) -> u64 {
    let mut h = DefaultHasher::new();
    v.to_string().hash(&mut h);
    h.finish()
}

fn chrono_now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}
