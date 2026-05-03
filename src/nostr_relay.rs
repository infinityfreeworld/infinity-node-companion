//! # Backend nostr-rs-relay — Phase E
//!
//! Spawn d'une instance `nostr-rs-relay` locale écoutant sur
//! `127.0.0.1:7777`. Auto-génère un config.toml minimal dans
//! `~/.infinity-node/relay/` si absent.
//!
//! ## Pré-requis
//!
//! Le binaire `nostr-rs-relay` doit être présent sur le PATH. Doc :
//! https://github.com/scsibug/nostr-rs-relay
//!
//! ## Métriques
//!
//! `nostr-rs-relay` n'expose pas d'endpoint stats par défaut. Pour
//! l'instant on remonte juste un booléen `is_running`. NIP-11 (info
//! relay) pourrait être interrogé, mais ça donne pas de live stats.
//! Métriques détaillées (events/s, conns) → Phase E.1.
//!
//! ## Port
//!
//! `127.0.0.1:7777` par défaut. La PWA NE LE LIT PAS directement —
//! elle passe par le handshake (champ `nostrRelayUrl`).

use crate::supervisor::ManagedChild;
use std::{path::PathBuf, process::Command};
use tracing::{info, warn};

const BIN:  &str = "nostr-rs-relay";
const PORT: u16  = 7777;

pub struct NostrRelayBackend {
    _child:    ManagedChild,
    pub url:   String,
}

impl NostrRelayBackend {
    pub fn try_start() -> Option<Self> {
        if which::which(BIN).is_err() {
            warn!("nostr-rs-relay backend: '{BIN}' introuvable sur PATH — skip");
            return None;
        }

        let dir = data_dir();
        if let Err(e) = std::fs::create_dir_all(&dir) {
            warn!("nostr-rs-relay: mkdir {} failed: {e}", dir.display());
            return None;
        }
        let cfg = dir.join("config.toml");
        if !cfg.exists() {
            if let Err(e) = std::fs::write(&cfg, default_config()) {
                warn!("nostr-rs-relay: write config failed: {e}");
                return None;
            }
            info!("nostr-rs-relay: config par défaut écrite ({})", cfg.display());
        }

        let mut cmd = Command::new(BIN);
        cmd.args([
            "--config", cfg.to_str().unwrap_or("config.toml"),
            "--db",     dir.to_str().unwrap_or("."),
        ]);
        let child = ManagedChild::spawn("nostr-rs-relay", cmd)?;

        Some(Self {
            _child: child,
            url:    format!("ws://127.0.0.1:{PORT}"),
        })
    }
}

fn data_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".infinity-node")
        .join("relay")
}

/// Config TOML minimale — bind loopback, db SQLite locale, no auth.
/// Cohérent avec la philosophie Tier 1 : le relai sert d'abord le
/// Bâtisseur lui-même, l'exposition publique vient en Phase F.
fn default_config() -> String {
    format!(r#"# Auto-généré par Infinity Node
[info]
relay_url = "ws://127.0.0.1:{PORT}/"
name      = "Infinity Node (local)"
description = "Relai NOSTR local d'un Bâtisseur Infinity"

[network]
address = "127.0.0.1"
port    = {PORT}

[database]
data_directory = "."
engine         = "sqlite"

[limits]
messages_per_sec      = 0
broadcast_buffer      = 16384
event_persist_buffer  = 4096

[retention]
# Conserver tout par défaut (Tier 0 user). Ajustable manuellement.
max_events    = 0
"#)
}
