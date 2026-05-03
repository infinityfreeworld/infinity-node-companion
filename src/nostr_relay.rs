//! # Backend nostr-rs-relay — Phase E + 3.A
//!
//! Spawn d'une instance `nostr-rs-relay` locale écoutant sur
//! `127.0.0.1:7777`. Auto-génère un `config.toml` minimal dans
//! `~/.infinity-node/relay/` si absent OU si la `owner_pubkey`
//! a changé depuis le dernier démarrage (= le relai applique la
//! nouvelle whitelist au prochain restart).
//!
//! ## Phase 3.A — mode "owned"
//!
//! Le relai accepte seulement les events SIGNÉS PAR la `owner_pubkey`
//! (la pubkey NOSTR du Bâtisseur, pas la pubkey device de la PWA).
//! Toute tentative d'écriture par une autre pubkey est rejetée au
//! niveau du relai (`[authorization].pubkey_whitelist`).
//!
//! Si `owner_pubkey` est `None`, on génère quand même un relai mais
//! sans whitelist (mode "ouvert local") — pratique pour le 1ᵉʳ run
//! où la PWA n'a pas encore poussé sa pubkey via `POST /relay/private/owner`.
//!
//! ## Re-config dynamique
//!
//! Quand la PWA met à jour `owner_pubkey` via l'API, on RÉ-ÉCRIT le
//! config.toml mais le subprocess en cours n'est PAS redémarré
//! automatiquement (éviterait de couper les sessions WS actives sans
//! prévenir l'utilisateur). La nouvelle whitelist sera active au
//! prochain `restart` du companion. L'API renvoie un avertissement
//! au caller pour qu'il puisse afficher un bouton "redémarrer".
//!
//! ## Pré-requis
//!
//! Le binaire `nostr-rs-relay` doit être présent sur le PATH. Doc :
//! https://github.com/scsibug/nostr-rs-relay
//!
//! ## Port
//!
//! `127.0.0.1:7777` par défaut (loopback). Phase 3.B élargira à
//! `0.0.0.0:7777` ou Tailscale IP pour le multi-device.

use crate::relay_installer;
use crate::supervisor::ManagedChild;
use std::{path::PathBuf, process::Command};
use tracing::{info, warn};

const PORT: u16 = 7777;

/// Configuration du backend NOSTR-relay au démarrage.
#[derive(Clone, Debug, Default)]
pub struct NostrRelayConfig {
    /// Pubkey hex 64 chars du Bâtisseur autorisé à écrire. None = pas
    /// de whitelist (mode local ouvert). En Phase 3.A on s'attend à
    /// ce que la PWA pousse cette valeur via `POST /relay/private/owner`.
    pub owner_pubkey: Option<String>,
}

pub struct NostrRelayBackend {
    _child:    ManagedChild,
    pub url:   String,
    /// Owner pubkey appliquée au démarrage (peut être stale si la PWA
    /// a depuis poussé une nouvelle valeur — voir doc en haut).
    pub applied_owner_pubkey: Option<String>,
}

impl NostrRelayBackend {
    /// Démarre le relai avec la config fournie.
    ///
    /// Si `config.owner_pubkey` est `Some(hex)` → whitelist active,
    /// seul le Bâtisseur peut publier. Sinon → relai en mode ouvert
    /// (utile pour le 1ᵉʳ run avant que la PWA ait set la pubkey).
    pub fn try_start_with_config(config: NostrRelayConfig) -> Option<Self> {
        // Phase 3.E — auto-install si binaire pas trouvé sur PATH ni
        // dans le dossier de cache local. find_existing() couvre les 2.
        let bin_path = match relay_installer::find_existing() {
            Some(p) => p,
            None => match relay_installer::ensure_installed() {
                Some(p) => p,
                None => {
                    warn!(
                        "nostr-rs-relay introuvable et auto-install impossible — relai désactivé.\n\
                         → installe manuellement : `cargo install nostr-rs-relay`\n\
                           ou récupère un binaire prédbuilt et place-le sur ton PATH."
                    );
                    return None;
                }
            },
        };

        let dir = data_dir();
        if let Err(e) = std::fs::create_dir_all(&dir) {
            warn!("nostr-rs-relay: mkdir {} failed: {e}", dir.display());
            return None;
        }

        // On RÉ-ÉCRIT toujours le config (pas de cache) — comme ça la
        // whitelist est garantie cohérente avec la valeur courante du
        // vault au démarrage.
        let cfg = dir.join("config.toml");
        let toml = build_config(&config);
        if let Err(e) = std::fs::write(&cfg, &toml) {
            warn!("nostr-rs-relay: write config failed: {e}");
            return None;
        }
        info!(
            "nostr-rs-relay config écrite ({}, owner: {})",
            cfg.display(),
            config.owner_pubkey.as_deref().unwrap_or("<aucun, mode ouvert>"),
        );

        let mut cmd = Command::new(&bin_path);
        cmd.args([
            "--config", cfg.to_str().unwrap_or("config.toml"),
            "--db",     dir.to_str().unwrap_or("."),
        ]);
        let child = ManagedChild::spawn("nostr-rs-relay", cmd)?;

        Some(Self {
            _child: child,
            url:    format!("ws://127.0.0.1:{PORT}"),
            applied_owner_pubkey: config.owner_pubkey,
        })
    }

    /// Renvoie le port utilisé (utile pour les futures découvertes mDNS).
    #[must_use]
    pub fn port() -> u16 { PORT }
}

fn data_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".infinity-node")
        .join("relay")
}

/// Génère le `config.toml` selon la config. Si `owner_pubkey` est défini,
/// on ajoute une section `[authorization]` avec `pubkey_whitelist` qui
/// rejette les events non signés par cette pubkey.
fn build_config(config: &NostrRelayConfig) -> String {
    let mut toml = format!(r#"# Auto-généré par Infinity Node — Phase 3.A
[info]
relay_url   = "ws://127.0.0.1:{PORT}/"
name        = "Infinity Node (privé)"
description = "Relai NOSTR privé d'un Bâtisseur Infinity"

[network]
address = "127.0.0.1"
port    = {PORT}

[database]
data_directory = "."
engine         = "sqlite"

[limits]
messages_per_sec     = 0
broadcast_buffer     = 16384
event_persist_buffer = 4096

[retention]
# Conserver tout par défaut (Tier 1 user, c'est SON cube). Ajustable.
max_events = 0
"#);

    if let Some(owner) = &config.owner_pubkey {
        toml.push_str(&format!(
            r#"
# Phase 3.A — relai PRIVÉ : seul le Bâtisseur peut écrire des events.
# Toute tentative d'EVENT signé par une autre pubkey est rejetée
# au niveau du relai (NIP-01 OK, NIP-09 deletion respectée).
[authorization]
pubkey_whitelist = ["{owner}"]
"#
        ));
    }

    toml
}
