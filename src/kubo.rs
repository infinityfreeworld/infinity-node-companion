//! # Backend Kubo (IPFS) — Phase E
//!
//! Spawn et supervise une instance kubo dédiée à Infinity Node, isolée
//! du repo IPFS éventuellement déjà installé par l'utilisateur.
//!
//! ## Isolation
//!
//! On crée un repo IPFS dédié dans `~/.infinity-node/ipfs/` (env
//! `IPFS_PATH`) avec ports custom :
//!
//! | Service           | Port stock | Port Infinity Node |
//! |-------------------|------------|--------------------|
//! | API HTTP          | 5001       | **5101**           |
//! | Gateway HTTP      | 8080       | **8181**           |
//! | Swarm TCP         | 4001       | **4101**           |
//! | Swarm WS          | -          | **4102**           |
//!
//! Comme ça, si l'utilisateur a déjà `ipfs daemon` qui tourne en
//! parallèle (kubo desktop, brave node, etc.), aucun conflit.
//!
//! ## Pré-requis
//!
//! Le binaire `ipfs` doit être présent sur le PATH. Si absent, on log
//! et on retourne `None` — la PWA verra `capabilities` sans `"ipfs"`.
//! Doc d'install : https://docs.ipfs.tech/install/command-line/
//!
//! ## Métriques
//!
//! Polling HTTP toutes les 5 s sur l'API kubo (toutes les routes
//! POST, c'est le design de kubo). Trois endpoints :
//!
//!   - `POST /api/v0/swarm/peers`         → nombre de pairs connectés
//!   - `POST /api/v0/pin/ls?type=recursive` → CIDs pinnés récursivement
//!   - `POST /api/v0/stats/bw`            → bande passante cumulée
//!
//! Les valeurs sont publiées dans [`KuboMetrics`] que le `/api/handshake`
//! recopie dans sa réponse.

use crate::bandwidth::BandwidthTracker;
use crate::ipfs_private::{disable_public_bootstrap, is_repo_in_private_mode};
use crate::pinning::KuboPinClient;
use crate::supervisor::ManagedChild;
use serde::Deserialize;
use std::{
    path::PathBuf,
    process::Command,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tracing::{info, warn};

const API_PORT:     u16 = 5101;
const GATEWAY_PORT: u16 = 8181;
const SWARM_PORT:   u16 = 4101;
const SWARM_WS:     u16 = 4102;
const BIN:          &str = "ipfs";

pub fn api_base() -> String { format!("http://127.0.0.1:{API_PORT}/api/v0") }

/// Snapshot atomique des métriques publiées par kubo.
#[derive(Default)]
pub struct KuboMetrics {
    pub peers:        AtomicU64,
    pub pinned_count: AtomicU64,
    pub bytes_served: AtomicU64,
}

pub struct KuboBackend {
    /// Détenu pour garder le child vivant — Drop = kill.
    _child:   ManagedChild,
    pub metrics:  Arc<KuboMetrics>,
    pub gateway:  String,
}

impl KuboBackend {
    /// Renvoie `None` si :
    ///   - `ipfs` n'est pas sur le PATH
    ///   - l'init du repo échoue
    ///   - le daemon ne démarre pas
    ///
    /// Quand `Some` est renvoyé, le polling de métriques tourne déjà
    /// en background. `bandwidth` est mis à jour à chaque cycle.
    pub fn try_start(
        rt: &tokio::runtime::Handle,
        bandwidth: Arc<BandwidthTracker>,
    ) -> Option<Self> {
        if which::which(BIN).is_err() {
            warn!("kubo backend: '{BIN}' introuvable sur PATH — skip");
            return None;
        }

        let repo = repo_path();
        if let Err(e) = ensure_repo_initialized(&repo) {
            warn!("kubo backend: init repo failed: {e}");
            return None;
        }
        if let Err(e) = configure_ports(&repo) {
            warn!("kubo backend: configure_ports failed: {e}");
            return None;
        }

        // Phase 3-IPFS-A — détection mode privé. Si swarm.key existe
        // dans le repo, on lance Kubo avec LIBP2P_FORCE_PNET=1 qui
        // refuse TOUT peer sans la même clé (réseau privé fermé).
        // On désactive aussi les bootstrap publics (sinon Kubo essaie
        // quand même de joindre le DHT mondial qui rejettera mais
        // consomme cycles).
        let private = is_repo_in_private_mode(&repo);
        if private {
            if let Err(e) = disable_public_bootstrap(&repo) {
                warn!("disable_public_bootstrap: {e}");
            }
            info!("kubo: démarrage en MODE PRIVÉ (swarm.key détectée)");
        }

        /* Un kubo d'un run précédent tient peut-être encore `repo.lock` — le
           23/08, un daemon vieux de 41 h le gardait, notre kubo mourait en
           30 ms sur « someone else has the lock », et le nœud annonçait quand
           même la capacité `ipfs`. Le fichier de PID ne suffit pas ici : ce
           fantôme-là avait été lancé par une version du nœud qui n'en écrivait
           pas encore. On demande donc au système QUI tient le verrou. */
        if crate::supervisor::liberer_verrou(&repo.join("repo.lock"), BIN) {
            info!("kubo: verrou du dépôt libéré, démarrage possible");
        }

        let mut cmd = Command::new(BIN);
        cmd.args(["daemon", "--migrate=true", "--enable-pubsub-experiment"])
            .env("IPFS_PATH", &repo);
        if private {
            cmd.env("LIBP2P_FORCE_PNET", "1");
        }
        let child = ManagedChild::spawn("kubo", cmd)?;

        let metrics = Arc::new(KuboMetrics::default());
        spawn_metrics_loop(rt, metrics.clone(), bandwidth);

        Some(Self {
            _child:   child,
            metrics,
            gateway:  format!("http://127.0.0.1:{GATEWAY_PORT}"),
        })
    }

    /// Client HTTP partagé pour les opérations de pinning.
    pub fn pin_client(&self) -> KuboPinClient {
        KuboPinClient::new(api_base())
    }
}

// ── Helpers privés ───────────────────────────────────────────────────────

fn repo_path() -> PathBuf {
    crate::chemins::sous_dossier("ipfs")
}

/// Lance `ipfs init` si le repo n'existe pas encore. Idempotent.
fn ensure_repo_initialized(repo: &PathBuf) -> Result<(), String> {
    if repo.join("config").exists() {
        return Ok(());
    }
    info!("kubo: initialisation du repo {}", repo.display());
    std::fs::create_dir_all(repo).map_err(|e| e.to_string())?;
    let out = Command::new(BIN)
        .args(["init", "--profile=server"])
        .env("IPFS_PATH", repo)
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).into_owned());
    }
    Ok(())
}

/// Configure les 4 ports custom via `ipfs config`. Idempotent.
fn configure_ports(repo: &PathBuf) -> Result<(), String> {
    let pairs: &[(&str, String)] = &[
        ("Addresses.API",       format!("/ip4/127.0.0.1/tcp/{API_PORT}")),
        ("Addresses.Gateway",   format!("/ip4/127.0.0.1/tcp/{GATEWAY_PORT}")),
    ];
    for (key, val) in pairs {
        run_config(repo, &[key, val])?;
    }
    // Swarm = JSON array → on doit utiliser --json
    let swarm = format!(
        "[\"/ip4/0.0.0.0/tcp/{SWARM_PORT}\", \
          \"/ip4/0.0.0.0/tcp/{SWARM_WS}/ws\"]"
    );
    run_config(repo, &["--json", "Addresses.Swarm", &swarm])?;
    Ok(())
}

fn run_config(repo: &PathBuf, args: &[&str]) -> Result<(), String> {
    let mut cmd_args = vec!["config"];
    cmd_args.extend_from_slice(args);
    let out = Command::new(BIN)
        .args(&cmd_args)
        .env("IPFS_PATH", repo)
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).into_owned());
    }
    Ok(())
}

// ── Polling métriques ────────────────────────────────────────────────────

#[derive(Deserialize)]
struct PeersResp { #[serde(rename = "Peers")] peers: Option<Vec<serde_json::Value>> }

#[derive(Deserialize)]
struct PinResp { #[serde(rename = "Keys")] keys: Option<serde_json::Map<String, serde_json::Value>> }

#[derive(Deserialize)]
struct BwResp { #[serde(rename = "TotalOut")] total_out: Option<u64> }

fn spawn_metrics_loop(
    rt: &tokio::runtime::Handle,
    metrics: Arc<KuboMetrics>,
    bandwidth: Arc<BandwidthTracker>,
) {
    rt.spawn(async move {
        // Donne 3 s à kubo pour ouvrir son API HTTP avant le 1er poll
        tokio::time::sleep(Duration::from_secs(3)).await;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .expect("reqwest client");
        let base = api_base();

        loop {
            // POST /swarm/peers
            if let Ok(r) = client.post(format!("{base}/swarm/peers")).send().await {
                if let Ok(j) = r.json::<PeersResp>().await {
                    let n = j.peers.map(|v| v.len() as u64).unwrap_or(0);
                    metrics.peers.store(n, Ordering::Relaxed);
                }
            }
            // POST /pin/ls?type=recursive
            if let Ok(r) = client
                .post(format!("{base}/pin/ls"))
                .query(&[("type", "recursive")])
                .send().await
            {
                if let Ok(j) = r.json::<PinResp>().await {
                    let n = j.keys.map(|m| m.len() as u64).unwrap_or(0);
                    metrics.pinned_count.store(n, Ordering::Relaxed);
                }
            }
            // POST /stats/bw — feed aussi le BandwidthTracker
            if let Ok(r) = client.post(format!("{base}/stats/bw")).send().await {
                if let Ok(j) = r.json::<BwResp>().await {
                    let total = j.total_out.unwrap_or(0);
                    metrics.bytes_served.store(total, Ordering::Relaxed);
                    bandwidth.sample(total);
                }
            }

            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
}
