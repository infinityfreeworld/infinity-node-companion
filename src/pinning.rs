//! # Pin policy + tracker — Phase E.1
//!
//! Le companion expose une API HTTP que les modules PWA appellent pour
//! demander la persistance d'un CID IPFS. Chaque pin est associé :
//!   - à un **module** (obf, mhe, mouv, …) — utilisé pour appliquer la
//!     politique par module et pour les caps storage par module
//!   - à un **TTL** (heures) — au-delà, le janitor unpinne
//!     automatiquement et le bloc devient candidat au GC kubo
//!
//! ## Politique
//!
//! [`PinPolicy`] est persistée dans `~/.infinity-node/policy.json`. Le
//! Bâtisseur peut la modifier via l'endpoint `PUT /api/policy` (UI
//! Cœur du Cube) ou directement à la main (le fichier est rechargé au
//! prochain restart).
//!
//! ## Tracker
//!
//! [`PinTracker`] garde le mapping `cid → PinRecord` en mémoire et le
//! persiste dans `~/.infinity-node/pins.json` à chaque mutation. Au
//! boot, on relit le fichier pour reprendre l'état.
//!
//! ## Janitor
//!
//! Tâche tokio qui tourne toutes les heures, scanne les pins, et
//! déclenche l'unpin kubo + suppression du record pour ceux dont
//! `pinned_at + ttl_secs < now`.
//!
//! ## Pourquoi pas garbage collection auto ?
//!
//! kubo expose `/api/v0/repo/gc` qui collecte les blocs non pinnés.
//! On NE le déclenche PAS depuis le companion : c'est lent (peut
//! prendre minutes sur un gros repo) et le user peut vouloir tester
//! manuellement. On unpin, c'est tout. Le user peut planifier un GC
//! via la tray (TODO E.2) ou laisser kubo gérer en background.

use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tracing::{info, warn};

const POLICY_FILE: &str = "policy.json";
const PINS_FILE:   &str = "pins.json";

// ── Données persistées ───────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ModuleRule {
    pub enabled:           bool,
    /// Cap stockage en Mo pour ce module. 0 = pas de cap.
    pub max_mb:            u64,
    /// TTL par défaut si la requête ne le précise pas. 0 = jamais expirer.
    pub default_ttl_hours: u32,
}

impl Default for ModuleRule {
    fn default() -> Self {
        Self { enabled: true, max_mb: 100, default_ttl_hours: 24 * 7 }  // 7j
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct PinPolicy {
    /// Mapping module_id → règle. Modules absents = règle par défaut.
    pub modules: HashMap<String, ModuleRule>,
    /// Fallback appliqué aux modules pas listés explicitement.
    #[serde(default)]
    pub default_rule: ModuleRule,
}

impl PinPolicy {
    pub fn rule_for(&self, module: &str) -> ModuleRule {
        self.modules.get(module).cloned().unwrap_or_else(|| self.default_rule.clone())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PinRecord {
    pub cid:        String,
    pub module:     String,
    /// Timestamp Unix (secondes).
    pub pinned_at:  u64,
    /// 0 = jamais expirer.
    pub ttl_secs:   u64,
    /// Taille rapportée par kubo `/object/stat` au moment du pin (octets, 0 si inconnue).
    #[serde(default)]
    pub size_bytes: u64,
}

// ── État partagé ─────────────────────────────────────────────────────────

pub struct PinState {
    pub policy: PinPolicy,
    pub pins:   HashMap<String, PinRecord>,   // cid → record
}

#[derive(Clone)]
pub struct PinTracker {
    inner:    Arc<Mutex<PinState>>,
    data_dir: PathBuf,
}

impl PinTracker {
    /// Charge l'état depuis disque (ou crée des fichiers neufs).
    pub fn load() -> Self {
        let data_dir = data_dir();
        let _ = std::fs::create_dir_all(&data_dir);

        let policy = read_json::<PinPolicy>(&data_dir.join(POLICY_FILE))
            .unwrap_or_default();
        let pins   = read_json::<HashMap<String, PinRecord>>(&data_dir.join(PINS_FILE))
            .unwrap_or_default();

        Self {
            inner:    Arc::new(Mutex::new(PinState { policy, pins })),
            data_dir,
        }
    }

    pub fn snapshot_policy(&self) -> PinPolicy {
        self.inner.lock().expect("pin state lock").policy.clone()
    }

    pub fn set_policy(&self, p: PinPolicy) {
        let mut g = self.inner.lock().expect("pin state lock");
        g.policy = p;
        let _ = write_json(&self.data_dir.join(POLICY_FILE), &g.policy);
    }

    pub fn list_pins(&self) -> Vec<PinRecord> {
        self.inner.lock().expect("pin state lock").pins.values().cloned().collect()
    }

    /// Compte total + somme des tailles (octets).
    pub fn totals(&self) -> (u64, u64) {
        let g = self.inner.lock().expect("pin state lock");
        let count = g.pins.len() as u64;
        let bytes = g.pins.values().map(|p| p.size_bytes).sum();
        (count, bytes)
    }

    /// Insère ou met à jour un record + persistance.
    pub fn upsert(&self, rec: PinRecord) {
        let mut g = self.inner.lock().expect("pin state lock");
        g.pins.insert(rec.cid.clone(), rec);
        let _ = write_json(&self.data_dir.join(PINS_FILE), &g.pins);
    }

    pub fn remove(&self, cid: &str) -> Option<PinRecord> {
        let mut g = self.inner.lock().expect("pin state lock");
        let removed = g.pins.remove(cid);
        if removed.is_some() {
            let _ = write_json(&self.data_dir.join(PINS_FILE), &g.pins);
        }
        removed
    }

    /// Renvoie les CIDs expirés (ttl > 0 et pinned_at + ttl < now).
    pub fn expired_cids(&self) -> Vec<String> {
        let now = unix_now();
        let g   = self.inner.lock().expect("pin state lock");
        g.pins.values()
            .filter(|p| p.ttl_secs > 0 && p.pinned_at + p.ttl_secs < now)
            .map(|p| p.cid.clone())
            .collect()
    }
}

// ── Helpers IO ───────────────────────────────────────────────────────────

fn data_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".infinity-node")
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &PathBuf) -> Option<T> {
    let s = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&s).ok()
}

fn write_json<T: Serialize>(path: &PathBuf, v: &T) -> Result<(), String> {
    let s = serde_json::to_string_pretty(v).map_err(|e| e.to_string())?;
    std::fs::write(path, s).map_err(|e| e.to_string())
}

pub fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

// ── Client kubo (pin add/rm/object stat) ─────────────────────────────────

#[derive(Clone)]
pub struct KuboPinClient {
    client:   reqwest::Client,
    api_base: String,
}

impl KuboPinClient {
    pub fn new(api_base: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))   // pin/object/stat peuvent être lents
            .build()
            .expect("reqwest client");
        Self { client, api_base }
    }

    pub async fn pin_add(&self, cid: &str) -> Result<(), String> {
        let url = format!("{}/pin/add", self.api_base);
        let r = self.client.post(&url).query(&[("arg", cid)])
            .send().await.map_err(|e| e.to_string())?;
        if !r.status().is_success() {
            return Err(format!("HTTP {}", r.status()));
        }
        Ok(())
    }

    pub async fn pin_rm(&self, cid: &str) -> Result<(), String> {
        let url = format!("{}/pin/rm", self.api_base);
        let r = self.client.post(&url).query(&[("arg", cid)])
            .send().await.map_err(|e| e.to_string())?;
        if !r.status().is_success() {
            return Err(format!("HTTP {}", r.status()));
        }
        Ok(())
    }

    /// Renvoie `CumulativeSize` (taille du DAG, octets) ou 0 si inconnu.
    pub async fn object_size(&self, cid: &str) -> u64 {
        let url = format!("{}/object/stat", self.api_base);
        let Ok(r) = self.client.post(&url).query(&[("arg", cid)]).send().await else {
            return 0;
        };
        if !r.status().is_success() { return 0; }
        let Ok(j) = r.json::<serde_json::Value>().await else { return 0; };
        j.get("CumulativeSize").and_then(|v| v.as_u64()).unwrap_or(0)
    }
}

// ── Janitor ──────────────────────────────────────────────────────────────

/// Boucle qui tourne toutes les heures, unpinne les expirés via kubo,
/// puis purge les records.
pub fn spawn_janitor(rt: &tokio::runtime::Handle, tracker: PinTracker, kubo: Option<KuboPinClient>) {
    rt.spawn(async move {
        // Première passe différée pour laisser kubo monter
        tokio::time::sleep(Duration::from_secs(60)).await;
        loop {
            let expired = tracker.expired_cids();
            if !expired.is_empty() {
                info!("janitor: {} pins expirés à nettoyer", expired.len());
                for cid in expired {
                    if let Some(k) = kubo.as_ref() {
                        if let Err(e) = k.pin_rm(&cid).await {
                            warn!("janitor: pin_rm {cid} failed: {e}");
                            continue;       // on garde le record si kubo râle
                        }
                    }
                    tracker.remove(&cid);
                }
            }
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    });
}
