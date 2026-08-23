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
    /// Tenu à jour à chaque mutation — jamais recalculé à la lecture.
    pub resume: ResumePins,
}

/// Les trois chiffres que tout le monde demande : combien de demandes,
/// combien d'octets, et combien sont RÉELLEMENT détenus.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ResumePins {
    pub enregistres: u64,
    pub octets:      u64,
    pub detenus:     u64,
}

/// Un seul parcours pour les trois chiffres.
#[must_use]
pub fn calculer_resume(pins: &HashMap<String, PinRecord>) -> ResumePins {
    let mut r = ResumePins { enregistres: pins.len() as u64, ..ResumePins::default() };
    for p in pins.values() {
        r.octets += p.size_bytes;
        if p.size_bytes > 0 {
            r.detenus += 1;
        }
    }
    r
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
            inner:    Arc::new(Mutex::new(PinState { policy, resume: calculer_resume(&pins), pins })),
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
        let r = self.resume();
        (r.enregistres, r.octets)
    }

    /// Les trois chiffres d'un coup, sans parcourir la table.
    ///
    /// ⚠️ Ils étaient recalculés à CHAQUE lecture — deux parcours complets
    /// (`totals` puis `held_count`), sous verrou, à chaque tick du flux
    /// (500 ms **par page ouverte**), à chaque handshake et toutes les 2 s
    /// pour le menu. Invisible avec dix pins ; avec les dizaines de milliers
    /// que vise un vrai nœud de stockage, c'est la table entière balayée
    /// plusieurs fois par seconde, verrou tenu — donc les écritures de pins
    /// qui attendent. Le résumé est maintenant tenu à jour à l'ÉCRITURE, qui
    /// réécrit déjà le fichier entier : le calcul y est gratuit en comparaison.
    pub fn resume(&self) -> ResumePins {
        self.inner.lock().expect("pin state lock").resume
    }

    /// Combien de pins le nœud DÉTIENT réellement, octets à l'appui.
    ///
    /// `totals()` compte des enregistrements — des DEMANDES. Le 17/08/2026, un
    /// nœud en annonçait dix pour zéro octet détenu, et l'interface écrivait
    /// « 10 contenus gardés ». Ce compteur-ci est le seul qu'on ait le droit de
    /// présenter comme un contenu conservé ; le publier évite à l'interface de
    /// devoir lister tous les pins pour l'apprendre.
    pub fn held_count(&self) -> u64 {
        self.resume().detenus
    }

    /// Insère ou met à jour un record + persistance.
    pub fn upsert(&self, rec: PinRecord) {
        let mut g = self.inner.lock().expect("pin state lock");
        g.pins.insert(rec.cid.clone(), rec);
        g.resume = calculer_resume(&g.pins);
        let _ = write_json(&self.data_dir.join(PINS_FILE), &g.pins);
    }

    pub fn remove(&self, cid: &str) -> Option<PinRecord> {
        let mut g = self.inner.lock().expect("pin state lock");
        let removed = g.pins.remove(cid);
        g.resume = calculer_resume(&g.pins);
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
    crate::chemins::dossier_donnees()
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

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Un tracker isolé du disque du Bâtisseur — chaque test a son dossier.
    fn tracker_jetable(nom: &str) -> PinTracker {
        let dir = std::env::temp_dir().join(format!("infinity-pins-test-{nom}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dossier de test");
        PinTracker {
            inner:    Arc::new(Mutex::new(PinState {
                policy: PinPolicy::default(),
                pins:   HashMap::new(),
                resume: ResumePins::default(),
            })),
            data_dir: dir,
        }
    }

    fn rec(cid: &str, size_bytes: u64) -> PinRecord {
        PinRecord {
            cid: cid.to_string(),
            module: "test".into(),
            pinned_at: 0,
            ttl_secs: 0,
            size_bytes,
        }
    }

    /// Le résumé est tenu à jour à l'écriture : il ne doit JAMAIS diverger de
    /// ce qu'un parcours complet donnerait. Un point de mutation qui oublie de
    /// le rafraîchir fait mentir tous les compteurs du nœud, en silence —
    /// c'est le risque qu'on prend en cessant de recalculer à la lecture, donc
    /// c'est ce que ce test surveille.
    #[test]
    fn le_resume_ne_derive_jamais_de_la_table() {
        let t = tracker_jetable("resume");
        let verifier = |t: &PinTracker, ou: &str| {
            let attendu = calculer_resume(&t.inner.lock().expect("verrou").pins);
            assert_eq!(t.resume(), attendu, "résumé périmé après {ou}");
        };

        t.upsert(rec("a", 0));
        t.upsert(rec("b", 10));
        t.upsert(rec("c", 0));
        verifier(&t, "des insertions");

        t.remove("b");
        verifier(&t, "une suppression");

        t.upsert(rec("c", 5));          // une demande devient détenue
        verifier(&t, "une mise à jour");

        t.remove("inexistant");
        verifier(&t, "une suppression sans effet");

        assert_eq!(
            t.resume(),
            ResumePins { enregistres: 2, octets: 5, detenus: 1 },
            "et les chiffres eux-mêmes doivent être justes"
        );
    }

    /// Un tracker qui recharge un fichier existant doit démarrer avec le bon
    /// résumé — pas avec des zéros qui se corrigeraient à la première écriture.
    #[test]
    fn le_resume_est_juste_des_le_chargement() {
        let pins: HashMap<String, PinRecord> = [
            ("x".to_string(), rec("x", 100)),
            ("y".to_string(), rec("y", 0)),
        ]
        .into_iter()
        .collect();
        assert_eq!(
            calculer_resume(&pins),
            ResumePins { enregistres: 2, octets: 100, detenus: 1 }
        );
        assert_eq!(calculer_resume(&HashMap::new()), ResumePins::default());
    }

    /// LE relevé du 17/08/2026 : dix enregistrements, zéro octet détenu.
    ///
    /// `totals()` en comptait dix et l'interface écrivait « 10 contenus
    /// gardés ». Le nœud n'en détenait aucun.
    #[test]
    fn held_count_ne_compte_pas_les_demandes_vides() {
        let t = tracker_jetable("vides");
        for i in 0..10 {
            t.upsert(rec(&format!("bafkrei{i}"), 0));
        }
        assert_eq!(t.totals().0, 10, "dix demandes enregistrées");
        assert_eq!(t.totals().1, 0,  "et pas un octet");
        assert_eq!(t.held_count(), 0, "donc AUCUN contenu détenu");
    }

    #[test]
    fn held_count_compte_ceux_qui_ont_des_octets() {
        let t = tracker_jetable("melange");
        t.upsert(rec("plein-a", 4096));
        t.upsert(rec("vide-b", 0));
        t.upsert(rec("plein-c", 12));
        assert_eq!(t.totals().0, 3);
        assert_eq!(t.held_count(), 2, "seuls ceux qui portent des octets comptent");
    }

    #[test]
    fn held_count_est_zero_sur_un_noeud_neuf() {
        assert_eq!(tracker_jetable("neuf").held_count(), 0);
    }

    /// Un pin réenregistré avec ses octets passe de « demandé » à « détenu ».
    /// C'est la reprise attendue quand kubo finit par récupérer le contenu.
    #[test]
    fn un_pin_qui_recoit_ses_octets_devient_detenu() {
        let t = tracker_jetable("reprise");
        t.upsert(rec("bafkrei-x", 0));
        assert_eq!(t.held_count(), 0);
        t.upsert(rec("bafkrei-x", 2048));
        assert_eq!(t.totals().0, 1, "toujours un seul enregistrement");
        assert_eq!(t.held_count(), 1);
    }
}
