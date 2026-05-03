//! # Bandwidth tracking — Phase E.1
//!
//! Surveille la bande passante uploadée (octets servis aux pairs IPFS)
//! sur la journée en cours, avec un cap configurable purement
//! informatif pour le MVP.
//!
//! ## Pourquoi pas d'enforcement réel ?
//!
//! kubo n'expose pas d'API simple « refuse les nouveaux blocs servis
//! au-delà de X o ». Pour vraiment limiter, il faudrait :
//!   - shaper au niveau OS (tc/netfilter linux, pf macos, …)
//!   - OU déconnecter les pairs au-delà d'un seuil (hostile)
//!   - OU configurer `Swarm.ResourceMgr` avec des limits dynamiques
//!
//! C'est complexe. Pour E.1 on se contente de **tracker** et
//! **afficher**. L'enforcement viendra en E.2 (probablement par
//! pause auto du nœud quand cap atteint, comportement réversible
//! au prochain reset journalier).
//!
//! ## Reset
//!
//! Reset à minuit local — détection lazy au moment du `sample()`.
//! Si le user laisse le binaire tourner H24 et tape minuit, le compteur
//! repart à 0 sur le prochain sample.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;

#[derive(Default)]
pub struct BandwidthTracker {
    /// Octets servis au début de la journée courante (baseline kubo).
    /// Premier sample = baseline = total kubo, used = 0.
    baseline_bytes:  AtomicU64,
    /// Compteur dérivé : octets servis depuis la baseline (= aujourd'hui).
    used_today:      AtomicU64,
    /// Jour courant (jours depuis epoch). Sert à détecter le rollover.
    current_day:     AtomicU64,
    /// Cap journalier configuré (0 = illimité).
    cap_bytes:       AtomicU64,
}

impl BandwidthTracker {
    pub fn new(cap_bytes: u64) -> Arc<Self> {
        Arc::new(Self {
            cap_bytes: AtomicU64::new(cap_bytes),
            ..Default::default()
        })
    }

    pub fn cap(&self) -> u64 { self.cap_bytes.load(Ordering::Relaxed) }
    pub fn used(&self) -> u64 { self.used_today.load(Ordering::Relaxed) }

    /// À appeler à chaque cycle de polling kubo avec le total cumulé.
    /// Détecte le passage à un nouveau jour et reset la baseline.
    pub fn sample(&self, kubo_total_bytes: u64) {
        let day = current_day();
        let prev_day = self.current_day.swap(day, Ordering::Relaxed);

        if prev_day != day {
            // Nouveau jour OU premier sample → baseline = total actuel
            self.baseline_bytes.store(kubo_total_bytes, Ordering::Relaxed);
            self.used_today.store(0, Ordering::Relaxed);
            if prev_day != 0 {
                info!("bandwidth: nouvelle journée, reset compteur");
            }
            return;
        }

        // Même jour → used = total - baseline (saturating si kubo a redémarré)
        let baseline = self.baseline_bytes.load(Ordering::Relaxed);
        let used     = kubo_total_bytes.saturating_sub(baseline);
        self.used_today.store(used, Ordering::Relaxed);
    }

    /// True si le cap est défini ET dépassé. Purement informatif en E.1.
    pub fn is_over_cap(&self) -> bool {
        let cap = self.cap_bytes.load(Ordering::Relaxed);
        cap > 0 && self.used_today.load(Ordering::Relaxed) >= cap
    }
}

/// Numéro de jour absolu (jours depuis epoch UTC, sans tz). Suffisant
/// pour détecter un rollover ; pas besoin de précision tz pour ça.
fn current_day() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() / 86_400)
        .unwrap_or(0)
}
