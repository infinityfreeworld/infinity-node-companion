//! # Amorçage et journal — ce que le nœud fait AVANT d'être joignable
//!
//! Le tableau de bord (`src/ui.rs`) est servi par le serveur HTTP, qui ne
//! démarrait qu'une fois la pile sécurité initialisée. Or c'est précisément
//! là que le nœud se fige : un binaire fraîchement bâti a une signature
//! nouvelle aux yeux de macOS, qui affiche une demande d'autorisation du
//! trousseau et **attend un clic humain**, indéfiniment. Symptôme vu deux
//! fois : une seule ligne de log, puis plus rien, et rien à interroger —
//! l'instrument de diagnostic était derrière la panne qu'il devait
//! expliquer.
//!
//! Ce module porte donc :
//!   - l'**étape d'amorçage** courante, publiée dès la première seconde ;
//!   - un **journal en mémoire** (les dernières lignes de `tracing`), pour
//!     que « le nœud ne répond pas » se lise sans `sample <pid>` ;
//!   - un **serveur d'amorçage** qui sert la page et ces deux endpoints
//!     AVANT l'init sécurité, puis rend la main au serveur définitif.

use axum::{response::{IntoResponse, Json}, routing::get, Router};
use std::{
    collections::VecDeque,
    io::Write,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU8, Ordering},
        Mutex, OnceLock,
    },
    time::Instant,
};
use tracing::{info, warn};

/// Nombre de lignes gardées. Assez pour couvrir un démarrage complet ;
/// assez peu pour qu'un nœud qui tourne des semaines ne gonfle pas.
const LIGNES_GARDEES: usize = 400;

// ── Étape d'amorçage ─────────────────────────────────────────────────────

/// Les étapes, dans l'ordre. La valeur numérique est publiée telle quelle.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Etape {
    Demarrage     = 0,
    Securite      = 1,
    SousProcessus = 2,
    Pret          = 3,
}

impl Etape {
    fn depuis_u8(v: u8) -> Self {
        match v {
            1 => Self::Securite,
            2 => Self::SousProcessus,
            3 => Self::Pret,
            _ => Self::Demarrage,
        }
    }

    #[must_use]
    pub fn libelle(self) -> &'static str {
        match self {
            Self::Demarrage     => "démarrage",
            Self::Securite      => "ouverture du coffre et de l'identité",
            Self::SousProcessus => "démarrage d'IPFS et du relais",
            Self::Pret          => "prêt",
        }
    }

    /// Ce qu'il faut faire si l'étape s'éternise. C'est la raison d'être du
    /// module : une étape sans explication ne vaut pas mieux qu'un silence.
    #[must_use]
    pub fn explication(self, secondes: u64) -> Option<&'static str> {
        match self {
            Self::Securite if secondes >= 10 => Some(
                "macOS attend probablement une autorisation du trousseau. \
                 Cherche la fenêtre « … veut utiliser le trousseau » et clique \
                 « Toujours autoriser » : tout binaire reconstruit la redemande.",
            ),
            Self::SousProcessus if secondes >= 30 => Some(
                "kubo ou nostr-rs-relay met un temps inhabituel à répondre. \
                 Vérifie qu'un exemplaire du run précédent ne tient pas déjà le port.",
            ),
            _ => None,
        }
    }
}

static ETAPE: AtomicU8 = AtomicU8::new(0);

fn depuis() -> &'static Mutex<Instant> {
    static D: OnceLock<Mutex<Instant>> = OnceLock::new();
    D.get_or_init(|| Mutex::new(Instant::now()))
}

/// Déclare l'étape courante. Repart le chronomètre.
pub fn etape(e: Etape) {
    ETAPE.store(e as u8, Ordering::Relaxed);
    if let Ok(mut d) = depuis().lock() {
        *d = Instant::now();
    }
    info!(target: "amorcage", "étape : {}", e.libelle());
}

#[must_use]
pub fn etape_courante() -> Etape {
    Etape::depuis_u8(ETAPE.load(Ordering::Relaxed))
}

#[must_use]
pub fn secondes_dans_letape() -> u64 {
    depuis()
        .lock()
        .map(|d| d.elapsed().as_secs())
        .unwrap_or(0)
}

fn etat_json() -> serde_json::Value {
    let e = etape_courante();
    let s = secondes_dans_letape();
    serde_json::json!({
        "etape":       e as u8,
        "libelle":     e.libelle(),
        "depuisSecs":  s,
        "explication": e.explication(s),
        "pret":        e == Etape::Pret,
    })
}

pub async fn handler_amorcage() -> impl IntoResponse {
    Json(etat_json())
}

// ── Journal en mémoire ───────────────────────────────────────────────────

fn tampon() -> &'static Mutex<VecDeque<String>> {
    static T: OnceLock<Mutex<VecDeque<String>>> = OnceLock::new();
    T.get_or_init(|| Mutex::new(VecDeque::with_capacity(LIGNES_GARDEES)))
}

/// Ce qu'on garde d'une ligne brute — `None` si elle n'apporte rien.
/// Séparé du tampon pour être éprouvable sans dépendre d'un état global que
/// les autres tests remplissent en parallèle.
#[must_use]
pub fn ligne_retenue(ligne: &str) -> Option<String> {
    let l = sans_ansi(ligne.trim_end());
    if l.trim().is_empty() {
        None
    } else {
        Some(l)
    }
}

/// Ajoute une ligne au journal, en jetant la plus ancienne au-delà du cap.
pub fn pousser_ligne(ligne: &str) {
    let Some(ligne) = ligne_retenue(ligne) else { return };
    if let Ok(mut t) = tampon().lock() {
        if t.len() == LIGNES_GARDEES {
            t.pop_front();
        }
        t.push_back(ligne);
    }
}

#[must_use]
pub fn dernieres_lignes(combien: usize) -> Vec<String> {
    tampon()
        .lock()
        .map(|t| t.iter().rev().take(combien).rev().cloned().collect())
        .unwrap_or_default()
}

pub async fn handler_journal() -> impl IntoResponse {
    Json(serde_json::json!({ "lignes": dernieres_lignes(200) }))
}

/// Retire les séquences ANSI. Sans ça, la console garde ses couleurs mais la
/// page affiche des `[2m[32m` au milieu de chaque ligne.
#[must_use]
pub fn sans_ansi(s: &str) -> String {
    let mut sortie = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            sortie.push(c);
            continue;
        }
        // ESC [ … <lettre finale>
        for suite in chars.by_ref() {
            if suite.is_ascii_alphabetic() {
                break;
            }
        }
    }
    sortie
}

/// Écrivain branché sur `tracing` : la console garde tout, le journal en
/// mémoire reçoit la même chose en clair.
#[derive(Clone, Copy, Default)]
pub struct EcrivainJournal;

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for EcrivainJournal {
    type Writer = LigneEnCours;
    fn make_writer(&'a self) -> Self::Writer {
        LigneEnCours::default()
    }
}

/// Accumule un événement, l'écrit sur la sortie standard, et le dépose dans
/// le journal à sa destruction (tracing crée un écrivain par événement).
#[derive(Default)]
pub struct LigneEnCours {
    tampon: Vec<u8>,
}

impl Write for LigneEnCours {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.tampon.extend_from_slice(buf);
        let _ = std::io::stdout().write_all(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        std::io::stdout().flush()
    }
}

impl Drop for LigneEnCours {
    fn drop(&mut self) {
        if let Ok(s) = std::str::from_utf8(&self.tampon) {
            for ligne in s.lines() {
                pousser_ligne(ligne);
            }
        }
    }
}

// ── Serveur d'amorçage ───────────────────────────────────────────────────

/// Sert le tableau de bord et l'état d'amorçage AVANT que la pile sécurité
/// soit prête, puis s'arrête proprement quand `arret` est déclenché — pour
/// rendre le port au serveur définitif.
///
/// ⚠️ Un échec de bind ici n'est PAS fatal : le nœud doit démarrer même si
/// le port est pris (le serveur définitif dira lui-même ce qu'il en est).
pub async fn servir(addr: SocketAddr, arret: tokio::sync::oneshot::Receiver<()>) {
    let app = Router::new()
        .route("/",             get(crate::ui::page))
        .route("/ui",           get(crate::ui::page))
        .route("/healthz",      get(|| async { "amorçage" }))
        .route("/api/amorcage", get(handler_amorcage))
        .route("/api/journal",  get(handler_journal));

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            warn!(target: "amorcage", "serveur d'amorçage non lancé : {e}");
            return;
        }
    };
    info!(target: "amorcage", "tableau de bord disponible pendant l'amorçage sur http://{addr}/ui");

    let _ = axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = arret.await;
        })
        .await;
    info!(target: "amorcage", "serveur d'amorçage arrêté — passage au serveur définitif");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn les_couleurs_de_la_console_ne_polluent_pas_le_journal() {
        let brut = "\u{1b}[2m2026-08-20T04:03:37\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m security data dir ready";
        assert_eq!(sans_ansi(brut), "2026-08-20T04:03:37  INFO security data dir ready");
        assert_eq!(sans_ansi("rien à retirer"), "rien à retirer");
    }

    #[test]
    fn le_journal_garde_les_dernieres_lignes_dans_lordre() {
        for i in 0..(LIGNES_GARDEES + 50) {
            pousser_ligne(&format!("ligne {i}"));
        }
        let l = dernieres_lignes(5);
        assert_eq!(l.len(), 5);
        assert_eq!(l[4], format!("ligne {}", LIGNES_GARDEES + 49));
        assert_eq!(l[0], format!("ligne {}", LIGNES_GARDEES + 45));
        // Le cap tient : la plus ancienne a bien été jetée.
        assert_eq!(dernieres_lignes(10_000).len(), LIGNES_GARDEES);
    }

    #[test]
    fn une_ligne_vide_nentre_pas_dans_le_journal() {
        assert_eq!(ligne_retenue("   "), None);
        assert_eq!(ligne_retenue(""), None);
        assert_eq!(ligne_retenue("\u{1b}[0m"), None, "une ligne de pure couleur ne dit rien");
        assert_eq!(ligne_retenue("  INFO relais prêt  "), Some("  INFO relais prêt".to_string()));
    }

    /// Le cœur du module : l'étape qui traîne doit DIRE quoi faire.
    #[test]
    fn letape_securite_qui_traine_explique_le_trousseau() {
        assert!(Etape::Securite.explication(2).is_none(), "pas d'alarme immédiate");
        let e = Etape::Securite.explication(11).expect("une explication après 10 s");
        assert!(e.contains("trousseau"), "l'explication doit nommer le trousseau : {e}");
        assert!(e.contains("Toujours autoriser"), "elle doit donner le geste exact : {e}");
        assert!(Etape::Pret.explication(10_000).is_none(), "un nœud prêt n'a rien à expliquer");
    }
}
