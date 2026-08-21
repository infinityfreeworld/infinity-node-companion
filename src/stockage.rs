//! # Ce que le nœud pèse RÉELLEMENT sur la machine
//!
//! Le tableau de bord montrait ce que le nœud fait, jamais ce qu'il coûte.
//! Or la question posée par le Bâtisseur — « est-ce que ça alourdit la
//! machine ? » — n'avait de réponse qu'en ligne de commande, et la réponse
//! était instructive : un dépôt IPFS de **336 Ko** pour un daemon kubo de
//! 80 Mo de mémoire vive, à côté de **254 Mo** d'archives de tuiles.
//!
//! On publie donc les tailles, mesurées et non estimées.
//!
//! ## Deux précautions
//!
//! - **Cache** de 5 minutes : parcourir un dépôt IPFS de plusieurs gigaoctets
//!   à chaque rafraîchissement de page coûterait plus cher que tout le reste
//!   du nœud réuni.
//! - **Plafond de fichiers** : au-delà, on s'arrête et on le DIT
//!   (`tronque: true`). Un total silencieusement faux vaut moins que pas de
//!   total du tout.

use axum::response::{IntoResponse, Json};
use std::{
    path::Path,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

/// Durée de validité d'une mesure.
const TTL: Duration = Duration::from_secs(300);

/// Au-delà, on cesse de compter et on l'annonce.
const PLAFOND_FICHIERS: u64 = 200_000;

/// Résultat d'un parcours : octets, fichiers vus, et si on s'est arrêté avant
/// la fin.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Mesure {
    pub octets:   u64,
    pub fichiers: u64,
    pub tronque:  bool,
}

/// Taille d'un dossier, bornée. Les erreurs de lecture sont ignorées — un
/// dossier illisible pèse ce qu'on peut en lire, jamais une panne.
#[must_use]
pub fn taille_dossier(racine: &Path, plafond: u64) -> Mesure {
    let mut m = Mesure::default();
    let mut piles = vec![racine.to_path_buf()];
    while let Some(dossier) = piles.pop() {
        let Ok(entrees) = std::fs::read_dir(&dossier) else { continue };
        for entree in entrees.flatten() {
            if m.fichiers >= plafond {
                m.tronque = true;
                return m;
            }
            let Ok(t) = entree.file_type() else { continue };
            if t.is_dir() {
                piles.push(entree.path());
            } else if t.is_file() {
                if let Ok(meta) = entree.metadata() {
                    m.octets += meta.len();
                    m.fichiers += 1;
                }
            }
            // Les liens symboliques sont ignorés : les suivre ferait compter
            // deux fois, ou tourner en rond.
        }
    }
    m
}

/// `true` s'il faut refaire la mesure. Pure pour être éprouvable sans
/// attendre cinq minutes.
#[must_use]
pub fn doit_recalculer(derniere: Option<Duration>, ttl: Duration) -> bool {
    match derniere {
        None => true,
        Some(age) => age >= ttl,
    }
}

fn cache() -> &'static Mutex<Option<(Instant, serde_json::Value)>> {
    static C: OnceLock<Mutex<Option<(Instant, serde_json::Value)>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(None))
}

fn mesurer() -> serde_json::Value {
    let base = crate::chemins::dossier_donnees();
    let parts = [
        ("ipfs",        base.join("ipfs")),
        ("tuiles",      base.join("tiles")),
        ("relais",      base.join("relay")),
        ("sauvegardes", base.join("sauvegarde-binaire")),
    ];

    let mut total = 0u64;
    let mut tronque = false;
    let mut detail = serde_json::Map::new();
    for (nom, chemin) in parts {
        let m = taille_dossier(&chemin, PLAFOND_FICHIERS);
        total += m.octets;
        tronque |= m.tronque;
        detail.insert(
            nom.to_string(),
            serde_json::json!({ "octets": m.octets, "fichiers": m.fichiers, "tronque": m.tronque }),
        );
    }

    serde_json::json!({
        "dossier": base.to_string_lossy(),
        "detail":  detail,
        "total":   total,
        "tronque": tronque,
    })
}

pub async fn handler() -> impl IntoResponse {
    let frais = {
        let garde = cache().lock().ok();
        garde.and_then(|g| g.as_ref().map(|(t, v)| (t.elapsed(), v.clone())))
    };
    if let Some((age, valeur)) = frais {
        if !doit_recalculer(Some(age), TTL) {
            return Json(valeur);
        }
    }

    // Un parcours de disque n'a rien à faire sur un fil asynchrone : il
    // bloquerait les autres requêtes du nœud pendant tout le comptage.
    let valeur = tokio::task::spawn_blocking(mesurer)
        .await
        .unwrap_or_else(|_| serde_json::json!({ "erreur": "mesure interrompue" }));

    if let Ok(mut g) = cache().lock() {
        *g = Some((Instant::now(), valeur.clone()));
    }
    Json(valeur)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn fichier(chemin: &Path, octets: usize) {
        std::fs::create_dir_all(chemin.parent().unwrap()).unwrap();
        let mut f = std::fs::File::create(chemin).unwrap();
        f.write_all(&vec![b'x'; octets]).unwrap();
    }

    #[test]
    fn additionne_les_sous_dossiers() {
        let d = tempfile::tempdir().unwrap();
        fichier(&d.path().join("a.bin"), 1000);
        fichier(&d.path().join("sous/b.bin"), 2000);
        fichier(&d.path().join("sous/encore/c.bin"), 3);
        let m = taille_dossier(d.path(), PLAFOND_FICHIERS);
        assert_eq!(m.octets, 3003);
        assert_eq!(m.fichiers, 3);
        assert!(!m.tronque);
    }

    #[test]
    fn un_dossier_absent_pese_zero_et_ne_panique_pas() {
        let m = taille_dossier(Path::new("/dossier/qui/nexiste/pas"), PLAFOND_FICHIERS);
        assert_eq!(m, Mesure::default());
    }

    /// Le point qui compte : un total tronqué doit se DIRE tronqué, sinon la
    /// page affiche un chiffre faux avec l'aplomb d'un chiffre juste.
    #[test]
    fn au_dela_du_plafond_le_total_savoue_incomplet() {
        let d = tempfile::tempdir().unwrap();
        for i in 0..5 {
            fichier(&d.path().join(format!("f{i}.bin")), 10);
        }
        let m = taille_dossier(d.path(), 3);
        assert!(m.tronque, "le parcours borné doit s'annoncer incomplet");
        assert!(m.fichiers <= 3);
        assert!(m.octets < 50, "il ne peut pas avoir tout compté : {}", m.octets);
    }

    /// Le handler complet, sans `AppState` : ce que le navigateur reçoit
    /// vraiment. Il mesure le dossier RÉEL du nœud — on ne vérifie donc pas
    /// des chiffres, mais la forme, qui est ce que la page consomme.
    #[tokio::test]
    async fn le_handler_publie_les_quatre_postes_et_un_total() {
        use axum::response::IntoResponse;
        let corps = axum::body::to_bytes(handler().await.into_response().into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&corps).unwrap();
        for poste in ["ipfs", "tuiles", "relais", "sauvegardes"] {
            assert!(
                v["detail"][poste]["octets"].is_u64(),
                "poste « {poste} » absent ou mal formé : {v}"
            );
        }
        assert!(v["total"].is_u64(), "pas de total : {v}");
        assert!(v["tronque"].is_boolean(), "l'aveu d'incomplétude doit toujours être là : {v}");
        assert!(v["dossier"].is_string());
    }

    #[test]
    fn la_mesure_nest_refaite_quapres_expiration() {
        assert!(doit_recalculer(None, TTL), "aucune mesure : il faut la faire");
        assert!(!doit_recalculer(Some(Duration::from_secs(1)), TTL));
        assert!(doit_recalculer(Some(TTL), TTL), "à l'échéance exacte, on refait");
        assert!(doit_recalculer(Some(Duration::from_secs(3600)), TTL));
    }
}
