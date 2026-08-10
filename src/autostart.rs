//! # Auto-launch au boot — Phase D.2
//!
//! Wrapper minimal autour du crate `auto-launch` pour piloter le
//! démarrage automatique d'Infinity Node à l'ouverture de session.
//!
//! ## Mécanismes par plateforme
//!
//! | Plateforme | Mécanisme                                                   |
//! |------------|-------------------------------------------------------------|
//! | macOS      | Élément d'ouverture de session (AppleScript) — voir ci-dessous |
//! | Linux      | `~/.config/autostart/InfinityNode.desktop` (XDG Autostart)  |
//! | Windows    | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`        |
//!
//! ## ⚠️ Sur macOS, ce n'est PAS un LaunchAgent — constaté le 10/08/2026
//!
//! Le crate `auto-launch` n'écrit un `~/Library/LaunchAgents/*.plist` que si on
//! lui demande `set_use_launch_agent(true)`. Sans cet appel — c'est notre cas —
//! il passe par AppleScript et inscrit un **élément d'ouverture de session**,
//! visible dans Réglages Système → Général → Ouverture.
//!
//! Le README et ce fichier annonçaient le plist. C'est faux, et ça coûte cher :
//! on cherche un fichier qui n'existera jamais, on en conclut que l'activation
//! a échoué, alors qu'elle a parfaitement fonctionné.
//!
//! **Conséquence réelle, pas seulement documentaire** : un élément d'ouverture
//! de session lance l'application AU LOGIN, et rien de plus. Il n'a pas de
//! `KeepAlive` — le plist du crate n'en pose pas davantage. Un nœud qui TOMBE
//! reste donc tombé jusqu'à la prochaine session. Seul
//! `scripts/noeud-demarrage-auto.sh` (dépôt PWA) pose un vrai LaunchAgent avec
//! `KeepAlive`. Ne pas confondre « démarre tout seul » et « se relève tout
//! seul » : nous n'avons que le premier.
//!
//! Tous ces mécanismes sont **per-user** (pas besoin de droits admin)
//! et s'activent à l'ouverture de session de l'utilisateur — pas au
//! boot système, ce qui est exactement ce qu'on veut pour un companion
//! qui n'a aucune raison de tourner avant que l'utilisateur soit logué.
//!
//! ## Chemin d'exécutable
//!
//! On utilise [`std::env::current_exe`] qui renvoie le binaire en cours.
//! En `cargo run`, c'est `target/debug/infinity-node`. Pour un build
//! distribué, ce sera le chemin du binaire installé. Sur macOS, idéal
//! serait le path du `.app` bundle — non géré ici (D.3 packaging).
//!
//! ## Persistance
//!
//! La préférence est persistée par l'OS lui-même (plist / desktop /
//! registre). On n'a aucun fichier de config à gérer côté Infinity Node.

use auto_launch::{AutoLaunch, AutoLaunchBuilder};

const APP_NAME: &str = "Infinity Node";

/// Construit un handle [`AutoLaunch`] pointant sur le binaire en cours.
/// Renvoie `None` si on ne peut pas résoudre `current_exe` (cas extrême).
pub fn handle() -> Option<AutoLaunch> {
    let exe = std::env::current_exe().ok()?;
    let path_str = exe.to_string_lossy().into_owned();
    AutoLaunchBuilder::new()
        .set_app_name(APP_NAME)
        .set_app_path(&path_str)
        // Pas d'args : on relance le binaire identique à comment
        // l'utilisateur l'a lancé la première fois.
        .set_args(&Vec::<&str>::new())
        .build()
        .ok()
}

/// État courant — `false` si introuvable ou erreur (fail-safe).
pub fn is_enabled(auto: &AutoLaunch) -> bool {
    auto.is_enabled().unwrap_or(false)
}

/// Active. Renvoie `Ok` si la modif a été enregistrée, `Err` sinon
/// (par ex. quota plist macOS ou permission registre Windows).
pub fn enable(auto: &AutoLaunch) -> Result<(), String> {
    auto.enable().map_err(|e| e.to_string())
}

/// Désactive idempotent — pas d'erreur si déjà off.
pub fn disable(auto: &AutoLaunch) -> Result<(), String> {
    auto.disable().map_err(|e| e.to_string())
}

// ── Défaut appliqué UNE SEULE FOIS — Phase D.2b ─────────────────────────────
//
// ## Le défaut que ceci corrige
//
// Bâtisseur, 08/08/2026, devant l'alerte « Carte hors-ligne indisponible » :
// « le nœud devrait se rendre opérationnel automatiquement, non ? »
//
// Il devrait, et il le POUVAIT déjà : tout le mécanisme ci-dessus existe et
// fonctionne sur les trois systèmes. Mais il est branché sur une CASE À COCHER
// du menu de la barre système, décochée au premier lancement. Il faut donc
// savoir qu'elle existe, et aller la chercher. Personne ne le fera — et une
// capacité que personne n'active n'existe pas.
//
// L'application coche donc elle-même, une fois, au premier démarrage.
//
// ## ⚠️ « Une fois » est le mot important
//
// Réactiver à chaque lancement effacerait un refus délibéré : quelqu'un qui
// décoche verrait sa décision annulée au démarrage suivant, sans explication.
// Un marqueur retient donc qu'on a déjà appliqué le défaut, et l'on ne
// repasse JAMAIS derrière un choix humain.
//
// ## ⚠️ Et pas depuis un build de développement
//
// `current_exe` rend `target/debug/infinity-node` sous `cargo run`. Enregistrer
// ce chemin-là poserait un démarrage automatique vers un binaire qui sera
// effacé au prochain `cargo clean`, ou déplacé avec le dossier de travail — le
// système relancerait alors dans le vide à chaque session, en silence. La même
// leçon a déjà été payée côté PWA : ne jamais pointer un service vers un
// répertoire de travail.

use std::path::{Path, PathBuf};

/// Marqueur : le défaut a déjà été appliqué une fois sur cette machine.
fn marqueur() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".infinity-node")
        .join("autostart-defaut-applique")
}

/// Un binaire lancé depuis l'arbre de compilation — chemin non pérenne.
///
/// Volontairement fondé sur `target/debug` ou `target/release`, les deux seuls
/// emplacements que Cargo produit : un binaire INSTALLÉ n'y vit jamais.
pub fn est_build_de_dev(exe: &Path) -> bool {
    let mut composants = exe.components().rev().skip(1); // on saute le nom du binaire
    matches!(composants.next().map(|c| c.as_os_str().to_string_lossy().into_owned()).as_deref(),
             Some("debug") | Some("release"))
        && composants.next().map(|c| c.as_os_str() == "target").unwrap_or(false)
}

/// Faut-il appliquer le défaut « démarre à l'ouverture de session » ?
///
/// PURE : aucune écriture, aucun accès système. C'est la règle seule, et c'est
/// elle qui mérite d'être éprouvée — le reste n'est que de l'écriture de
/// fichier.
pub fn doit_appliquer_defaut(marqueur_present: bool, deja_actif: bool, exe: &Path) -> bool {
    if marqueur_present { return false }   // un choix a déjà été fait — on n'y touche pas
    if deja_actif { return false }         // rien à faire, et le marqueur suffira
    !est_build_de_dev(exe)
}

/// Applique le défaut au premier démarrage. Idempotent, silencieux en cas
/// d'échec : un démarrage automatique qu'on ne peut pas poser ne doit jamais
/// empêcher le nœud de tourner MAINTENANT.
///
/// Renvoie `true` si l'auto-démarrage vient d'être activé par cet appel.
pub fn appliquer_defaut_une_fois(auto: &AutoLaunch) -> bool {
    let exe = match std::env::current_exe() { Ok(p) => p, Err(_) => return false };
    appliquer_avec(&marqueur(), &exe, is_enabled(auto), || enable(auto).is_ok())
}

/// Le corps testable : le marqueur et l'activation sont INJECTÉS.
///
/// ⚠️ Extrait le 10/08/2026 parce qu'une mutation a SURVÉCU — « poser le
/// marqueur même sur échec » ne faisait rougir aucun test, alors que c'est
/// exactement le défaut qui condamnerait une machine à ne jamais réessayer.
/// Une règle qu'aucun test ne peut atteindre n'est pas protégée.
pub fn appliquer_avec(
    marqueur: &Path,
    exe: &Path,
    deja_actif: bool,
    activer: impl FnOnce() -> bool,
) -> bool {
    let poser_marqueur = || {
        let _ = std::fs::create_dir_all(marqueur.parent().unwrap_or(Path::new(".")));
        let _ = std::fs::write(marqueur, b"1");
    };
    if !doit_appliquer_defaut(marqueur.exists(), deja_actif, exe) {
        poser_marqueur();
        return false
    }
    /* ⚠️ LE MARQUEUR NE SE POSE QUE SI L'ACTIVATION A RÉUSSI — corrigé le
       10/08/2026, au premier essai RÉEL sur une vraie installation.
       La version précédente l'écrivait dans les deux cas. Un échec (quota,
       permission refusée, AppleScript indisponible) consommait donc l'unique
       tentative : l'auto-démarrage restait absent POUR TOUJOURS sur cette
       machine, sans trace et sans recours. On ne brûle la cartouche que
       lorsqu'elle a tiré ; un échec sera retenté au prochain démarrage. */
    if !activer() {
        return false
    }
    poser_marqueur();
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn un_binaire_installe_n_est_pas_un_build_de_dev() {
        assert!(!est_build_de_dev(&PathBuf::from("/Applications/Infinity Node.app/Contents/MacOS/infinity-node")));
        assert!(!est_build_de_dev(&PathBuf::from("/usr/local/bin/infinity-node")));
    }

    #[test]
    fn un_cargo_run_est_reconnu() {
        // ⚠️ Le cas qui poserait un démarrage automatique vers un chemin
        // effacé au prochain `cargo clean`.
        assert!(est_build_de_dev(&PathBuf::from("/Users/x/repo/target/debug/infinity-node")));
        assert!(est_build_de_dev(&PathBuf::from("/Users/x/repo/target/release/infinity-node")));
    }

    #[test]
    fn un_dossier_nomme_debug_ailleurs_ne_trompe_pas() {
        // « debug » sans « target » juste au-dessus n'est pas un build Cargo.
        assert!(!est_build_de_dev(&PathBuf::from("/opt/debug/infinity-node")));
    }

    #[test]
    fn on_applique_au_tout_premier_demarrage() {
        let installe = PathBuf::from("/usr/local/bin/infinity-node");
        assert!(doit_appliquer_defaut(false, false, &installe));
    }

    #[test]
    fn on_ne_repasse_jamais_derriere_un_choix_humain() {
        // ⚠️ LE test de ce lot. Quelqu'un qui décoche verrait sinon sa décision
        // annulée au démarrage suivant, sans explication.
        let installe = PathBuf::from("/usr/local/bin/infinity-node");
        assert!(!doit_appliquer_defaut(true, false, &installe));
    }

    #[test]
    fn on_n_active_pas_depuis_les_sources() {
        let dev = PathBuf::from("/Users/x/repo/target/debug/infinity-node");
        assert!(!doit_appliquer_defaut(false, false, &dev));
    }

    #[test]
    fn rien_a_faire_si_c_est_deja_actif() {
        let installe = PathBuf::from("/usr/local/bin/infinity-node");
        assert!(!doit_appliquer_defaut(false, true, &installe));
    }

    /// Un dossier de travail jetable, propre à chaque test.
    fn dossier_jetable(nom: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("infinity-autostart-{nom}"));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn un_echec_d_activation_ne_brule_pas_la_tentative() {
        // ⚠️ LE test de ce lot : une mutation « poser le marqueur même sur
        // échec » ne faisait rougir personne, alors qu'elle condamnerait la
        // machine à ne JAMAIS réessayer.
        let d = dossier_jetable("echec");
        let m = d.join("marqueur");
        let exe = PathBuf::from("/usr/local/bin/infinity-node");

        assert!(!appliquer_avec(&m, &exe, false, || false));
        assert!(!m.exists(), "le marqueur a été posé alors que rien n'a été activé");

        // Le démarrage suivant retente, et cette fois ça marche.
        assert!(appliquer_avec(&m, &exe, false, || true));
        assert!(m.exists());
    }

    #[test]
    fn une_activation_reussie_pose_le_marqueur_et_ne_se_repete_pas() {
        let d = dossier_jetable("succes");
        let m = d.join("marqueur");
        let exe = PathBuf::from("/usr/local/bin/infinity-node");

        assert!(appliquer_avec(&m, &exe, false, || true));
        // Deuxième démarrage : le marqueur existe, on ne repasse pas.
        let mut rappele = false;
        assert!(!appliquer_avec(&m, &exe, false, || { rappele = true; true }));
        assert!(!rappele, "on a retenté alors que la décision était prise");
    }

    #[test]
    fn depuis_les_sources_on_n_active_rien_mais_on_tranche() {
        let d = dossier_jetable("dev");
        let m = d.join("marqueur");
        let dev = PathBuf::from("/Users/x/repo/target/debug/infinity-node");
        let mut rappele = false;
        assert!(!appliquer_avec(&m, &dev, false, || { rappele = true; true }));
        assert!(!rappele, "on a inscrit un binaire de développement");
        // La décision est prise une fois pour toutes : pas de question à chaque run.
        assert!(m.exists());
    }
}
