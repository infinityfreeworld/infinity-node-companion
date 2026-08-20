//! # Process supervisor
//!
//! Wrapper minimal autour de [`std::process::Child`] qui :
//!   - **kill au Drop** — quand l'objet sort de scope (Quit tray, panic,
//!     etc.) le child reçoit SIGKILL. Pas d'orphan kubo qui bouffe la
//!     bande passante après la fermeture du companion.
//!   - **ramassage des orphelins au démarrage** — parce que le Drop ne
//!     suffit pas : `killall`, un `quit` AppleScript, une fermeture de
//!     session ou un crash font sortir le processus SANS dérouler la pile,
//!     donc sans Drop. Constaté le 20/08/2026 : après un « Quitter », le
//!     `nostr-rs-relay` tournait toujours, et le nœud relancé aurait trouvé
//!     son port 7777 occupé par son propre fantôme. Chaque enfant écrit donc
//!     son PID dans `<état>/enfants/<nom>.pid` ; au spawn suivant on tue ce
//!     qui reste, après avoir VÉRIFIÉ que le PID est bien celui du binaire
//!     attendu — un PID est recyclé par le système, et tuer à l'aveugle
//!     reviendrait à abattre le processus d'un tiers.
//!   - **redirige stdout/stderr** vers nos logs `tracing` (préfixés du
//!     nom du backend).
//!   - **exposé thread-safe** via `Arc<Mutex<…>>` côté caller.
//!
//! On reste sur l'API `std::process` (pas tokio::process) parce que les
//! children sont long-running et qu'on n'a aucune raison d'attendre
//! leur sortie de manière async.

use std::{
    ffi::OsStr,
    io::{BufRead, BufReader},
    path::PathBuf,
    process::{Child, Command, Stdio},
};
use tracing::{info, warn};

/// Représente un sous-processus géré. Tué au Drop.
pub struct ManagedChild {
    name:  String,
    child: Child,
}

impl ManagedChild {
    /// Spawn une commande, monte stdout+stderr dans nos logs.
    /// Renvoie `None` si le spawn échoue (binaire introuvable, etc.).
    pub fn spawn(name: &str, mut cmd: Command) -> Option<Self> {
        // Un fantôme du run précédent tient peut-être encore le port.
        let programme = cmd.get_program().to_owned();
        ramasser_orphelin(name, &programme);

        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                warn!(target: "supervisor", "spawn '{name}' failed: {e}");
                return None;
            }
        };

        // Pump stdout
        if let Some(stdout) = child.stdout.take() {
            let n = name.to_owned();
            std::thread::Builder::new()
                .name(format!("{name}-stdout"))
                .spawn(move || {
                    for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                        info!(target: "child", "[{n}] {line}");
                    }
                })
                .ok();
        }
        // Pump stderr (en INFO, pas WARN — kubo écrit beaucoup en stderr
        // par design même quand tout va bien)
        if let Some(stderr) = child.stderr.take() {
            let n = name.to_owned();
            std::thread::Builder::new()
                .name(format!("{name}-stderr"))
                .spawn(move || {
                    for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                        info!(target: "child", "[{n} err] {line}");
                    }
                })
                .ok();
        }

        info!(target: "supervisor", "spawned '{name}' (pid {})", child.id());
        ecrire_pid(name, child.id());
        Some(Self { name: name.to_owned(), child })
    }

}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        // Best-effort kill — on ignore les erreurs (déjà mort = OK)
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(fichier_pid(&self.name));
        info!(target: "supervisor", "killed '{}'", self.name);
    }
}

// ── Orphelins ────────────────────────────────────────────────────────────

fn dossier_pids() -> PathBuf {
    crate::chemins::sous_dossier("enfants")
}

fn fichier_pid(nom: &str) -> PathBuf {
    dossier_pids().join(format!("{nom}.pid"))
}

fn ecrire_pid(nom: &str, pid: u32) {
    let dossier = dossier_pids();
    if let Err(e) = std::fs::create_dir_all(&dossier) {
        warn!(target: "supervisor", "dossier des pids indisponible : {e}");
        return;
    }
    if let Err(e) = std::fs::write(fichier_pid(nom), pid.to_string()) {
        warn!(target: "supervisor", "pid de '{nom}' non écrit : {e}");
    }
}

/// Décide s'il faut tuer le PID retrouvé — à partir de la ligne de commande
/// que le système en donne. Pure, donc éprouvable sans tuer personne.
///
/// ⚠️ Le point qui compte : un PID est RECYCLÉ. Sans cette vérification, le
/// nœud abattrait le processus qui a hérité du numéro — potentiellement
/// celui d'un tiers, choisi par le hasard de l'ordonnanceur.
#[must_use]
pub fn doit_tuer(ligne_de_commande: Option<&str>, programme_attendu: &str) -> bool {
    let Some(ligne) = ligne_de_commande else { return false };
    let ligne = ligne.trim();
    if ligne.is_empty() || programme_attendu.is_empty() {
        return false;
    }
    // On compare sur le NOM du binaire, pas sur le chemin : le fantôme a pu
    // être lancé depuis un autre chemin (installeur, PATH différent).
    let attendu = std::path::Path::new(programme_attendu)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| programme_attendu.to_string());
    ligne.split_whitespace().next().is_some_and(|premier| {
        std::path::Path::new(premier)
            .file_name()
            .is_some_and(|n| n.to_string_lossy() == attendu)
    })
}

/// Lit la ligne de commande d'un PID vivant. `None` si le processus n'existe
/// plus (ou si `ps` n'est pas disponible).
fn ligne_de_commande(pid: u32) -> Option<String> {
    let out = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "command="])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Tue le reliquat du run précédent, s'il tourne encore ET s'il s'agit bien
/// du binaire attendu.
fn ramasser_orphelin(nom: &str, programme: &OsStr) {
    let fichier = fichier_pid(nom);
    let Ok(contenu) = std::fs::read_to_string(&fichier) else { return };
    let Ok(pid) = contenu.trim().parse::<u32>() else {
        let _ = std::fs::remove_file(&fichier);
        return;
    };

    let ligne = ligne_de_commande(pid);
    if !doit_tuer(ligne.as_deref(), &programme.to_string_lossy()) {
        // Mort, ou PID recyclé par quelqu'un d'autre : on ne touche à rien.
        let _ = std::fs::remove_file(&fichier);
        return;
    }

    warn!(target: "supervisor", "'{nom}' du run précédent tourne encore (pid {pid}) — arrêt");
    let _ = Command::new("kill").arg(pid.to_string()).status();

    // Laisser le temps de fermer sa base proprement, puis insister.
    for _ in 0..20 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        if ligne_de_commande(pid).is_none() {
            info!(target: "supervisor", "orphelin '{nom}' (pid {pid}) arrêté");
            let _ = std::fs::remove_file(&fichier);
            return;
        }
    }
    warn!(target: "supervisor", "orphelin '{nom}' (pid {pid}) résiste — SIGKILL");
    let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
    let _ = std::fs::remove_file(&fichier);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn un_pid_disparu_ne_se_tue_pas() {
        assert!(!doit_tuer(None, "/usr/local/bin/kubo"));
        assert!(!doit_tuer(Some(""), "/usr/local/bin/kubo"));
        assert!(!doit_tuer(Some("   "), "/usr/local/bin/kubo"));
    }

    #[test]
    fn un_pid_recycle_par_un_tiers_ne_se_tue_pas() {
        // Le cas qui justifie tout ce code : le numéro est le bon, le
        // processus n'est pas le nôtre.
        assert!(!doit_tuer(Some("/usr/bin/ssh med@serveur"), "/usr/local/bin/kubo"));
        assert!(!doit_tuer(Some("/Applications/Safari.app/Contents/MacOS/Safari"), "kubo"));
        // Un nom qui contient le nôtre n'est pas le nôtre.
        assert!(!doit_tuer(Some("/usr/bin/kubot --daemon"), "kubo"));
    }

    #[test]
    fn le_fantome_du_run_precedent_se_tue() {
        assert!(doit_tuer(Some("/usr/local/bin/kubo daemon --routing=dhtclient"), "/usr/local/bin/kubo"));
        // Relancé depuis un autre chemin : c'est le même binaire.
        assert!(doit_tuer(
            Some("/Users/med/.cargo/bin/nostr-rs-relay --config /x/config.toml"),
            "/opt/homebrew/bin/nostr-rs-relay"
        ));
    }

    #[test]
    fn le_fichier_de_pid_vit_dans_letat_du_noeud() {
        // Il doit suivre INFINITY_DATA_DIR, sinon une instance isolée
        // ramasserait les enfants du nœud de production.
        let f = fichier_pid("kubo");
        assert!(f.ends_with("enfants/kubo.pid"), "chemin inattendu : {f:?}");
        assert!(f.starts_with(crate::chemins::dossier_donnees()));
    }
}
