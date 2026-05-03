//! # Process supervisor
//!
//! Wrapper minimal autour de [`std::process::Child`] qui :
//!   - **kill au Drop** — quand l'objet sort de scope (Quit tray, panic,
//!     etc.) le child reçoit SIGKILL. Pas d'orphan kubo qui bouffe la
//!     bande passante après la fermeture du companion.
//!   - **redirige stdout/stderr** vers nos logs `tracing` (préfixés du
//!     nom du backend).
//!   - **exposé thread-safe** via `Arc<Mutex<…>>` côté caller.
//!
//! On reste sur l'API `std::process` (pas tokio::process) parce que les
//! children sont long-running et qu'on n'a aucune raison d'attendre
//! leur sortie de manière async.

use std::{
    io::{BufRead, BufReader},
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
        Some(Self { name: name.to_owned(), child })
    }

}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        // Best-effort kill — on ignore les erreurs (déjà mort = OK)
        let _ = self.child.kill();
        let _ = self.child.wait();
        info!(target: "supervisor", "killed '{}'", self.name);
    }
}
