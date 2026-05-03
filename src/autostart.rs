//! # Auto-launch au boot — Phase D.2
//!
//! Wrapper minimal autour du crate `auto-launch` pour piloter le
//! démarrage automatique d'Infinity Node à l'ouverture de session.
//!
//! ## Mécanismes par plateforme
//!
//! | Plateforme | Mécanisme                                                   |
//! |------------|-------------------------------------------------------------|
//! | macOS      | `~/Library/LaunchAgents/com.infinity.node.plist` (LaunchAgent) |
//! | Linux      | `~/.config/autostart/InfinityNode.desktop` (XDG Autostart)  |
//! | Windows    | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`        |
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
