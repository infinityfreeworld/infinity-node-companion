//! # Où le nœud écrit son état — UN seul endroit
//!
//! Six modules calculaient chacun `~/.infinity-node` de leur côté. Aucun
//! n'était configurable, donc **toute** seconde instance — un binaire de
//! développement lancé sur un autre port pour essayer quelque chose —
//! écrivait dans les données du nœud de production.
//!
//! Ce n'est pas théorique : le 20/08/2026, une instance de mise au point
//! lancée sur le port 7475 a partagé `~/.infinity-node`. Son janitor y a
//! trouvé dix pins expirés et, faute de kubo sur son `PATH`, a supprimé les
//! enregistrements du nœud de production. Le vrai nœud les a servis de
//! mémoire jusqu'à son redémarrage, puis a rechargé un registre vide.
//!
//! `INFINITY_DATA_DIR` isole donc TOUT l'état d'une instance en une seule
//! variable : registre des pins, politique, repo IPFS, base du relais,
//! archives de tuiles, marqueur d'autostart — et, quand elle est posée, le
//! dossier sécurité (vault) qui vit sinon dans `Application Support`.
//!
//! ```text
//! INFINITY_DATA_DIR=/tmp/noeud-essai INFINITY_BIND_ADDR=127.0.0.1:7475 infinity-node
//! ```
//!
//! ⚠️ L'identité Ed25519 vit dans le **trousseau du système**, pas ici :
//! deux instances la partagent quoi qu'il arrive. L'isolation porte sur les
//! fichiers, pas sur la clé.

use std::path::PathBuf;

/// Nom de la variable qui déplace tout l'état du nœud.
pub const VAR_DOSSIER: &str = "INFINITY_DATA_DIR";

/// Le dossier d'état du nœud. `~/.infinity-node` par défaut.
#[must_use]
pub fn dossier_donnees() -> PathBuf {
    match std::env::var(VAR_DOSSIER) {
        Ok(v) if !v.trim().is_empty() => PathBuf::from(v.trim()),
        _ => dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".infinity-node"),
    }
}

/// `true` si l'état a été déplacé explicitement — le dossier sécurité suit
/// alors le déplacement, sinon il reste à sa place historique.
#[must_use]
pub fn dossier_deplace() -> bool {
    matches!(std::env::var(VAR_DOSSIER), Ok(v) if !v.trim().is_empty())
}

/// Sous-dossier de l'état du nœud.
#[must_use]
pub fn sous_dossier(nom: &str) -> PathBuf {
    dossier_donnees().join(nom)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Un seul test touche l'environnement : `set_var` est global au
    /// processus et les tests Rust tournent en parallèle — deux tests qui
    /// posent la même variable se voleraient leur valeur.
    #[test]
    fn la_variable_deplace_tout_letat() {
        std::env::remove_var(VAR_DOSSIER);
        let defaut = dossier_donnees();
        assert!(defaut.ends_with(".infinity-node"), "défaut inattendu : {defaut:?}");
        assert!(!dossier_deplace());

        std::env::set_var(VAR_DOSSIER, "/tmp/noeud-essai");
        assert_eq!(dossier_donnees(), PathBuf::from("/tmp/noeud-essai"));
        assert_eq!(sous_dossier("ipfs"), PathBuf::from("/tmp/noeud-essai/ipfs"));
        assert!(dossier_deplace());

        // Une variable posée mais vide n'est pas une intention : on ne veut
        // pas qu'un `export INFINITY_DATA_DIR=` fasse écrire le nœud dans "".
        std::env::set_var(VAR_DOSSIER, "   ");
        assert!(dossier_donnees().ends_with(".infinity-node"));
        assert!(!dossier_deplace());

        std::env::remove_var(VAR_DOSSIER);
    }
}
