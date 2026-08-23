//! # Parler à qui est DEVANT la machine
//!
//! Le jeton d'appairage ne doit jamais transiter par HTTP : aucune route ne
//! le renvoie, sinon n'importe quelle page ouverte dans le navigateur
//! pourrait se l'offrir et appairer un appareil en silence (l'API tourne en
//! `allow_origin(Any)`). Il ne doit pas non plus entrer dans le journal du
//! nœud, que la page sert sans authentification.
//!
//! Il était donc imprimé sur la **sortie standard**… que personne ne voit
//! quand le nœud est lancé depuis le Finder : le Bâtisseur cliquait
//! « Appairer un nouvel appareil… » et **rien ne se passait**. Une capacité
//! réelle, branchée dans le vide.
//!
//! Une boîte de dialogue du système garde la propriété qui compte — il faut
//! être physiquement devant l'écran — et la rend enfin visible.

/// Un jeton sûr à insérer dans un script AppleScript : ni guillemet, ni
/// contre-oblique, ni saut de ligne — donc rien qui puisse s'échapper de la
/// chaîne et devenir de l'instruction.
///
/// ⚠️ On ne « nettoie » pas le jeton : on REFUSE de l'afficher s'il sort de
/// l'alphabet attendu. Échapper un secret dans un langage de script est un
/// jeu qu'on perd tôt ou tard ; le refus, lui, ne se contourne pas.
#[must_use]
pub fn jeton_sur(jeton: &str) -> bool {
    !jeton.is_empty()
        && jeton.len() <= 256
        && jeton
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

/// Affiche le jeton dans une fenêtre du système, sans bloquer la boucle du
/// menu (la fenêtre attend un clic humain : l'attendre sur le fil principal
/// figerait la barre de menus).
///
/// Renvoie `false` si l'affichage n'a pas pu être tenté — l'appelant garde
/// alors l'impression console comme filet.
pub fn afficher_jeton_appairage(jeton: &str) -> bool {
    if !jeton_sur(jeton) {
        return false;
    }
    #[cfg(target_os = "macos")]
    {
        let jeton = jeton.to_owned();
        std::thread::spawn(move || {
            let script = format!(
                "display dialog \"Jeton d'appairage — valide 10 minutes.\n\n\
                 Saisis-le dans Infinity, sur l'appareil à appairer.\" \
                 with title \"Infinity Node\" default answer \"{jeton}\" \
                 buttons {{\"Fermer\"}} default button 1 with icon note"
            );
            let _ = std::process::Command::new("osascript")
                .arg("-e")
                .arg(script)
                .status();
        });
        true
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn un_jeton_ordinaire_est_accepte() {
        assert!(jeton_sur("a1B2c3D4e5F6"));
        assert!(jeton_sur("abc-def_012.34"));
    }

    /// Ce que le garde existe pour arrêter : un jeton qui sortirait de sa
    /// chaîne AppleScript et deviendrait une instruction.
    #[test]
    fn tout_ce_qui_pourrait_sechapper_est_refuse() {
        assert!(!jeton_sur("abc\" & (do shell script \"rm -rf ~\") & \""));
        assert!(!jeton_sur("abc\\ndef"));
        assert!(!jeton_sur("abc def"));
        assert!(!jeton_sur("abc\ndef"));
        assert!(!jeton_sur(""));
        assert!(!jeton_sur(&"a".repeat(257)));
    }
}
