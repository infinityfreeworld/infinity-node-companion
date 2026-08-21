//! # Tableau de bord local du nœud — LECTURE SEULE
//!
//! Une page unique, embarquée dans le binaire, servie sur `/` et `/ui`.
//! Elle n'expose aucune donnée nouvelle : elle affiche ce que le nœud
//! répond déjà (`/api/handshake`, `/api/stream`, `/api/pins`, `/api/policy`,
//! `/api/tiles`, `/relay/private/info`, `/ipfs/private/info`).
//!
//! ## Pourquoi côté nœud et pas seulement dans la PWA
//!
//! Le Cube affiche l'état du nœud à travers le pont PWA↔nœud. Les pannes
//! qu'on veut diagnostiquer sont justement celles où ce pont est cassé :
//! l'instrument tombe en même temps que ce qu'il mesure. Cette page est
//! servie par le nœud lui-même — elle reste lisible quand la PWA ne voit
//! plus rien, et elle montre la valeur BRUTE, pas la version interprétée.
//!
//! ## Sécurité
//!
//! - **Lecture seule.** Aucune route mutante n'est ajoutée ici. Toute
//!   écriture reste derrière la signature Ed25519 (`api::auth_middleware`).
//! - **Anti DNS-rebinding.** L'API tourne sur une adresse locale avec
//!   `CorsLayer::allow_origin(Any)` : sans garde, une page malveillante
//!   pourrait faire pointer `piege.example` sur 127.0.0.1 et lire le nœud
//!   depuis son propre origine. On refuse donc tout en-tête `Host` qui
//!   n'est pas une IP littérale ou `localhost` — un nom de domaine est
//!   précisément ce qu'un attaquant a besoin de faire résoudre.
//!   Échappatoire explicite pour MagicDNS/Tailscale : `INFINITY_UI_HOSTS`
//!   (noms supplémentaires séparés par des virgules).
//! - **CSP stricte** : rien ne peut être chargé depuis l'extérieur, et la
//!   page ne parle qu'à sa propre origine.

use axum::{
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};

/// La page est embarquée dans le binaire : un nœud diagnostiqué depuis une
/// machine sans réseau doit pouvoir l'afficher, et aucun fichier posé à côté
/// du binaire ne peut diverger de la version qui tourne.
const PAGE: &str = include_str!("../assets/ui.html");

const CSP: &str = "default-src 'none'; \
                   script-src 'unsafe-inline'; \
                   style-src 'unsafe-inline'; \
                   connect-src 'self'; \
                   img-src 'self' data:; \
                   base-uri 'none'; \
                   form-action 'none'; \
                   frame-ancestors 'none'";

pub async fn page(headers: HeaderMap) -> Response {
    let hote = headers.get(header::HOST).and_then(|v| v.to_str().ok());
    if !hote_autorise(hote, &noms_supplementaires()) {
        return (
            StatusCode::FORBIDDEN,
            "Hôte refusé. Le tableau de bord ne s'ouvre que sur une adresse IP \
             littérale ou « localhost » (garde anti DNS-rebinding). \
             Pour un nom de domaine légitime : INFINITY_UI_HOSTS=mon.nom.interne\n",
        )
            .into_response();
    }

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
            (header::CONTENT_SECURITY_POLICY, CSP),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::REFERRER_POLICY, "no-referrer"),
        ],
        PAGE,
    )
        .into_response()
}

fn noms_supplementaires() -> Vec<String> {
    std::env::var("INFINITY_UI_HOSTS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

/// `true` si l'en-tête `Host` est une IP littérale, `localhost`, ou un nom
/// explicitement autorisé par l'utilisateur.
///
/// ⚠️ Le point qui compte : un **nom** non listé est refusé, parce que le
/// rebinding DNS a besoin d'un nom. Une IP ne se rebinde pas.
pub fn hote_autorise(hote: Option<&str>, supplementaires: &[String]) -> bool {
    let brut = match hote {
        Some(h) if !h.is_empty() => h.trim().to_ascii_lowercase(),
        // Pas d'en-tête Host : on ne peut rien prouver, on refuse.
        _ => return false,
    };

    let sans_port = if let Some(reste) = brut.strip_prefix('[') {
        // IPv6 littéral : [::1]:7474
        match reste.split(']').next() {
            Some(ip) => ip.to_string(),
            None => return false,
        }
    } else {
        match brut.rsplit_once(':') {
            Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => h.to_string(),
            _ => brut.clone(),
        }
    };

    if sans_port == "localhost" {
        return true;
    }
    if sans_port.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    supplementaires.iter().any(|n| *n == sans_port)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn aucun() -> Vec<String> {
        Vec::new()
    }

    #[test]
    fn accepte_les_adresses_locales_et_ip_litterales() {
        assert!(hote_autorise(Some("127.0.0.1:7474"), &aucun()));
        assert!(hote_autorise(Some("localhost:7474"), &aucun()));
        assert!(hote_autorise(Some("localhost"), &aucun()));
        assert!(hote_autorise(Some("[::1]:7474"), &aucun()));
        assert!(hote_autorise(Some("192.168.1.42:7474"), &aucun()));
        // Adresse Tailscale — INFINITY_BIND_ADDR documente ce cas.
        assert!(hote_autorise(Some("100.64.1.5:7474"), &aucun()));
        assert!(hote_autorise(Some("LOCALHOST:7474"), &aucun()));
    }

    #[test]
    fn refuse_les_noms_de_domaine_cest_tout_lobjet_du_garde() {
        assert!(!hote_autorise(Some("piege.example:7474"), &aucun()));
        assert!(!hote_autorise(Some("infinity-freeworld.com"), &aucun()));
        // Un nom qui CONTIENT une IP reste un nom.
        assert!(!hote_autorise(Some("127.0.0.1.piege.example:7474"), &aucun()));
        // Le sous-domaine d'un nom autorisé n'est pas ce nom.
        assert!(!hote_autorise(
            Some("mechant.mon.nom.interne"),
            &["mon.nom.interne".to_string()]
        ));
    }

    #[test]
    fn refuse_un_host_absent_ou_vide() {
        assert!(!hote_autorise(None, &aucun()));
        assert!(!hote_autorise(Some(""), &aucun()));
        assert!(!hote_autorise(Some("   "), &aucun()));
    }

    #[test]
    fn autorise_un_nom_explicitement_declare() {
        let sup = vec!["mac-de-med.tail1234.ts.net".to_string()];
        assert!(hote_autorise(Some("mac-de-med.tail1234.ts.net:7474"), &sup));
        assert!(hote_autorise(Some("MAC-DE-MED.tail1234.TS.NET"), &sup));
        assert!(!hote_autorise(Some("autre.ts.net"), &sup));
    }

    /// La page doit rester lisible sur une machine sans réseau : aucune
    /// ressource externe, sinon le tableau de bord de diagnostic dépend
    /// justement de ce qu'il est censé diagnostiquer.
    #[test]
    fn la_page_ne_charge_rien_de_lexterieur() {
        for motif in ["src=\"http", "href=\"http", "//fonts.", "cdn.", "@import"] {
            assert!(
                !PAGE.contains(motif),
                "la page embarquée référence une ressource externe : {motif}"
            );
        }
    }

    /// Garde anti-dérive : la page ne doit interroger que des routes qui
    /// existent vraiment. Une route renommée côté Rust laisserait sinon une
    /// carte muette, sans erreur visible.
    #[test]
    fn la_page_ninterroge_que_des_routes_connues() {
        const CONNUES: &[&str] = &[
            "/api/handshake",
            "/api/stream",
            "/api/pins",
            "/api/policy",
            "/api/tiles",
            "/relay/private/info",
            "/ipfs/private/info",
            "/auth/devices",
            "/healthz",
            "/api/amorcage",
            "/api/journal",
        ];
        // Les chemins réellement appelés : arguments de fetch() et cible du
        // WebSocket (concaténée à location.host). Surtout PAS toutes les
        // chaînes qui commencent par « / » — les phrases françaises en
        // contiennent, et un test qui crie au loup finit désactivé.
        let mut citees: Vec<&str> = Vec::new();
        for (marqueur, decalage) in [
            ("fetch(\"", 7),
            ("lire(\"", 6),
            ("location.host + \"", 17),
        ] {
            let mut reste = PAGE;
            while let Some(i) = reste.find(marqueur) {
                reste = &reste[i + decalage..];
                let fin = match reste.find('\"') {
                    Some(f) => f,
                    None => break,
                };
                let chemin = &reste[..fin];
                if chemin.starts_with('/') && !citees.contains(&chemin) {
                    citees.push(chemin);
                }
            }
        }
        assert!(
            citees.len() >= 7,
            "extraction cassée : seulement {} routes trouvées dans la page",
            citees.len()
        );
        assert!(
            citees.contains(&"/api/stream"),
            "le flux direct n'est plus branché dans la page"
        );
        for chemin in citees {
            assert!(
                CONNUES.contains(&chemin),
                "la page appelle « {chemin} », qui n'est pas une route du nœud"
            );
        }
    }

    /// Le handler complet, sans aucun `AppState` : ce qui se voit ici est ce
    /// que le navigateur reçoit vraiment (statut, en-têtes, corps).
    #[tokio::test]
    async fn un_hote_local_recoit_la_page_et_ses_gardes() {
        let mut h = HeaderMap::new();
        h.insert(header::HOST, "127.0.0.1:7474".parse().unwrap());
        let r = page(h).await;
        assert_eq!(r.status(), StatusCode::OK);
        let entetes = r.headers();
        assert_eq!(entetes[header::CONTENT_TYPE], "text/html; charset=utf-8");
        assert_eq!(entetes[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert_eq!(entetes[header::CACHE_CONTROL], "no-store");
        let csp = entetes[header::CONTENT_SECURITY_POLICY].to_str().unwrap();
        assert!(csp.contains("default-src 'none'"), "CSP trop permissive : {csp}");
        assert!(csp.contains("connect-src 'self'"), "CSP trop permissive : {csp}");
        assert!(csp.contains("frame-ancestors 'none'"), "CSP trop permissive : {csp}");

        let corps = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
        assert_eq!(corps.len(), PAGE.len());
    }

    /// Un site distant qui fait résoudre son nom sur 127.0.0.1 ne doit pas
    /// récupérer une ligne de la page — ni un message qui la remplacerait.
    #[tokio::test]
    async fn un_nom_de_domaine_ne_recoit_pas_la_page() {
        let mut h = HeaderMap::new();
        h.insert(header::HOST, "piege.example".parse().unwrap());
        let r = page(h).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        let corps = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
        let texte = String::from_utf8_lossy(&corps);
        assert!(!texte.contains("<html"), "la page a fuité vers un hôte refusé");
        assert!(texte.contains("DNS-rebinding"), "le refus n'explique pas pourquoi");
    }

    /// Le tutoriel est la seule partie de la page écrite pour quelqu'un qui
    /// n'a pas bâti le nœud. Il se supprime d'un coup de refactor sans que
    /// rien ne casse — d'où ce garde.
    #[test]
    fn la_page_explique_le_noeud_a_qui_ne_le_connait_pas() {
        assert!(PAGE.contains("Explication du nœud"), "le texte cliquable a disparu");
        assert!(PAGE.contains("<summary>"), "l'explication doit rester dépliante");
        // La notion qu'on ne peut PAS se permettre de perdre : une demande
        // n'est pas une détention.
        assert!(
            PAGE.contains("demandé n'est pas détenu"),
            "le tutoriel n'explique plus la différence entre pin demandé et pin détenu"
        );
    }

    /// Lecture seule : aucune méthode mutante ne doit apparaître dans la page.
    #[test]
    fn la_page_est_en_lecture_seule() {
        for motif in ["method: \"POST", "method:\"POST", "method: \"PUT", "method: \"DELETE"] {
            assert!(!PAGE.contains(motif), "la page tente une écriture : {motif}");
        }
    }
}
