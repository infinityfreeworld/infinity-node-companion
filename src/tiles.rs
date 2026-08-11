//! # Serveur d'archives PMTiles — le chaînon qui manquait
//!
//! ## Le défaut, constaté le 10/08/2026
//!
//! Bâtisseur : « hors ligne, la carte est noire ». Trois archives PMTiles
//! dormaient dans `~/.infinity-node/tiles/` — 244 Mo, atlas + deux satellites —
//! et le mot « tiles » n'apparaissait **nulle part** dans ce dépôt. Elles
//! étaient servies par RIEN.
//!
//! Côté PWA, tout existait pourtant : le lecteur PMTiles, le constructeur de
//! style hors-ligne, le diagnostic qui explique l'absence de fond. Ce code
//! attendait un interlocuteur qui n'avait jamais été écrit. Encore une capacité
//! présente des deux côtés, et le fil entre les deux jamais tiré.
//!
//! ## Le contrat, tel que la PWA l'attend
//!
//!   • la capacité `tiles` dans le handshake — c'est une liste BLANCHE :
//!     ce qui n'y figure pas n'est jamais tenté, même si ça fonctionne ;
//!   • `GET /api/tiles` → `{ "active": true, "archives": [ { name, url,
//!     sizeBytes } ] }` ;
//!   • chaque `url` sert le fichier en RÉPONDANT AUX REQUÊTES DE PLAGE.
//!
//! ## ⚠️ Les requêtes de plage ne sont pas une optimisation
//!
//! Un fichier PMTiles est un conteneur : le lecteur lit d'abord l'en-tête
//! (127 octets), puis l'index, puis les tuiles voulues — quelques kilo-octets
//! sur 134 Mo. Sans le code **206** et l'en-tête `Content-Range`, le navigateur
//! reçoit tout le fichier à chaque tuile : la carte semble « lente » au lieu
//! d'être franchement cassée, ce qui est pire à diagnostiquer. C'est un piège
//! déjà rencontré côté PWA, noté « ⚠️ 206 pas 200 ».
//!
//! ## Ce que ce module refuse
//!
//! Il ne sert QUE `*.pmtiles`, et seulement à la racine du dossier d'archives.
//! Un chemin contenant un séparateur ou `..` est rejeté sans être interprété :
//! ce serveur écoute sur une machine personnelle, et une traversée de chemin y
//! lirait le dossier de départ du Bâtisseur.

use axum::{
    body::Body,
    extract::Path as AxumPath,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncSeekExt};

/// Où vivent les archives. Même dossier que le reste de l'état du nœud.
pub fn tiles_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".infinity-node")
        .join("tiles")
}

#[derive(Serialize)]
pub struct ArchiveJson {
    pub name: String,
    pub url: String,
    #[serde(rename = "sizeBytes")]
    pub size_bytes: u64,
}

#[derive(Serialize)]
pub struct TilesJson {
    pub active: bool,
    pub archives: Vec<ArchiveJson>,
}

/// Y a-t-il au moins une archive lisible ? Décide de la capacité `tiles`.
///
/// ⚠️ Annoncer la capacité avec un dossier VIDE serait pire que se taire : la
/// PWA basculerait sur un fond hors-ligne inexistant et rendrait une carte
/// noire — le symptôme même qu'on corrige. On n'annonce que ce qu'on a.
pub fn has_archives() -> bool {
    !lister(&tiles_dir()).is_empty()
}

/// Les archives présentes, triées par nom pour un ordre stable d'un appel à
/// l'autre (une liste qui change d'ordre ferait clignoter le sélecteur).
fn lister(dir: &Path) -> Vec<(String, u64)> {
    let mut out: Vec<(String, u64)> = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else { return out };
    for e in entries.flatten() {
        let path = e.path();
        if path.extension().and_then(|s| s.to_str()) != Some("pmtiles") {
            continue;
        }
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else { continue };
        let size = e.metadata().map(|m| m.len()).unwrap_or(0);
        /* Un fichier vide ou tronqué (copie interrompue) ferait échouer le
           lecteur avec une erreur incompréhensible. On l'écarte ici. */
        if size < 128 {
            continue;
        }
        out.push((name.to_string(), size));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Empreinte d'une archive : sa taille et sa date de modification.
///
/// ⚠️ PAS un hachage du contenu. Hacher 134 Mo à chaque requête de tuile
/// coûterait mille fois plus cher que de servir la tuile elle-même. Taille et
/// date changent dès qu'on remplace le fichier — le seul cas qui nous
/// intéresse, puisqu'une archive n'est jamais modifiée en place.
fn empreinte(meta: &std::fs::Metadata) -> String {
    let secs = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("\"{}-{}\"", meta.len(), secs)
}

/// Ce qu'on dit au navigateur sur la durée de vie d'une tuile.
///
/// ⚠️ Sans ces en-têtes — l'état livré le 10/08 — le navigateur ne garde RIEN :
/// repasser sur une zone déjà vue redemande chaque tuile au nœud. En loopback
/// une plage coûte 1,6 à 2,7 ms (mesuré), donc l'effet est invisible ; il cesse
/// de l'être dès que le nœud est joint par le réseau local ou par Tailscale, où
/// le même aller-retour se compte en dizaines de millisecondes.
///
/// `immutable` : le contenu d'un octet donné d'une archive ne change jamais. Si
/// l'archive est remplacée, son empreinte change et le navigateur revalide.
const CACHE_TUILES: &str = "public, max-age=604800, immutable";

/// `GET /api/tiles` — le catalogue.
pub async fn list_tiles(headers: HeaderMap) -> impl IntoResponse {
    /* L'URL rendue doit être joignable PAR LE NAVIGATEUR, pas par nous. On la
       construit donc à partir de l'hôte qu'il a lui-même appelé : le nœud peut
       écouter sur 127.0.0.1, sur une IP du réseau local ou sur une adresse
       Tailscale, et coder « 127.0.0.1 » en dur casserait tous les cas sauf un. */
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("127.0.0.1:7474");
    let archives = lister(&tiles_dir())
        .into_iter()
        .map(|(name, size_bytes)| ArchiveJson {
            url: format!("http://{host}/api/tiles/{name}"),
            name,
            size_bytes,
        })
        .collect::<Vec<_>>();
    Json(TilesJson { active: !archives.is_empty(), archives })
}

/// Refuse tout nom qui n'est pas un simple fichier d'archive de ce dossier.
fn nom_sur(nom: &str) -> Option<String> {
    if nom.contains('/') || nom.contains('\\') || nom.contains("..") {
        return None;
    }
    if !nom.ends_with(".pmtiles") {
        return None;
    }
    Some(nom.to_string())
}

/// Lit `[debut, fin]` du fichier. Bornes INCLUSIVES, comme le veut HTTP.
async fn lire_plage(path: &Path, debut: u64, fin: u64) -> std::io::Result<Vec<u8>> {
    let mut f = tokio::fs::File::open(path).await?;
    f.seek(std::io::SeekFrom::Start(debut)).await?;
    let taille = (fin - debut + 1) as usize;
    let mut buf = vec![0u8; taille];
    f.read_exact(&mut buf).await?;
    Ok(buf)
}

/// `GET /api/tiles/:nom` — le fichier, entier ou par plage.
pub async fn get_tile_archive(
    AxumPath(nom): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    let Some(nom) = nom_sur(&nom) else {
        return (StatusCode::BAD_REQUEST, "nom d'archive invalide").into_response();
    };
    let path = tiles_dir().join(&nom);
    let Ok(meta) = tokio::fs::metadata(&path).await else {
        return (StatusCode::NOT_FOUND, "archive absente").into_response();
    };
    let taille = meta.len();
    let etag = empreinte(&meta);

    /* Le navigateur nous rend l'empreinte qu'il détient : si elle correspond,
       il n'y a rien à renvoyer. ⚠️ On répond AVANT de lire le disque — après,
       le code serait juste et le coût inchangé. */
    if headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|e| e.trim() == etag))
    {
        return Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .header(header::ETAG, etag)
            .header(header::CACHE_CONTROL, CACHE_TUILES)
            .body(Body::empty())
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }

    let plage = headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| parse_range(v, taille));

    match plage {
        Some((debut, fin)) => match lire_plage(&path, debut, fin).await {
            Ok(buf) => Response::builder()
                .status(StatusCode::PARTIAL_CONTENT)
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .header(header::CONTENT_RANGE, format!("bytes {debut}-{fin}/{taille}"))
                .header(header::CONTENT_LENGTH, buf.len())
                .header(header::ACCEPT_RANGES, "bytes")
                .header(header::ETAG, &etag)
                .header(header::CACHE_CONTROL, CACHE_TUILES)
                .body(Body::from(buf))
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()),
            Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "lecture impossible").into_response(),
        },
        None => {
            /* Pas de plage demandée : on rend tout. ⚠️ `Accept-Ranges` est
               annoncé MÊME ICI — c'est ce qui dit au lecteur qu'il peut
               demander des morceaux la prochaine fois. Sans cet en-tête,
               certains clients renoncent aux plages et retéléchargent 134 Mo
               par tuile. */
            match tokio::fs::read(&path).await {
                Ok(buf) => Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/octet-stream")
                    .header(header::CONTENT_LENGTH, buf.len())
                    .header(header::ACCEPT_RANGES, "bytes")
                    .header(header::ETAG, &etag)
                    .header(header::CACHE_CONTROL, CACHE_TUILES)
                    .body(Body::from(buf))
                    .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()),
                Err(_) => (StatusCode::NOT_FOUND, "archive illisible").into_response(),
            }
        }
    }
}

/// Interprète un en-tête `Range`. Rend `None` si absurde — l'appelant sert
/// alors le fichier entier, ce qui est toujours correct.
///
/// ⚠️ On ne gère QUE la forme `bytes=debut-fin` et `bytes=debut-`. Les plages
/// multiples (`bytes=0-99,200-299`) sont légales mais exigent une réponse
/// `multipart/byteranges` qu'aucun lecteur PMTiles n'émet. Prétendre les
/// comprendre en ne rendant que la première serait un mensonge silencieux : on
/// préfère rendre le fichier entier, lent mais juste.
pub fn parse_range(v: &str, taille: u64) -> Option<(u64, u64)> {
    let reste = v.trim().strip_prefix("bytes=")?;
    if reste.contains(',') {
        return None;
    }
    let (a, b) = reste.split_once('-')?;
    let a = a.trim();
    let b = b.trim();

    if a.is_empty() {
        /* Suffixe : `bytes=-500` = les 500 DERNIERS octets. C'est ainsi que
           beaucoup de lecteurs vont chercher l'en-tête de fin d'un conteneur. */
        let n: u64 = b.parse().ok()?;
        if n == 0 || taille == 0 {
            return None;
        }
        let n = n.min(taille);
        return Some((taille - n, taille - 1));
    }

    let debut: u64 = a.parse().ok()?;
    if debut >= taille {
        return None; // hors du fichier — on ne peut rien en dire de sensé
    }
    let fin = if b.is_empty() { taille - 1 } else { b.parse::<u64>().ok()?.min(taille - 1) };
    if fin < debut {
        return None;
    }
    Some((debut, fin))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn une_plage_ordinaire() {
        assert_eq!(parse_range("bytes=0-99", 1000), Some((0, 99)));
        assert_eq!(parse_range("bytes=100-199", 1000), Some((100, 199)));
    }

    #[test]
    fn une_plage_ouverte_va_jusquau_bout() {
        assert_eq!(parse_range("bytes=900-", 1000), Some((900, 999)));
    }

    #[test]
    fn un_suffixe_prend_la_fin_du_fichier() {
        // ⚠️ `bytes=-500` ne veut PAS dire « jusqu'à 500 » : c'est la fin.
        assert_eq!(parse_range("bytes=-500", 1000), Some((500, 999)));
    }

    #[test]
    fn une_fin_au_dela_du_fichier_est_ramenee() {
        // Un lecteur qui demande trop doit recevoir ce qui existe, pas une
        // erreur : c'est le cas normal quand il lit le dernier bloc.
        assert_eq!(parse_range("bytes=900-99999", 1000), Some((900, 999)));
    }

    #[test]
    fn une_plage_absurde_est_refusee() {
        assert_eq!(parse_range("bytes=500-100", 1000), None);
        assert_eq!(parse_range("bytes=2000-3000", 1000), None);
        assert_eq!(parse_range("octets=0-10", 1000), None);
        assert_eq!(parse_range("", 1000), None);
    }

    #[test]
    fn les_plages_multiples_sont_refusees_plutot_que_tronquees() {
        // Rendre seulement la première serait un mensonge silencieux.
        assert_eq!(parse_range("bytes=0-99,200-299", 1000), None);
    }

    #[test]
    fn un_nom_de_fichier_ne_peut_pas_sortir_du_dossier() {
        // ⚠️ Ce serveur tourne sur une machine personnelle.
        assert_eq!(nom_sur("../../.ssh/id_rsa"), None);
        assert_eq!(nom_sur("sous/dossier.pmtiles"), None);
        assert_eq!(nom_sur("atlas.pmtiles"), Some("atlas.pmtiles".into()));
    }

    #[test]
    fn seules_les_archives_pmtiles_sont_servies() {
        assert_eq!(nom_sur("config.toml"), None);
        assert_eq!(nom_sur("vault.ifv"), None);
    }

    fn dossier_jetable(nom: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("infinity-tiles-{nom}"));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }
    fn ecrire(d: &Path, nom: &str, octets: usize) {
        std::fs::write(d.join(nom), vec![0u8; octets]).unwrap();
    }

    #[test]
    fn un_dossier_vide_ne_donne_aucune_archive() {
        // ⚠️ Ce qui décide de la capacité `tiles`. L'annoncer à vide ferait
        // basculer la carte sur un fond hors-ligne inexistant — donc NOIRE,
        // le symptôme même qu'on corrige.
        let d = dossier_jetable("vide");
        assert!(lister(&d).is_empty());
    }

    #[test]
    fn seuls_les_pmtiles_sont_listes() {
        let d = dossier_jetable("tri");
        ecrire(&d, "atlas.pmtiles", 1000);
        ecrire(&d, "config.toml", 1000);
        ecrire(&d, "vault.ifv", 1000);
        let l = lister(&d);
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].0, "atlas.pmtiles");
        assert_eq!(l[0].1, 1000);
    }

    #[test]
    fn une_archive_tronquee_est_ecartee() {
        // Une copie interrompue ferait échouer le lecteur avec une erreur
        // incompréhensible, très loin d'ici.
        let d = dossier_jetable("tronque");
        ecrire(&d, "moitie.pmtiles", 12);
        assert!(lister(&d).is_empty());
    }

    #[test]
    fn l_ordre_est_stable() {
        // Un ordre qui change d'un appel à l'autre ferait clignoter le
        // sélecteur de fonds sous les yeux du Bâtisseur.
        let d = dossier_jetable("ordre");
        ecrire(&d, "zeta.pmtiles", 500);
        ecrire(&d, "alpha.pmtiles", 500);
        let noms: Vec<String> = lister(&d).into_iter().map(|(n, _)| n).collect();
        assert_eq!(noms, vec!["alpha.pmtiles", "zeta.pmtiles"]);
    }

    #[test]
    fn un_dossier_absent_ne_fait_pas_paniquer() {
        // Premier démarrage : `~/.infinity-node/tiles/` n'existe pas encore.
        assert!(lister(Path::new("/tmp/ce-dossier-n-existe-pas-42")).is_empty());
    }

    #[test]
    fn l_empreinte_change_quand_l_archive_change() {
        // ⚠️ Le point de tout le cache : si l'empreinte NE changeait PAS après
        // remplacement, le navigateur servirait l'ancienne carte pendant une
        // semaine (`immutable`), sans aucun moyen de s'en apercevoir.
        let d = dossier_jetable("empreinte");
        let f = d.join("a.pmtiles");
        std::fs::write(&f, vec![0u8; 500]).unwrap();
        let e1 = empreinte(&std::fs::metadata(&f).unwrap());

        // Une taille différente suffit à distinguer.
        std::fs::write(&f, vec![0u8; 900]).unwrap();
        let e2 = empreinte(&std::fs::metadata(&f).unwrap());
        assert_ne!(e1, e2, "l'empreinte n'a pas bougé après remplacement");
    }

    #[test]
    fn l_empreinte_est_stable_pour_un_fichier_inchange() {
        // Sinon chaque requête invaliderait le cache : les en-têtes seraient
        // là, et le cache n'existerait toujours pas.
        let d = dossier_jetable("stable");
        let f = d.join("b.pmtiles");
        std::fs::write(&f, vec![0u8; 500]).unwrap();
        let m = std::fs::metadata(&f).unwrap();
        assert_eq!(empreinte(&m), empreinte(&m));
    }

    #[test]
    fn l_empreinte_est_un_etag_bien_forme() {
        // Un ETag DOIT être entre guillemets : sans eux, les navigateurs
        // l'ignorent silencieusement — en-tête présent, effet nul.
        let d = dossier_jetable("forme");
        let f = d.join("c.pmtiles");
        std::fs::write(&f, vec![0u8; 128]).unwrap();
        let e = empreinte(&std::fs::metadata(&f).unwrap());
        assert!(e.starts_with('"') && e.ends_with('"'), "ETag mal formé : {e}");
    }
}
