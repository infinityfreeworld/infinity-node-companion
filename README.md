# Infinity Node — Companion natif

Compagnon Tier 1 du **Cœur du Cube**. Binaire Rust autonome qui expose
un endpoint de découverte sur `127.0.0.1:7474` que la PWA Infinity
détecte automatiquement (cf. `src/services/coeur-node/companion-probe.ts`).

## Quick start

```bash
cd infinity-node
cargo run
```

Au démarrage, la console affiche l'URL du handshake **et** une icône
cyan apparaît dans la barre système (menu bar macOS / system tray
windows / status bar linux). Ouvre la PWA Infinity, le panneau
**Cœur du Cube** : la sphère du Cube passe au cyan dans les
~8 secondes (cadence du probe PWA).

### Menu de la tray

| Item                       | Action                                                        |
|----------------------------|---------------------------------------------------------------|
| **Statut : Actif**         | Label en lecture seule (« Actif » ou « En pause »)            |
| **Ouvrir Infinity**        | Lance la PWA dans le navigateur défaut                        |
| **Mettre en pause**        | Le handshake renvoie 503 → la PWA bascule en mode browser     |
| **Démarrer à l'ouverture de session** ☑︎ | Toggle auto-launch (per-user, sans droits admin)  |
| **Quitter Infinity Node**  | Sortie propre (le port est libéré)                            |

### Auto-launch (Phase D.2)

Quand tu coches **« Démarrer à l'ouverture de session »**, le companion
s'enregistre auprès du système et redémarre automatiquement à chaque
login. Mécanismes par plateforme :

| Plateforme | Emplacement                                                  |
|------------|--------------------------------------------------------------|
| macOS      | `~/Library/LaunchAgents/com.infinity.node.plist`             |
| Linux      | `~/.config/autostart/InfinityNode.desktop` (XDG Autostart)   |
| Windows    | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`         |

Tout est **per-user** — pas de droits admin, pas de service système.
Décocher = suppression idempotente du registre/plist/desktop.

URL ciblée par « Ouvrir Infinity » : `https://localhost:5173` par
défaut. Override via env :

```bash
INFINITY_URL=https://infinity.app cargo run
```

## Build release (binaire optimisé taille)

```bash
cargo build --release
ls -lh target/release/infinity-node
```

Profil release : `opt-level=z`, LTO, single codegen unit, strip,
panic=abort. Objectif < 10 Mo (avant tray + IPFS).

## Endpoints

| Méthode | Path              | Description                                            |
|---------|-------------------|--------------------------------------------------------|
| GET     | `/api/handshake`  | Contrat de découverte (cf. `Handshake` dans main.rs)   |
| GET     | `/healthz`        | `"ok"` (monitoring)                                    |
| POST    | `/api/pin`        | `{ cid, module, ttl_hours? }` → record persisté        |
| DELETE  | `/api/pin/:cid`   | Unpin explicite + retrait du registre                  |
| GET     | `/api/pins`       | Liste tous les pins gérés (par la pin policy)          |
| GET     | `/api/policy`     | Politique de pin courante (par module + défaut)        |
| PUT     | `/api/policy`     | Remplace la politique (persistée disque)               |

CORS : toutes origines autorisées. La sécurité repose sur le bind
loopback (`127.0.0.1` uniquement, jamais `0.0.0.0`) — aucun acteur
externe ne peut atteindre l'endpoint.

## Roadmap

| Phase | Contenu                                                                | Statut |
|-------|------------------------------------------------------------------------|--------|
| D.0   | Handshake HTTP minimal                                                 | ✓      |
| D.1   | Tray icon native (tao + tray-icon, pause/reprendre/ouvrir/quit)        | ✓      |
| D.2   | Auto-launch au login (LaunchAgent mac / XDG linux / Run reg win)       | ✓      |
| E     | Subprocess kubo + nostr-rs-relay (auto-init repo, polling métriques)   | ✓      |
| E.1   | Pin policy par module + bandwidth caps + endpoints HTTP + janitor      | ✓      |
| F     | Mode public — UPnP / Cloudflare Tunnel / NIP-05 auto-attribué          | TODO   |

## Installation des backends (Phase E)

Infinity Node spawn les binaires **`ipfs`** (kubo) et **`nostr-rs-relay`**
s'ils sont présents sur le `PATH`. S'ils sont absents, le companion
tourne quand même mais s'annonce avec `capabilities: []` côté handshake.

### macOS (homebrew)

```bash
brew install ipfs                          # kubo
cargo install nostr-rs-relay               # ~3 min compile
```

### Linux

```bash
# kubo (binaire officiel)
curl -L https://dist.ipfs.tech/kubo/latest/install.sh | bash

# nostr-rs-relay
cargo install nostr-rs-relay
```

### Vérification

```bash
which ipfs nostr-rs-relay && cargo run
```

Tu dois voir dans le banner `Kubo : ✓` et `NOSTR : ✓`. Le `/api/handshake`
renvoie alors `capabilities: ["ipfs", "nostr-relay"]` avec les vraies
métriques pairs/CIDs/octets servis.

### Isolation kubo

Pour ne pas entrer en conflit avec un éventuel daemon kubo déjà installé
par l'utilisateur, Infinity Node utilise un repo IPFS dédié dans
`~/.infinity-node/ipfs/` avec ports custom :

| Service        | Port stock | Port Infinity Node |
|----------------|------------|--------------------|
| API HTTP       | 5001       | **5101**           |
| Gateway HTTP   | 8080       | **8181**           |
| Swarm TCP      | 4001       | **4101**           |
| Swarm WS       | -          | **4102**           |

Le repo est auto-initialisé au premier lancement (`ipfs init --profile=server`).

## Pin policy & bandwidth (Phase E.1)

Le companion gère un sous-ensemble des pins kubo selon une **politique
par module** (OBF, MHE, MOUV, …). Les modules PWA appellent
`POST /api/pin { cid, module, ttl_hours? }` quand ils veulent qu'un
contenu soit conservé localement et seedé. Le companion :

1. Vérifie la policy (le module est-il autorisé à pinner ?)
2. Appelle kubo `pin_add(cid)` (si présent)
3. Mesure la taille (`object/stat`) et persiste un record
4. Le **janitor** (job tokio horaire) unpinne les records dont
   `pinned_at + ttl_secs < now`

Politique par défaut (`default_rule`) : `enabled=true`, `max_mb=100`,
`default_ttl_hours=168` (7 jours). Personnalisable via
`PUT /api/policy` ou en éditant `~/.infinity-node/policy.json`.

### Bandwidth cap

Cap journalier configurable via env :

```bash
INFINITY_BW_CAP_MB=10000 cargo run    # 10 Go/jour au lieu du défaut 5 Go
```

Reset à minuit UTC, baseline = `stats/bw` à ce moment-là. **Pas
d'enforcement** en E.1 — uniquement tracking + display dans la tray
et le handshake. L'enforcement viendra en E.2 (probable : pause auto
du nœud quand cap atteint, reprise au reset journalier).

### Fichiers persistés

```
~/.infinity-node/
├── ipfs/              # repo kubo isolé
├── relay/             # data nostr-rs-relay + config
├── policy.json        # pin policy
└── pins.json          # registre des pins gérés (cid → record)
```
