# Activer l'auto-installer du relai NOSTR — Tutoriel

> **Pour qui :** mainteneur du repo `infinity-node-companion`.
> **Quand :** une fois pour activer Phase 3.E, puis chaque fois qu'on
> bump la version de `nostr-rs-relay` upstream (rare, ~1 fois par an).
> **Durée :** ~20 minutes (15 min de build CI + 5 min de clics).

---

## Pourquoi

Sans cette activation, le companion natif `infinity-node` ne peut PAS
auto-télécharger `nostr-rs-relay` au 1ᵉʳ run — l'utilisateur doit
l'installer manuellement (`cargo install nostr-rs-relay`), ce qui
bloque 99 % des Bâtisseurs.

Une fois activé, le companion télécharge automatiquement le bon
binaire pour son OS/arch au 1ᵉʳ démarrage. Zéro friction.

---

## 3 étapes

### Étape 1 — Lancer le workflow `release-relay`

1. Va sur https://github.com/infinityfreeworld/infinity-node-companion/actions
2. Clique sur le workflow **« Release nostr-rs-relay binaries »**
3. Clique **« Run workflow »** (bouton à droite)
4. Branche : `main`
5. `relay_version` : `0.9.1` (ou plus récent — cf.
   [scsibug/nostr-rs-relay/releases](https://github.com/scsibug/nostr-rs-relay/releases))
6. Clique **« Run workflow »**

Le workflow :
- Cross-compile `nostr-rs-relay` pour 5 cibles (Mac arm64/x86_64,
  Linux x86_64/aarch64, Windows x86_64) — **~10-15 min**
- Publie les binaires comme assets sur une release `relay-v0.9.1`
- **Auto-génère une PR** qui patch les SHA-256 dans
  `src/relay_installer.rs`

### Étape 2 — Merger la PR auto-générée

1. Une PR titrée **« chore(relay): bump RELAY_TAG + SHA-256 hashes
   (relay-v0.9.1) »** apparaît dans
   https://github.com/infinityfreeworld/infinity-node-companion/pulls
2. Vérifie le diff (juste le bump de `RELAY_TAG` + 5 hashes hex)
3. **Merge** (bouton vert)

### Étape 3 — Tag + release une nouvelle version companion

```bash
git checkout main
git pull
git tag v0.3.0
git push --tags
```

Le workflow `release.yml` se déclenche automatiquement et publie
les installeurs natifs (`.dmg`, `.msi`, `.AppImage`) sur la release
`v0.3.0`.

---

## Vérification

Une fois `v0.3.0` publié, télécharge l'installeur depuis
https://github.com/infinityfreeworld/infinity-node-companion/releases/latest
sur une **machine de test propre** (qui n'a pas `nostr-rs-relay` sur
le PATH) et lance `infinity-node`.

Au 1ᵉʳ run, dans les logs tu dois voir :

```
INFO  nostr-rs-relay non trouvé — auto-download depuis
      https://github.com/.../releases/download/relay-v0.9.1/nostr-rs-relay-macos-aarch64
INFO  nostr-rs-relay installé : ~/Library/.../bin/nostr-rs-relay (4194304 bytes)
INFO  nostr-rs-relay config écrite ...
```

Le relai privé tourne, les autres features (vault chiffré, identité
Ed25519, pairing PWA) fonctionnent normalement. ✅

---

## En cas de problème

### Le workflow `release-relay` échoue sur un job

- **macOS x86_64** (`macos-13`) : runner Intel parfois indispo →
  réessaye dans 1h, ou retire ce job temporairement (les Macs Intel
  sont en fin de vie, faible perte UX)
- **Linux aarch64** (`cross`) : timeout possible (cross + QEMU est
  lent) → augmente le timeout du job ou retry
- **Windows** : rare, en général retry suffit

### La PR auto n'apparaît pas

- Vérifie les logs du job `auto-pr-hashes` dans le run du workflow
- L'erreur la plus fréquente : `peter-evans/create-pull-request`
  manque la permission `pull-requests: write` (déjà set dans le YAML,
  mais peut être désactivée au niveau du repo settings)
- Solution : Settings → Actions → General → Workflow permissions →
  cocher « Read and write permissions »

### Le companion télécharge mais le hash ne matche pas

- Cela ne devrait JAMAIS arriver si la PR auto a été correctement
  mergée (les hashes sont dérivés du même build artifact)
- Si ça arrive : ré-exécuter le workflow `release-relay` produit
  des binaires bit-identiques (Rust release est déterministe)
- Si toujours fail : ouvre une issue, on investigue

---

## Pourquoi cette friction ?

**Pourquoi ne pas embarquer `nostr-rs-relay` directement dans le
binaire `infinity-node` ?**
- `+30 MB` au binaire principal pour une dépendance qu'on délègue
- Couplage fort à une version précise de `nostr-rs-relay`
- Plus dur à auditer (qui a compilé quoi quand)

L'auto-download avec verify SHA-256 + auto-PR pour les hashes est
le meilleur compromis : binaire compagnon léger, dépendance externe
auditable, mises à jour de `nostr-rs-relay` sans recompiler le
companion.

---

## Références

- Workflow : `.github/workflows/release-relay.yml`
- Auto-installer code : `src/relay_installer.rs`
- Upstream : https://github.com/scsibug/nostr-rs-relay
