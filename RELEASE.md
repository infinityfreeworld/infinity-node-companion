# Release process — Infinity Node

Documentation de comment publier une nouvelle version du companion
avec les 3 installeurs natifs (.dmg / .msi / .AppImage) automatisés
via GitHub Actions.

## Pré-requis (une seule fois)

1. **Push le repo sur GitHub** (public ou privé avec budget Actions)
2. **Adapter `src/modules/coeur-cube/hud-cdc/install-config.ts`** :
   - Remplace `INFINITY_OWNER/INFINITY_REPO` par le vrai owner/repo
3. **Vérifier les permissions Actions** :
   - Settings → Actions → General → Workflow permissions
   - Coche « Read and write permissions » (pour créer les Releases)

## Publier une release

```bash
# Depuis la racine du repo principal infinity/
git tag v0.1.0
git push origin v0.1.0
```

Le workflow `.github/workflows/release-infinity-node.yml` se déclenche
automatiquement et :

1. Build le binaire pour macOS (universel arm64+x86_64), Windows, Linux
2. Empaquette en `.dmg` / `.msi` / `.AppImage`
3. Crée un GitHub Release avec les 3 artefacts attachés
4. Génère les release notes automatiquement depuis les commits

Durée totale : **~10-15 minutes** (jobs parallèles).

## Vérifier le résultat

Une fois le workflow terminé, va sur :

```
https://github.com/<owner>/<repo>/releases/latest
```

Tu dois voir 3 assets :
- `Infinity-Node-mac.dmg`
- `Infinity-Node-win.msi`
- `Infinity-Node-linux.AppImage`

(Note : actuellement le workflow inclut le tag dans le nom — adapter
`install-config.ts` ou changer la stratégie de naming si besoin.)

## Workflow localement (optionnel)

Tu peux tester un build manuel sans déclencher le workflow :

```bash
# macOS — installe cargo-bundle une fois
cargo install cargo-bundle --locked
cd infinity-node
cargo bundle --release
# Le .app est dans target/release/bundle/osx/

# Windows — installe cargo-wix une fois
cargo install cargo-wix --locked
cd infinity-node
cargo wix init --force   # 1ère fois uniquement
cargo wix
# Le .msi est dans target/wix/

# Linux — appimagetool standalone
wget https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage
chmod +x appimagetool-x86_64.AppImage
# Puis voir les commandes dans .github/workflows/release-infinity-node.yml
```

## Code signing (optionnel, payant)

Sans signing, l'utilisateur voit **1 warning à bypasser la 1ʳᵉ fois**
sur macOS (Gatekeeper) et Windows (SmartScreen). Linux n'est pas
concerné.

Pour zéro warning :
- **macOS** : compte [Apple Developer Program](https://developer.apple.com/programs/) ($99/an)
  + ajouter `codesign` + `xcrun notarytool` dans le workflow
- **Windows** : EV Code Signing Certificate ($200-400/an chez DigiCert,
  Sectigo, etc.)
  + signer le .msi avec `signtool`

À faire seulement quand le projet sortira en bêta publique.

## Icônes

Le workflow utilise actuellement des icônes génériques. Pour fournir
une vraie icône :

1. Crée un PNG 1024×1024 → `infinity-node/icon.png`
2. Décommente `icon = ["icon.png"]` dans `Cargo.toml` (`[package.metadata.bundle]`)
3. Pour Windows, génère un .ico à partir du PNG et configure dans `[package.metadata.wix]`
4. Pour Linux, place un PNG 256×256 nommé `infinity-node.png` (le workflow l'utilise déjà via convert/imagemagick)

## Troubleshooting

- **Build mac universal échoue** : le `lipo` requiert les 2 cibles. Si
  problème, build chaque arch séparément et release 2 .dmg distincts.
- **WiX initialization** : la 1ʳᵉ fois génère `infinity-node/wix/main.wxs`
  qui doit être commité au repo pour les builds suivants.
- **AppImage permission denied** : `appimagetool` lui-même est un
  AppImage qui peut nécessiter `--appimage-extract-and-run` sur les
  runners GitHub Actions sans FUSE.
