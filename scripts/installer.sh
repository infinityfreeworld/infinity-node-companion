#!/usr/bin/env bash
# Installe le binaire fraîchement bâti dans /Applications/Infinity Node.app,
# en une commande — parce que la manœuvre (quitter, sauvegarder, copier,
# relancer, vérifier) s'est faite quatre fois à la main en deux jours, et
# qu'une étape oubliée donne un nœud qui tourne sur l'ANCIEN code sans que
# rien ne le signale.
#
#   ./scripts/installer.sh              # bâtit en release puis installe
#   ./scripts/installer.sh --sans-build # installe le binaire déjà bâti
#
set -euo pipefail

RACINE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINAIRE="$RACINE/target/release/infinity-node"
APP="/Applications/Infinity Node.app"
CIBLE="$APP/Contents/MacOS/infinity-node"
SAUVEGARDES="$HOME/.infinity-node/sauvegarde-binaire"
PORT="${INFINITY_PORT:-7474}"

if [[ "${1:-}" != "--sans-build" ]]; then
  echo "▸ compilation release…"
  ( cd "$RACINE" && cargo build --release )
fi

[[ -f "$BINAIRE" ]]  || { echo "✗ binaire absent : $BINAIRE"; exit 1; }
[[ -d "$APP" ]]      || { echo "✗ application absente : $APP"; exit 1; }

# ⚠️ Un `cargo build` interrompu laisse l'ANCIEN binaire en place, daté d'une
# autre session : on refuse d'installer ce qu'on n'a pas bâti à l'instant.
if [[ "${1:-}" != "--sans-build" ]] && [[ -n "$(find "$BINAIRE" -mmin +10)" ]]; then
  echo "✗ le binaire a plus de 10 minutes — la compilation n'a rien produit."
  exit 1
fi

empreinte() { codesign -dvvv "$1" 2>&1 | awk '/CandidateCDHash /{print $2}'; }
echo "▸ installé : $(empreinte "$CIBLE")"
echo "▸ nouveau  : $(empreinte "$BINAIRE")"

horodatage="$(date +%Y%m%d-%H%M)"
mkdir -p "$SAUVEGARDES"
cp "$CIBLE" "$SAUVEGARDES/infinity-node.avant-$horodatage"
echo "▸ sauvegarde : $SAUVEGARDES/infinity-node.avant-$horodatage"

# Rotation : 6,8 Mo par installation, et on installe plusieurs fois par jour
# pendant un chantier — 39 Mo s'étaient déjà accumulés en deux jours.
# ⚠️ Le motif ne vise QUE nos sauvegardes automatiques (`avant-<date>`) :
# celles nommées à la main (`avant-ui-…`, `avant-held-…`) sont des points de
# retour choisis, elles ne se suppriment pas toutes seules.
ls -t "$SAUVEGARDES"/infinity-node.avant-2[0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9] 2>/dev/null \
  | tail -n +4 | while read -r vieille; do
      echo "  ↳ purge $(basename "$vieille")"
      rm -f "$vieille"
    done

echo "▸ arrêt du nœud…"
osascript -e 'tell application "Infinity Node" to quit' >/dev/null 2>&1 || true
for _ in $(seq 1 20); do
  pgrep -f "Infinity Node.app/Contents/MacOS/infinity-node" >/dev/null || break
  sleep 0.5
done
pgrep -f "Infinity Node.app/Contents/MacOS/infinity-node" >/dev/null \
  && { echo "✗ le nœud refuse de s'arrêter — installe à la main"; exit 1; }

cp "$BINAIRE" "$CIBLE"
echo "▸ copié. Relancement…"
open -a "Infinity Node"

# Le nœud sert son état d'amorçage AVANT d'être prêt : on s'en sert pour dire
# ce qu'on attend, au lieu d'afficher un point d'interrogation pendant 40 s.
echo "▸ attente du démarrage (le trousseau va redemander l'autorisation)…"
for i in $(seq 1 120); do
  if curl -fsS -m 2 "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; then
    echo "✓ nœud prêt — http://127.0.0.1:$PORT/ui"
    echo "  empreinte servie : $(empreinte "$CIBLE")"
    exit 0
  fi
  etat="$(curl -fsS -m 2 "http://127.0.0.1:$PORT/api/amorcage" 2>/dev/null || true)"
  if [[ -n "$etat" ]] && (( i % 6 == 0 )); then
    echo "  … $(echo "$etat" | sed 's/.*"libelle":"\([^"]*\)".*/\1/')"
    if echo "$etat" | grep -q '"explication":"[^n]'; then
      echo "  ⚠ $(echo "$etat" | sed 's/.*"explication":"\([^"]*\)".*/\1/')"
    fi
  fi
  sleep 1
done
echo "✗ toujours pas de réponse après 2 min — regarde http://127.0.0.1:$PORT/ui"
exit 1
