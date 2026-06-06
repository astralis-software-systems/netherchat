#!/bin/sh
# Fetch the self-hosted brand fonts into web/public/fonts/. OFL 1.1, official
# release CDNs (jsDelivr mirrors of the upstream GitHub releases). Run once.
set -eu

DEST="$(CDPATH= cd -- "$(dirname -- "$0")/../public/fonts" && pwd)"
mkdir -p "$DEST"

get() {
  url="$1"; out="$2"
  echo "  $out"
  if command -v curl >/dev/null 2>&1; then curl -fsSL "$url" -o "$DEST/$out"
  else wget -qO "$DEST/$out" "$url"; fi
}

echo "Fetching brand fonts into $DEST"

# Space Grotesk (UI)
SG="https://cdn.jsdelivr.net/fontsource/fonts/space-grotesk@latest/latin-400-normal.woff2"
get "$SG" "SpaceGrotesk-Regular.woff2"
get "https://cdn.jsdelivr.net/fontsource/fonts/space-grotesk@latest/latin-500-normal.woff2" "SpaceGrotesk-Medium.woff2"
get "https://cdn.jsdelivr.net/fontsource/fonts/space-grotesk@latest/latin-600-normal.woff2" "SpaceGrotesk-SemiBold.woff2"

# JetBrains Mono
get "https://cdn.jsdelivr.net/fontsource/fonts/jetbrains-mono@latest/latin-400-normal.woff2" "JetBrainsMono-Regular.woff2"
get "https://cdn.jsdelivr.net/fontsource/fonts/jetbrains-mono@latest/latin-500-normal.woff2" "JetBrainsMono-Medium.woff2"

# IBM Plex Mono (ghost theme)
get "https://cdn.jsdelivr.net/fontsource/fonts/ibm-plex-mono@latest/latin-400-normal.woff2" "IBMPlexMono-Regular.woff2"

# Fira Code (sprinkles theme)
get "https://cdn.jsdelivr.net/fontsource/fonts/fira-code@latest/latin-400-normal.woff2" "FiraCode-Regular.woff2"

echo "Done. These files are gitignored; they ship with the Vite build."
