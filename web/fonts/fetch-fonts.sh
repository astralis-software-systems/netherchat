#!/bin/sh
# Fetch the self-hosted brand fonts into web/public/fonts/. OFL 1.1, official
# release CDNs (jsDelivr mirrors of the upstream GitHub releases). Run once.
set -eu

# Create the directory BEFORE resolving it. On a fresh checkout web/public/fonts
# does not exist — that is the whole state this script is here to fix — so cd-ing
# into it first made the script fail on line 1 of its job, on exactly the machine
# that needed it. The .ps1 alongside always got this right (New-Item -Force), which
# is why the gap survived unnoticed on Windows.
WEB="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
DEST="$WEB/public/fonts"
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
