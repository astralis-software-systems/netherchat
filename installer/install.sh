#!/bin/sh
# Netherchat installer — installs the `netherchat` terminal client.
#
#   curl -fsSL https://netherchat.com/install | bash
#   curl -fsSL https://netherchat.com/install | bash -s -- --version 1.2.0
#
# The server is distributed as a Docker image (salkreiner/netherchat); this script
# installs the client only. POSIX sh — no bashisms — so it runs under sh, bash,
# ash (Alpine) and zsh alike.
#
# Options:
#   --version <v>     install a specific version (default: latest release)
#   --bin-dir <dir>   install into <dir> (default: ~/.local/bin)
#   --uninstall       remove the installed client
#   -h, --help        show this help
#
# Honored env vars: NETHERCHAT_VERSION, NETHERCHAT_BIN_DIR, NO_COLOR.

set -eu

REPO="salehkreiner/netherchat"
BINARY="netherchat"
VERSION="${NETHERCHAT_VERSION:-latest}"
BIN_DIR="${NETHERCHAT_BIN_DIR:-}"
DO_UNINSTALL=0

# ---- pretty output ----------------------------------------------------------
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_RST=$(printf '\033[0m'); C_DIM=$(printf '\033[2m')
  C_GRN=$(printf '\033[32m'); C_YEL=$(printf '\033[33m')
  C_RED=$(printf '\033[31m'); C_VIO=$(printf '\033[35m')
else
  C_RST=''; C_DIM=''; C_GRN=''; C_YEL=''; C_RED=''; C_VIO=''
fi
step() { printf '%s›%s %s\n' "$C_VIO" "$C_RST" "$1"; }
ok()   { printf '  %s✓%s %s\n' "$C_GRN" "$C_RST" "$1"; }
warn() { printf '  %s!%s %s\n' "$C_YEL" "$C_RST" "$1" >&2; }
die()  { printf '%serror:%s %s\n' "$C_RED" "$C_RST" "$1" >&2; exit 1; }

usage() {
  sed -n '2,16p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//' || true
}

# ---- args -------------------------------------------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    --version)   [ $# -ge 2 ] || die "--version needs a value"; VERSION="$2"; shift 2 ;;
    --version=*) VERSION="${1#*=}"; shift ;;
    --bin-dir)   [ $# -ge 2 ] || die "--bin-dir needs a value"; BIN_DIR="$2"; shift 2 ;;
    --bin-dir=*) BIN_DIR="${1#*=}"; shift ;;
    --uninstall) DO_UNINSTALL=1; shift ;;
    -h|--help)   usage; exit 0 ;;
    *)           die "unknown option: $1 (try --help)" ;;
  esac
done

# ---- helpers ----------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }

# fetch URL -> stdout ; download URL FILE -> file
if have curl; then
  fetch()    { curl -fsSL "$1"; }
  download() { curl -fsSL -o "$2" "$1"; }
elif have wget; then
  fetch()    { wget -qO- "$1"; }
  download() { wget -qO "$2" "$1"; }
else
  die "need curl or wget to download Netherchat"
fi

sha256_of() {
  if have sha256sum; then sha256sum "$1" | awk '{print $1}'
  elif have shasum;  then shasum -a 256 "$1" | awk '{print $1}'
  else return 1
  fi
}

detect_bin_dir() {
  if [ -n "$BIN_DIR" ]; then return; fi
  BIN_DIR="$HOME/.local/bin"
}

# ---- uninstall --------------------------------------------------------------
if [ "$DO_UNINSTALL" -eq 1 ]; then
  detect_bin_dir
  target="$BIN_DIR/$BINARY"
  if [ -e "$target" ]; then
    rm -f "$target" && ok "removed $target"
  else
    warn "no $BINARY found in $BIN_DIR — nothing to do"
  fi
  exit 0
fi

# ---- platform ---------------------------------------------------------------
step "Detecting platform"
os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in
  linux)  os=linux ;;
  darwin) os=darwin ;;
  *) die "unsupported OS '$os' — Netherchat supports Linux and macOS here; on Windows run installer/install.ps1" ;;
esac
arch=$(uname -m)
case "$arch" in
  x86_64|amd64)  arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) die "unsupported architecture '$arch'" ;;
esac
ok "$os/$arch"

# ---- resolve version --------------------------------------------------------
step "Resolving release"
if [ "$VERSION" = "latest" ]; then
  tag=$(fetch "https://api.github.com/repos/$REPO/releases/latest" \
        | grep '"tag_name"' | head -1 \
        | sed -e 's/.*"tag_name":[[:space:]]*"//' -e 's/".*//')
  [ -n "$tag" ] || die "could not resolve the latest release (is the repo published yet?)"
else
  tag="v${VERSION#v}"
fi
ver="${tag#v}"
ok "netherchat $ver"

# ---- download + verify ------------------------------------------------------
archive="${BINARY}_${os}_${arch}.tar.gz"
base="https://github.com/$REPO/releases/download/$tag"
tmp=$(mktemp -d 2>/dev/null || mktemp -d -t netherchat)
trap 'rm -rf "$tmp"' EXIT INT TERM

step "Downloading $archive"
download "$base/$archive" "$tmp/$archive" || die "download failed: $base/$archive"
ok "downloaded"

step "Verifying checksum"
if download "$base/checksums.txt" "$tmp/checksums.txt" 2>/dev/null; then
  actual=$(sha256_of "$tmp/$archive" || true)
  expected=$(grep " ${archive}\$" "$tmp/checksums.txt" | awk '{print $1}' | head -1 || true)
  if [ -z "$actual" ]; then
    warn "no sha256 tool found — skipping verification"
  elif [ -z "$expected" ]; then
    warn "no checksum entry for $archive — skipping verification"
  elif [ "$actual" != "$expected" ]; then
    die "checksum mismatch for $archive (expected $expected, got $actual)"
  else
    ok "sha256 verified"
  fi
else
  warn "checksums.txt unavailable — skipping verification"
fi

# ---- extract + install ------------------------------------------------------
step "Installing"
tar -xzf "$tmp/$archive" -C "$tmp" || die "failed to extract $archive"
[ -f "$tmp/$BINARY" ] || die "archive did not contain a '$BINARY' binary"

detect_bin_dir
mkdir -p "$BIN_DIR" 2>/dev/null || die "cannot create $BIN_DIR"
if ! cp "$tmp/$BINARY" "$BIN_DIR/$BINARY" 2>/dev/null; then
  die "cannot write to $BIN_DIR — re-run with --bin-dir <writable dir>"
fi
chmod 0755 "$BIN_DIR/$BINARY"
ok "installed to $BIN_DIR/$BINARY"

# ---- PATH hint + next steps -------------------------------------------------
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *)
    warn "$BIN_DIR is not on your PATH"
    printf '    add this to your shell profile:\n      %sexport PATH="%s:$PATH"%s\n' "$C_DIM" "$BIN_DIR" "$C_RST"
    ;;
esac

printf '\n%sNetherchat %s installed.%s  Messaging that lives below the surface.\n' "$C_VIO" "$ver" "$C_RST"
printf '  %sConnect:%s   netherchat connect ws://localhost:3000 --name "$USER"\n' "$C_DIM" "$C_RST"
printf '  %sRun a server:%s docker run -p 3000:3000 salkreiner/netherchat\n' "$C_DIM" "$C_RST"
printf '  %sUninstall:%s curl -fsSL https://netherchat.com/install | bash -s -- --uninstall\n\n' "$C_DIM" "$C_RST"
