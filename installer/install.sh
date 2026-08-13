#!/bin/sh
# Netherchat installer — installs the `netherchat` terminal client.
#
#   curl -fsSL https://netherchat.com/install | bash
#   curl -fsSL https://netherchat.com/install | bash -s -- --with-server
#
# The unpinned form installs the latest release; pass --version to pin one, and
# --with-server to also install the relay. See Options below.
#
# Netherchat is two artifacts: the endpoint client (installed by default) and the
# netherchat-server relay. --with-server also installs the relay binary, which
# already ships in the same release archive. POSIX sh — no bashisms — so it runs
# under sh, bash, ash (Alpine) and zsh alike.
#
# Options:
#   --version <v>     install a specific version (default: latest release)
#   --bin-dir <dir>   install into <dir> (default: ~/.local/bin)
#   --with-server     also install the netherchat-server relay binary
#   --uninstall       remove the installed client (and relay, if present)
#   -h, --help        show this help
#
# Honored env vars: NETHERCHAT_VERSION, NETHERCHAT_BIN_DIR, NO_COLOR.

set -eu

REPO="astralis-software-systems/netherchat"
BINARY="netherchat"
SERVER_BINARY="netherchat-server"
VERSION="${NETHERCHAT_VERSION:-latest}"
BIN_DIR="${NETHERCHAT_BIN_DIR:-}"
DO_UNINSTALL=0
DO_SERVER=0

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
  sed -n '2,19p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//' || true
}

# ---- args -------------------------------------------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    --version)   [ $# -ge 2 ] || die "--version needs a value"; VERSION="$2"; shift 2 ;;
    --version=*) VERSION="${1#*=}"; shift ;;
    --bin-dir)   [ $# -ge 2 ] || die "--bin-dir needs a value"; BIN_DIR="$2"; shift 2 ;;
    --bin-dir=*) BIN_DIR="${1#*=}"; shift ;;
    --with-server) DO_SERVER=1; shift ;;
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
  server_target="$BIN_DIR/$SERVER_BINARY"
  if [ -e "$server_target" ]; then
    rm -f "$server_target" && ok "removed $server_target"
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

# Opt-in relay: the server binary already rode down inside this same archive, so
# --with-server installs it with zero extra download. If it is absent (an older
# release), warn and continue — the client install must always succeed.
if [ "$DO_SERVER" -eq 1 ]; then
  if [ -f "$tmp/$SERVER_BINARY" ]; then
    if cp "$tmp/$SERVER_BINARY" "$BIN_DIR/$SERVER_BINARY" 2>/dev/null; then
      chmod 0755 "$BIN_DIR/$SERVER_BINARY"
      ok "installed to $BIN_DIR/$SERVER_BINARY"
    else
      warn "cannot write $SERVER_BINARY to $BIN_DIR — relay not installed (the client is fine)"
    fi
  else
    warn "this release has no $SERVER_BINARY — relay not installed (the client is fine); get it via Docker or 'go build ./cmd/netherchat-server' — see docs/self-hosting.md"
  fi
fi

# ---- PATH hint + next steps -------------------------------------------------
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *)
    warn "$BIN_DIR is not on your PATH"
    printf '    add this to your shell profile:\n      %sexport PATH="%s:$PATH"%s\n' "$C_DIM" "$BIN_DIR" "$C_RST"
    ;;
esac

if [ "$DO_SERVER" -eq 1 ]; then
  printf '\n%sNetherchat %s installed — client + relay.%s  Messaging that lives below the surface.\n' "$C_VIO" "$ver" "$C_RST"
  printf '  %sConnect:%s     netherchat connect ws://localhost:3000 --name "$USER"\n' "$C_DIM" "$C_RST"
  printf '  %sRun a relay:%s netherchat-server --addr :3000   (or: docker run -p 3000:3000 salkreiner/netherchat)\n' "$C_DIM" "$C_RST"
  printf '  %sUninstall:%s   curl -fsSL https://netherchat.com/install | bash -s -- --uninstall\n\n' "$C_DIM" "$C_RST"
else
  printf '\n%sNetherchat %s installed — the endpoint client.%s  Messaging that lives below the surface.\n' "$C_VIO" "$ver" "$C_RST"
  printf '  %sConnect:%s    netherchat connect ws://localhost:3000 --name "$USER"\n' "$C_DIM" "$C_RST"
  printf '  %sSelf-host:%s  re-run with --with-server for the native relay (netherchat-server — already in\n' "$C_DIM" "$C_RST"
  printf '              this release, no extra download), or: docker run -p 3000:3000 salkreiner/netherchat\n'
  printf '  %sUninstall:%s  curl -fsSL https://netherchat.com/install | bash -s -- --uninstall\n\n' "$C_DIM" "$C_RST"
fi
