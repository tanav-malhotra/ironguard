#!/usr/bin/env bash
set -euo pipefail

BANNER="
██╗██████╗  ██████╗ ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
██║██╔══██╗██╔═══██╗████╗  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
██║██████╔╝██║   ██║██╔██╗ ██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
██║██╔══██╗██║   ██║██║╚██╗██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
██║██║  ██║╚██████╔╝██║ ╚████║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
"

printf "%s\n" "$BANNER"

if [[ $EUID -ne 0 ]]; then
  echo "[!] This installer must be run with sudo/root." >&2
  exit 1
fi

REPO_DEFAULT="tanav-malhotra/ironguard"
REPO="${IRONGUARD_REPO:-$REPO_DEFAULT}"
FROM_SOURCE=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --from-source) FROM_SOURCE=1; shift;;
    --repo) REPO="$2"; shift 2;;
    *) echo "[!] Unknown arg: $1" >&2; exit 1;;
  esac
done

API="https://api.github.com/repos/${REPO}/releases/latest"
ASSET_OS="linux"
ARCH=$(uname -m)
if [[ "$ARCH" != "x86_64" && "$ARCH" != "amd64" ]]; then
  echo "[!] Only 64-bit x86_64 is supported. Detected: $ARCH" >&2
  exit 1
fi
ASSET_ARCH="x86_64"

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

BIN_PATH="/usr/local/bin"

download_release() {
  echo "[*] Fetching latest release metadata from $REPO..."
  URL=$(curl -fsSL "$API" | grep -oE "https://[^"]+${ASSET_OS}-${ASSET_ARCH}[^"]*" | head -n1 || true)
  if [[ -z "${URL:-}" ]]; then
    return 1
  fi
  echo "[*] Downloading: $URL"
  ASSET_PATH="$TMPDIR/asset"
  curl -fsSL "$URL" -o "$ASSET_PATH"
  BIN_SRC=""
  if [[ "$URL" =~ \.tar\.gz$ || "$URL" =~ \.tgz$ ]]; then
    echo "[*] Unpacking tar.gz..."
    tar -xzf "$ASSET_PATH" -C "$TMPDIR"
    BIN_SRC=$(find "$TMPDIR" -maxdepth 2 -type f -name 'ironguard*' | head -n1 || true)
    if [[ -z "$BIN_SRC" ]]; then
      BIN_SRC=$(find "$TMPDIR" -maxdepth 2 -type f -perm -u+x | head -n1 || true)
    fi
  else
    BIN_SRC="$ASSET_PATH"
  fi
  if [[ -z "$BIN_SRC" ]]; then
    echo "[!] Could not locate binary in archive." >&2
    return 1
  fi
  chmod +x "$BIN_SRC" || true
  install -m 0755 "$BIN_SRC" "$BIN_PATH/ironguard"
}

build_from_source() {
  echo "[*] Building from source..."
  if ! command -v cargo >/dev/null 2>&1; then
    echo "[!] cargo not found. Install Rust via https://rustup.rs and retry, or use releases." >&2
    exit 1
  fi
  SRC_DIR="$TMPDIR/src"
  git clone --depth 1 "https://github.com/${REPO}.git" "$SRC_DIR"
  (cd "$SRC_DIR" && cargo build --release)
  install -m 0755 "$SRC_DIR/target/release/ironguard" "$BIN_PATH/ironguard"
}

if [[ $FROM_SOURCE -eq 1 ]]; then
  build_from_source
else
  if ! download_release; then
    echo "[!] Release download failed; falling back to source build..."
    build_from_source
  fi
fi

echo "[*] Installed to $BIN_PATH/ironguard"

if ! command -v ironguard >/dev/null 2>&1; then
  echo "[!] ironguard not found in PATH. Add $BIN_PATH to PATH and retry." >&2
  exit 1
fi

echo "[*] Verifying..."
ironguard --help || true

echo "[+] Done. Run 'ironguard init' next."
