#!/usr/bin/env bash
# Entry point Go yang reproducible untuk repo ini.
# Urutan toolchain: PAM_GOROOT -> ./.toolchain/go -> go di PATH.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GOROOT_DIR="${PAM_GOROOT:-$ROOT/.toolchain/go}"
if [[ -x "$GOROOT_DIR/bin/go" ]]; then
  export GOROOT="$GOROOT_DIR"
  export PATH="$GOROOT/bin:$PATH"
  export GOCACHE="${PAM_GOCACHE:-$ROOT/.toolchain/go-cache}"
  export GOMODCACHE="${PAM_GOMODCACHE:-$ROOT/.toolchain/go-mod}"
elif ! command -v go >/dev/null 2>&1; then
  echo "Go toolchain tidak ditemukan. Set PAM_GOROOT, pasang di .toolchain/go," >&2
  echo "atau pasang go1.27.4 di PATH: https://go.dev/dl/" >&2
  exit 1
fi
exec go "$@"
