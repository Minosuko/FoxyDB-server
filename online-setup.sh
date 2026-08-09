#!/usr/bin/env bash
set -euo pipefail

PROG_NAME="${0##*/}"
REPO_OWNER="Minosuko"
REPO_NAME="FoxyDB-server"
FOXYDB_BRANCH="${FOXYDB_BRANCH:-main}"
BASE_URL="https://github.com/$REPO_OWNER/$REPO_NAME/raw/$FOXYDB_BRANCH/setup-server.sh"

usage() {
    cat <<EOF
Usage: bash $PROG_NAME [setup-server options]

Downloads the latest FoxyDB-server from GitHub and runs setup-server.sh,
passing every argument through to it.

Environment:
  FOXYDB_BRANCH    Git branch or tag to fetch (default: main)

Examples:
  bash $PROG_NAME
  bash $PROG_NAME --host=0.0.0.0 --port=2002
  sudo FOXYDB_BRANCH=v1.0 bash $PROG_NAME --skip-secure
EOF
}

log2() { echo "[online] $*"; }
die()  { echo "[online] ERROR: $*" >&2; exit 1; }

for arg in "$@"; do
    case "$arg" in
        -h|--help|help) usage; exit 0 ;;
    esac
done

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

log2 "Fetching setup-server.sh from $BASE_URL ..."
if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 3 "$BASE_URL" -o "$WORK_DIR/setup-server.sh" || die "download failed (curl)"
elif command -v wget >/dev/null 2>&1; then
    wget -q --tries=3 "$BASE_URL" -O "$WORK_DIR/setup-server.sh" || die "download failed (wget)"
else
    die "neither curl nor wget is installed. Install one of them and re-run."
fi
[[ -s "$WORK_DIR/setup-server.sh" ]] || die "downloaded setup-server.sh is empty"
log2 "Running setup-server.sh ..."
exec bash "$WORK_DIR/setup-server.sh" "$@"