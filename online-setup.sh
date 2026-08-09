#!/usr/bin/env bash
set -euo pipefail

REPO_OWNER="Minosuko"
REPO_NAME="FoxyDB-server"
FOXYDB_BRANCH="${FOXYDB_BRANCH:-main}"

log2() { echo "[setup-online] $*"; }
die()  { echo "[setup-online] ERROR: $*" >&2; exit 1; }

usage() {
    cat <<EOF
FoxyDB one-line server setup.

Usage:
  curl -fsSL https://raw.githubusercontent.com/$REPO_OWNER/$REPO_NAME/refs/heads/$FOXYDB_BRANCH/online-setup.sh | bash
  wget -qO- https://raw.githubusercontent.com/$REPO_OWNER/$REPO_NAME/refs/heads/$FOXYDB_BRANCH/online-setup.sh | bash

It downloads the latest server package from GitHub, extracts it and runs
setup-server.sh (installs PHP, the foxydb user, systemd/SysV service and
hardens the default account) fully automatically. Requires curl or wget,
tar, and root access (sudo is used when needed).

Optional environment variables:
  FOXYDB_BRANCH    Git branch or tag to fetch (default: main)
  FOXYDB_HOST      Bind address      (equivalent of --host)
  FOXYDB_PORT      Listen port       (equivalent of --port)
  FOXYDB_DATA_DIR  Data directory    (equivalent of --data-dir)
  FOXYDB_LOG_DIR   Log directory     (equivalent of --log-dir)
  FOXYDB_APP_DIR   Install directory (equivalent of --app-dir)
  FOXYDB_USER      System user       (equivalent of --user)

With 'bash -s --' you can also pass setup-server.sh options directly:
  curl -fsSL <url> | bash -s -- --host=0.0.0.0 --port=2002
EOF
}

case "${1:-}" in
    -h|--help|help) usage; exit 0 ;;
esac

has() { command -v "$1" >/dev/null 2>&1; }

if ! has curl && ! has wget; then
    die "neither curl nor wget is installed.

Install one of them and re-run:
  Debian/Ubuntu:  apt-get install -y curl
  RHEL/Fedora:    dnf install -y curl
  Alpine:         apk add curl"
fi

command -v tar >/dev/null 2>&1 || die "tar is required but not installed."

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

download() {
    local url="$1" dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 3 "$url" -o "$dest"
    else
        wget -q --tries=3 "$url" -O "$dest"
    fi
}

TARBALL="$WORK_DIR/foxydb-server.tar.gz"
URL="https://codeload.github.com/$REPO_OWNER/$REPO_NAME/tar.gz/refs/heads/$FOXYDB_BRANCH"
log2 "Downloading $REPO_OWNER/$REPO_NAME ($FOXYDB_BRANCH) ..."
if ! download "$URL" "$TARBALL"; then
    [[ "$FOXYDB_BRANCH" == "main" ]] && download "https://codeload.github.com/$REPO_OWNER/$REPO_NAME/tar.gz/refs/heads/master" "$TARBALL" \
        || die "failed to download $URL"
fi
[[ -s "$TARBALL" ]] || die "downloaded archive is empty."

log2 "Extracting archive ..."
tar -xzf "$TARBALL" -C "$WORK_DIR" || die "failed to extract the archive (is tar installed?)."

SETUP_SCRIPT="$(find "$WORK_DIR" -maxdepth 2 -type f -name setup-server.sh -print -quit)"
[[ -n "$SETUP_SCRIPT" ]] || die "setup-server.sh not found inside the archive."

SETUP_DIR="$(dirname "$SETUP_SCRIPT")"

args=()
[[ -n "${FOXYDB_HOST:-}" ]]      && args+=(--host="$FOXYDB_HOST")
[[ -n "${FOXYDB_PORT:-}" ]]      && args+=(--port="$FOXYDB_PORT")
[[ -n "${FOXYDB_DATA_DIR:-}" ]]  && args+=(--data-dir="$FOXYDB_DATA_DIR")
[[ -n "${FOXYDB_LOG_DIR:-}" ]]   && args+=(--log-dir="$FOXYDB_LOG_DIR")
[[ -n "${FOXYDB_APP_DIR:-}" ]]   && args+=(--app-dir="$FOXYDB_APP_DIR")
[[ -n "${FOXYDB_USER:-}" ]]      && args+=(--user="$FOXYDB_USER")

log2 "running setup-server.sh ..."
bash "$SETUP_SCRIPT" "${args[@]}" "$@"
status=$?
rm -rf "$WORK_DIR"
exit $status