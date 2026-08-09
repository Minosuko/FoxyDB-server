#!/usr/bin/env bash
set -euo pipefail

PROG_NAME="${0##*/}"
APP_NAME="foxydb"
APP_USER="foxydb"
APP_GROUP="foxydb"
APP_DIR="/opt/foxydb"
DATA_DIR="/var/lib/foxydb"
LOG_DIR="/var/log/foxydb"
CFG_DIR="/etc/foxydb"
HOST="127.0.0.1"
PORT="2002"
PHP_BIN=""
ACTION="setup"
FORCE=0
PURGE_DATA=0
SECURE_PASSWORD=""
SKIP_SECURE=0

usage() {
    cat <<EOF
Usage: bash $PROG_NAME [command] [options]

Commands:
  setup (default)      Install or update FoxyDB and (re)create services
  start                Start the FoxyDB service
  stop                 Stop the FoxyDB service
  restart              Restart the FoxyDB service
  status               Show the FoxyDB service status
  uninstall            Remove FoxyDB application, services and user
  help                 Show this help

Options:
  --host=ADDRESS       Bind address (default: 127.0.0.1)
  --port=NUMBER        Listen port    (default: 2002)
  --data-dir=PATH      Data directory (default: /var/lib/foxydb)
  --log-dir=PATH       Log directory  (default: /var/log/foxydb)
  --app-dir=PATH       Install directory of server files (default: /opt/foxydb)
  --user=NAME          Dedicated system user (default: foxydb)
  --php=PATH           Existing php binary to use, skips package install
  --secure-password=P  Set root password during install instead of a generated one
  --skip-secure        Do not run the secure installation step
  --force              Do not ask for confirmation
  --purge              With uninstall also remove data and log directories

Examples:
  sudo bash $PROG_NAME
  sudo bash $PROG_NAME --host=0.0.0.0 --port=2002
  sudo bash $PROG_NAME --uninstall --purge
EOF
}

log2()  { echo "[setup] $*"; }
warn()  { echo "[setup] WARNING: $*" >&2; }
die()   { echo "[setup] ERROR: $*" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -f "$SCRIPT_DIR/bin/foxydb.php" ]] || die "setup-server.sh must be run from inside the FoxyDB-server package (missing bin/foxydb.php)."

confirm() {
    [[ $FORCE -eq 1 ]] && return 0
    [[ ! -t 0 ]] && return 0
    local reply
    read -r -p "$1 [y/N] " reply
    [[ "${reply,,}" =~ ^(y|yes)$ ]]
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            setup|install)   ACTION="setup" ;;
            start)           ACTION="start" ;;
            stop)            ACTION="stop" ;;
            restart)         ACTION="restart" ;;
            status)          ACTION="status" ;;
            uninstall)       ACTION="uninstall" ;;
            help|-h|--help)  usage; exit 0 ;;
            --host=*)        HOST="${1#*=}" ;;
            --port=*)        PORT="${1#*=}" ;;
            --data-dir=*)    DATA_DIR="${1#*=}" ;;
            --log-dir=*)     LOG_DIR="${1#*=}" ;;
            --app-dir=*)     APP_DIR="${1#*=}" ;;
            --user=*)        APP_USER="${1#*=}"; APP_GROUP="${1#*=}" ;;
            --php=*)         PHP_BIN="${1#*=}" ;;
            --secure-password=*) SECURE_PASSWORD="${1#*=}" ;;
            --skip-secure)   SKIP_SECURE=1 ;;
            --force|-y)      FORCE=1 ;;
            --purge)         PURGE_DATA=1 ;;
            *)               die "unknown argument: $1 (see --help)" ;;
        esac
        shift
    done
}

detect_package_manager() {
    PM="unknown"
    command -v apt-get >/dev/null 2>&1 && { PM="apt"; return; }
    command -v dnf     >/dev/null 2>&1 && { PM="dnf"; return; }
    command -v yum     >/dev/null 2>&1 && { PM="yum"; return; }
    command -v zypper  >/dev/null 2>&1 && { PM="zypper"; return; }
    command -v pacman  >/dev/null 2>&1 && { PM="pacman"; return; }
    command -v apk     >/dev/null 2>&1 && { PM="apk"; return; }
}

check_php() {
    if [[ -z "$PHP_BIN" ]]; then
        PHP_BIN="$(command -v php || true)"
    fi
    [[ -n "$PHP_BIN" ]] || return 1
    local ver ok=0
    ver="$( "$PHP_BIN" -r 'echo PHP_VERSION_ID;' 2>/dev/null || echo 0 )"
    [[ "$ver" -ge 70100 ]] || return 2
    "$PHP_BIN" -r 'foreach (["json","mbstring","openssl","zlib"] as $e) { if (!extension_loaded($e)) { exit(1); } }' 2>/dev/null && ok=1
    [[ "$ok" == "1" ]] || return 3
    return 0
}

warn_32bit() {
    local size
    size="$( "$PHP_BIN" -r 'echo PHP_INT_SIZE;' 2>/dev/null || echo 0 )"
    if [[ "$size" != "8" ]]; then
        warn "32-bit PHP detected (PHP_INT_SIZE=$size). The FoxyDB daemon expects 64-bit integers;" \
            "the binary protocol and storage codecs may fail at runtime on this build."
    fi
}

install_php() {
    local rc=0
    check_php || rc=$?
    if [[ $rc -eq 0 ]]; then
        log2 "Using existing PHP: $("$PHP_BIN" -v | head -n 1)"
        warn_32bit
        return 0
    fi
    detect_package_manager
    log2 "Installing PHP and required extensions via $PM..."
    case "$PM" in
        apt)
            apt-get update || true
            apt-get install -y php-cli php-mbstring \
                || apt-get install -y php8.3-cli php8.3-mbstring \
                || apt-get install -y php8.2-cli php8.2-mbstring \
                || apt-get install -y php8.1-cli php8.1-mbstring \
                || apt-get install -y php8.0-cli php8.0-mbstring \
                || apt-get install -y php7.4-cli php7.4-mbstring \
                || apt-get install -y php7.3-cli php7.3-mbstring \
                || apt-get install -y php7.2-cli php7.2-mbstring \
                || apt-get install -y php7.1-cli php7.1-mbstring \
                || true
            ;;
        dnf|yum)
            "$PM" install -y php-cli php-mbstring php-common || true
            warn "if PHP 7.1+ is not available, enable the Remi repository (dnf install epel-release -y && dnf module reset php -y && dnf module enable php:remi-8.3 -y)."
            ;;
        zypper)
            zypper --non-interactive install php-cli php-mbstring || true
            ;;
        pacman)
            pacman --noconfirm -Sy php php-mbstring || true
            ;;
        apk)
            apk add --no-cache php php-mbstring php-openssl \
                || apk add --no-cache php83 php83-mbstring \
                || apk add --no-cache php82 php82-mbstring \
                || apk add --no-cache php81 php81-mbstring \
                || apk add --no-cache php80 php80-mbstring \
                || apk add --no-cache php74 php74-mbstring \
                || apk add --no-cache php73 php73-mbstring \
                || apk add --no-cache php72 php72-mbstring \
                || apk add --no-cache php71 php71-mbstring \
                || true
            ;;
        *)
            die "no supported package manager found; install PHP 7.1+ manually and re-run with --php=/path/to/php"
            ;;
    esac
    check_php || rc=$?
    case "$rc" in
        0)  log2 "Using PHP: $("$PHP_BIN" -v | head -n 1)"
            warn_32bit
            ;;
        2)  die "PHP $( "$PHP_BIN" -v 2>/dev/null | head -n 1 ) is too old; FoxyDB requires PHP 7.1 or newer. Install PHP and re-run $0 with --php=/path/to/php" ;;
        3)  die "PHP is missing required extensions json, mbstring, openssl, zlib. Install them (e.g. php-mbstring) and re-run $0 with --php=/path/to/php" ;;
        *)  die "PHP was not found after installation. Install PHP 7.1+ manually and re-run $0 with --php=/path/to/php" ;;
    esac
}

create_user() {
    if ! getent group "$APP_GROUP" >/dev/null 2>&1; then
        groupadd --system "$APP_GROUP" || groupadd "$APP_GROUP"
    fi
    if ! id "$APP_USER" >/dev/null 2>&1; then
        useradd --system --gid "$APP_GROUP" --home-dir "$DATA_DIR" \
            --shell /usr/sbin/nologin "$APP_USER"
    fi
    mkdir -p "$DATA_DIR" "$LOG_DIR" "$CFG_DIR"
    chown -R "$APP_USER":"$APP_GROUP" "$DATA_DIR" "$LOG_DIR"
    chmod 750 "$DATA_DIR" "$LOG_DIR"
}

install_files() {
    mkdir -p "$APP_DIR"
    cp -a "$SCRIPT_DIR"/bin  "$APP_DIR"/
    cp -a "$SCRIPT_DIR"/src  "$APP_DIR"/
    if [[ -d "$SCRIPT_DIR/tests" ]]; then
        cp -a "$SCRIPT_DIR"/tests "$APP_DIR"/
    fi
    if [[ -f "$SCRIPT_DIR/LICENSE" ]]; then
        cp -a "$SCRIPT_DIR"/LICENSE "$APP_DIR"/
    fi
    chown -R root:root "$APP_DIR"
    chmod -R a+rX "$APP_DIR"
}

write_env_file() {
    cat > "$CFG_DIR/server.env" <<EOF
FOXYDB_HOST=$HOST
FOXYDB_PORT=$PORT
FOXYDB_DATA_DIR=$DATA_DIR
FOXYDB_LOG_DIR=$LOG_DIR
EOF
    chmod 640 "$CFG_DIR/server.env"
    chown root:"$APP_GROUP" "$CFG_DIR/server.env" 2>/dev/null || true
}

is_systemd() {
    command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]
}

write_systemd_unit() {
    cat > /etc/systemd/system/foxydb.service <<EOF
[Unit]
Description=FoxyDB database server
Documentation=https://github.com/Minosuko/FoxyDB-server
After=network.target

[Service]
Type=simple
User=$APP_USER
Group=$APP_GROUP
WorkingDirectory=$APP_DIR
EnvironmentFile=-$CFG_DIR/server.env
ExecStart=$PHP_BIN $APP_DIR/bin/foxydb.php
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=$DATA_DIR $LOG_DIR

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable foxydb.service >/dev/null 2>&1 || true
}

write_initd_service() {
    cat > /etc/init.d/foxydb <<EOF
#!/bin/sh
### BEGIN INIT INFO
# Provides:          foxydb
# Required-Start:    \$network \$remote_fs
# Required-Stop:     \$network \$remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: FoxyDB database server
### END INIT INFO

FOXYDB_PID=/run/foxydb.pid
FOXYDB_USER=$APP_USER
FOXYDB_GROUP=$APP_GROUP
FOXYDB_APP=$APP_DIR
FOXYDB_PHP=$PHP_BIN
FOXYDB_DATA=$DATA_DIR
FOXYDB_LOG=$LOG_DIR

start() {
    export FOXYDB_HOST=$HOST
    export FOXYDB_PORT=$PORT
    export FOXYDB_DATA_DIR="\$FOXYDB_DATA"
    export FOXYDB_LOG_DIR="\$FOXYDB_LOG"
    start-stop-daemon --start --background --make-pidfile \
        --pidfile "\$FOXYDB_PID" --chuid "\$FOXYDB_USER:\$FOXYDB_GROUP" \
        --chdir "\$FOXYDB_APP" --exec "\$FOXYDB_PHP" -- "\$FOXYDB_APP/bin/foxydb.php"
}

stop() {
    start-stop-daemon --stop --retry TERM/5/KILL --pidfile "\$FOXYDB_PID" || true
}

case "\$1" in
    start)   start ;;
    stop)    stop ;;
    restart) stop; start ;;
    status)  start-stop-daemon --status --pidfile "\$FOXYDB_PID" || true ;;
    *)       echo "Usage: /etc/init.d/foxydb {start|stop|restart|status}"; exit 1 ;;
esac
exit 0
EOF
    chmod +x /etc/init.d/foxydb
    if command -v update-rc.d >/dev/null 2>&1; then
        update-rc.d foxydb defaults >/dev/null 2>&1 || true
    elif command -v chkconfig >/dev/null 2>&1; then
        chkconfig --add foxydb >/dev/null 2>&1 || true
    fi
}

install_service() {
    mkdir -p "$CFG_DIR"
    write_env_file
    if is_systemd; then
        log2 "Installing systemd service (foxydb.service)..."
        write_systemd_unit
    else
        log2 "systemd not found; installing SysV init script (/etc/init.d/foxydb)..."
        write_initd_service
    fi
}

start_service() {
    if is_systemd; then
        systemctl start foxydb.service
    else
        /etc/init.d/foxydb start
    fi
}

stop_service() {
    if is_systemd; then
        systemctl stop foxydb.service || true
    else
        /etc/init.d/foxydb stop || true
    fi
}

service_status() {
    if is_systemd; then
        systemctl status foxydb.service --no-pager || true
    else
        /etc/init.d/foxydb status || true
    fi
}

wait_until_ready() {
    local i
    local check='exit(@stream_socket_client("tls://'"$HOST"':'"$PORT"'", $e, $s, 1) ? 0 : 1);'
    for i in $(seq 1 60); do
        if "$PHP_BIN" -r "$check" 2>/dev/null; then
            return 0
        fi
        sleep 1
    done
    return 1
}

secure_install() {
    if [[ $SKIP_SECURE -eq 1 ]] || [[ -e "$DATA_DIR/auth.initialized" ]]; then
        log2 "Skipping the secure installation step."
        return 0
    fi
    log2 "Waiting for the daemon to become ready..."
    if ! wait_until_ready; then
        warn "daemon did not become ready in 60s. Run the secure installation manually:"
        warn "  cd $DATA_DIR && php $APP_DIR/bin/foxydb_secure_installation.php --no-defaults --host=$HOST --port=$PORT --ssl-mode=VERIFY_IDENTITY --ssl-ca=$DATA_DIR/tls/server.crt --password"
        return 0
    fi
    local args=(--no-defaults "--host=$HOST" "--port=$PORT"
        "--ssl-mode=VERIFY_IDENTITY" "--ssl-ca=$DATA_DIR/tls/server.crt")
    if [[ -n "$SECURE_PASSWORD" ]]; then
        args+=("--password=$SECURE_PASSWORD")
        log2 "Running secure installation with the provided password..."
    else
        args+=(--use-default)
        log2 "Running secure installation and generating a random root password..."
    fi
    if ( cd "$DATA_DIR" && "$PHP_BIN" "$APP_DIR/bin/foxydb_secure_installation.php" "${args[@]}" \
            > "$CFG_DIR/first-boot.txt" 2>&1 ); then
        cat "$CFG_DIR/first-boot.txt"
        chmod 640 "$CFG_DIR/first-boot.txt"
        chown root:"$APP_GROUP" "$CFG_DIR/first-boot.txt" 2>/dev/null || true
        log2 "Secure installation complete. The root password is printed above and saved in $CFG_DIR/first-boot.txt (remove it after saving)."
    else
        warn "secure installation failed; inspect $CFG_DIR/first-boot.txt and retry manually with bin/foxydb_secure_installation.php."
    fi
}

action_setup() {
    log2 "Installing FoxyDB server to $APP_DIR"
    install_php
    create_user
    install_files
    install_service
    start_service
    secure_install
    cat <<EOF

FoxyDB installed and started.
  Application : $APP_DIR           (service: foxydb)
  Data        : $DATA_DIR
  Logs        : $LOG_DIR
  Config      : $CFG_DIR/server.env
  Listen      : tls://$HOST:$PORT

Manage with:
  systemctl {start|stop|restart|status} foxydb     (systemd)
  /etc/init.d/foxydb {start|stop|restart|status}   (SysV init)
TLS certificate for clients: $DATA_DIR/tls/server.crt
EOF
}

action_uninstall() {
    stop_service
    if is_systemd; then
        systemctl disable foxydb.service >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/foxydb.service
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi
    rm -f /etc/init.d/foxydb /run/foxydb.pid
    rm -rf "$APP_DIR" "$CFG_DIR"
    if [[ $PURGE_DATA -eq 1 ]] && confirm "Remove all FoxyDB data in $DATA_DIR?"; then
        rm -rf "$DATA_DIR" "$LOG_DIR"
    fi
    if id "$APP_USER" >/dev/null 2>&1; then
        userdel "$APP_USER" >/dev/null 2>&1 || true
    fi
    if getent group "$APP_GROUP" >/dev/null 2>&1; then
        groupdel "$APP_GROUP" >/dev/null 2>&1 || true
    fi
    log2 "FoxyDB uninstalled."
}

main() {
    case "$ACTION" in
        start)      start_service ;;
        stop)       stop_service ;;
        restart)    stop_service; start_service ;;
        status)     service_status ;;
        uninstall)
            confirm "Uninstall FoxyDB? Data directory $DATA_DIR is kept unless --purge." || die "aborted"
            action_uninstall
            ;;
        setup)      action_setup ;;
        *)          die "unknown action: $ACTION" ;;
    esac
}

parse_args "$@"

if [[ $EUID -ne 0 ]]; then
    if command -v sudo >/dev/null 2>&1; then
        exec sudo -E bash "$0" "$@"
    fi
    die "$PROG_NAME must be run as root (try: sudo bash $PROG_NAME)."
fi

main
