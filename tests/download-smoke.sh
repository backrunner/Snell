#!/usr/bin/env bash
# 需联网的 Linux 验证：下载官方 v6、启动真实进程并验证监听。
set -eu
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck disable=SC1091
source "$ROOT/Snell.sh"
WORK_DIR=$(mktemp -d)
server_pid=""
cleanup() {
    if [ -n "$server_pid" ]; then kill "$server_pid" 2>/dev/null || true; wait "$server_pid" 2>/dev/null || true; fi
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT
install_snell_binary "$(uname -m)" v6.0.0 6 "$WORK_DIR/bin" ''
SNELL_BIN="$WORK_DIR/bin/snell-server"
[ "$(get_installed_version)" = v6.0.0 ]
CONF_FILE="$WORK_DIR/snell.conf"
cat > "$CONF_FILE" <<'CONFIG'
[snell-server]
listen = 0.0.0.0:37177,[::]:37177
psk = abcdefghijklmnopqrstuvwxyz123456
dns = 1.1.1.1, 8.8.8.8
ipv6 = true
CONFIG
"$SNELL_BIN" -c "$CONF_FILE" > "$WORK_DIR/server.log" 2>&1 &
server_pid=$!
sleep 2
kill -0 "$server_pid" || { cat "$WORK_DIR/server.log"; exit 1; }
python3 - <<'SOCKETS'
import socket
for family, address in [(socket.AF_INET, ('127.0.0.1', 37177)), (socket.AF_INET6, ('::1', 37177))]:
    with socket.socket(family) as sock:
        sock.settimeout(3)
        sock.connect(address)
        print('Connected:', address)
SOCKETS
cat "$WORK_DIR/server.log"
printf 'Official Snell v6.0.0 download, version and dual-stack startup: PASS\n'
