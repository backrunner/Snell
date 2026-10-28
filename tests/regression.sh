#!/usr/bin/env bash
# 在临时目录测试，不接触宿主机安装或服务。
set -u
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck disable=SC1091
source "$ROOT/Snell.sh"
TEST_DIR=$(mktemp -d)
trap 'rm -rf "$TEST_DIR"' EXIT
export TMPDIR="$TEST_DIR"
mkdir -p "$TEST_DIR/bin" "$TEST_DIR/install"
SNELL_BIN="$TEST_DIR/install/snell-server"
CONF_FILE="$TEST_DIR/snell.conf"
export TEST_DIR
python3 - <<'FIXTURES'
import os, zipfile
from pathlib import Path
root=Path(os.environ['TEST_DIR'])
for name, version in [('v6', 'v6.0.0'), ('v5', 'v5.0.1'), ('wrong', 'v6.0.0b3')]:
    with zipfile.ZipFile(root / (name+'.zip'), 'w') as z:
        z.writestr('snell-server', '#!/bin/sh\necho "snell-server '+version+' (test)"\n')
with zipfile.ZipFile(root/'missing.zip', 'w') as z:
    z.writestr('other-file', 'invalid')
with zipfile.ZipFile(root/'extra.zip', 'w') as z:
    z.writestr('snell-server', '#!/bin/sh\necho "snell-server v6.0.0 (test)"\n')
    z.writestr('../escaped', 'must not be extracted')
(root/'broken.zip').write_text('not a zip')
FIXTURES
# macOS 的 sed 不支持 Linux sed -i，适配仅用于本地测试。
if [ "$(uname -s)" = Darwin ]; then
    sed() { if [ "${1:-}" = -i ]; then shift; command sed -i '' "$@"; else command sed "$@"; fi; }
fi
passed=0
failed=0
check() {
    local name="$1"
    shift
    if ( "$@" ) >"$TEST_DIR/result" 2>&1; then
        passed=$((passed+1)); printf 'ok %s - %s\n' "$passed" "$name"
    else
        failed=$((failed+1)); printf 'FAIL - %s\n' "$name"; cat "$TEST_DIR/result"
    fi
}
assert_equal() { [ "$1" = "$2" ] || { printf 'expected <%s>, got <%s>\n' "$2" "$1"; return 1; }; }
version_default() { SNELL_VERSION=v5.0.1; select_snell_version <<< '' || return 1; assert_equal "$SNELL_VERSION" v6.0.0; }
version_legacy() { select_snell_version <<< 1; assert_equal "$SNELL_PROTOCOL_VERSION" 5; }
version_eof() { ! select_snell_version </dev/null; }
url_checks() {
    local arch
    for arch in x86_64 amd64 i386 i686 aarch64 arm64; do
        get_snell_download_url "$arch" v6.0.0 6 || return 1
    done
    ! get_snell_download_url armv7l v6.0.0 6 && ! get_snell_download_url mips v6.0.0 6
}
install_valid() {
    install_snell_binary aarch64 v6.0.0 6 "$TEST_DIR/install" "$TEST_DIR/v6.zip" || return 1
    assert_equal "$(get_installed_version)" v6.0.0
}
reject_archive() {
    local fixture="$1"
    printf 'old binary' > "$SNELL_BIN"
    if install_snell_binary aarch64 v6.0.0 6 "$TEST_DIR/install" "$TEST_DIR/$fixture.zip"; then return 1; fi
    assert_equal "$(cat "$SNELL_BIN")" 'old binary'
}
archive_extra() {
    install_snell_binary aarch64 v6.0.0 6 "$TEST_DIR/install" "$TEST_DIR/extra.zip" || return 1
    [ ! -e "$TEST_DIR/escaped" ] && [ ! -e "$TEST_DIR/install/other-file" ]
}
ports() {
    local port
    for port in 1 65535 0080; do valid_port "$port" || return 1; done
    for port in 0 65536 -1 99999999999999999999999999 abc; do valid_port "$port" && return 1; done
    return 0
}
ips() {
    local address
    for address in 127.0.0.1 255.255.255.255 :: ::1 2001:db8::1 2001:db8:1:2:3:4:5:6; do is_valid_ip "$address" || return 1; done
    for address in 999.1.1.1 1.2.3 2001:::1 :1:: 1::2: 1:2:3 1::2::3 1:2:3:4:5:6:7:8:9 :1:2:3:4:5:6:7; do is_valid_ip "$address" && return 1; done
    return 0
}
config_fixture() {
    printf '[snell-server]\nlisten = 0.0.0.0:7177,[::]:7177\npsk = abcdefghijklmnopqrstuvwx\n' > "$CONF_FILE"
}
service_is_running() { [ "${TEST_RUNNING:-false}" = true ]; }
stop_service() { echo stop >> "$TEST_DIR/actions"; }
start_service() { echo start >> "$TEST_DIR/actions"; }
restart_service() { echo restart >> "$TEST_DIR/actions"; }
wait_for_service() { [ "${TEST_FAIL_SERVICE:-false}" != true ]; }
reset_multi() {
    config_fixture
    reset_port <<< 0080 || return 1
    assert_equal "$(sed -n 's/^listen = //p' "$CONF_FILE")" '0.0.0.0:80,[::]:80'
}
config_rollback() {
    config_fixture
    local original
    original=$(cat "$CONF_FILE")
    TEST_RUNNING=true TEST_FAIL_SERVICE=true
    ! reset_port <<< 8080 || return 1
    assert_equal "$(cat "$CONF_FILE")" "$original"
}
upgrade_case() {
    local running="$1" fail_service="$2" fail_download="$3"
    TEST_RUNNING="$running" TEST_FAIL_SERVICE="$fail_service"
    printf '#!/bin/sh\necho "snell-server v5.0.1 (test)"\n' > "$SNELL_BIN"
    chmod +x "$SNELL_BIN"
    config_fixture
    local original
    original=$(cat "$CONF_FILE")
    : > "$TEST_DIR/actions"
    # shellcheck disable=SC2329
    download_snell_zip() {
        [ "$fail_download" = false ] || return 1
        cp "$TEST_DIR/v6.zip" "$2"
    }
    if upgrade_snell <<< ''; then
        [ "$fail_service" = false ] && [ "$fail_download" = false ] || return 1
        assert_equal "$(get_installed_version)" v6.0.0 || return 1
    else
        [ "$fail_service" = true ] || [ "$fail_download" = true ] || return 1
        assert_equal "$(get_installed_version)" v5.0.1 || return 1
    fi
    assert_equal "$(cat "$CONF_FILE")" "$original" || return 1
    if [ "$running" = false ] || [ "$fail_download" = true ]; then [ ! -s "$TEST_DIR/actions" ]; fi
}
reject_online_version() {
    printf 'old binary' > "$SNELL_BIN"
    download_snell_zip() { cp "$TEST_DIR/wrong.zip" "$2"; }
    if install_snell_binary aarch64 v6.0.0 6 "$TEST_DIR/install" ''; then return 1; fi
    assert_equal "$(cat "$SNELL_BIN")" 'old binary'
}
menu_eof() { ! show_menu </dev/null; }
missing_arg() { ! bash "$ROOT/Snell.sh" -i; }
no_ansi() { show_menu <<< 0 > "$TEST_DIR/menu"; ! LC_ALL=C command grep -q $'\033' "$TEST_DIR/menu"; }

help_nonroot() { bash "$ROOT/Snell.sh" --help | command grep -q v6.0.0-linux; }
service_files() {
    OPENRC_SERVICE_FILE="$TEST_DIR/openrc-service"
    SYSTEMD_SERVICE_FILE="$TEST_DIR/snell.service"
    create_openrc_service /usr/local/bin /etc/snell/snell-server.conf || return 1
    assert_equal "$(head -n 1 "$OPENRC_SERVICE_FILE")" '#!/sbin/openrc-run' || return 1
    [ -x "$OPENRC_SERVICE_FILE" ] || return 1
    bash -n "$OPENRC_SERVICE_FILE" || return 1
    create_systemd_service /usr/local/bin /etc/snell/snell-server.conf || return 1
    command grep -q '^ExecStart=/usr/local/bin/snell-server -c /etc/snell/snell-server.conf$' "$SYSTEMD_SERVICE_FILE"
}
export_ip_family() {
    curl() { printf '%s\n' '2001:4860::1'; }
    assert_equal "$(get_server_ip false)" YOUR_SERVER_IP || return 1
    assert_equal "$(get_server_ip true)" '2001:4860::1' || return 1
    curl() { printf '%s\n' '1.2.3.4'; }
    assert_equal "$(get_server_ip false)" '1.2.3.4'
}
reject_downgrade() {
    printf '#!/bin/sh\necho "snell-server v6.0.0 (test)"\n' > "$SNELL_BIN"
    chmod +x "$SNELL_BIN"
    ! upgrade_snell <<< 1 || return 1
    assert_equal "$(get_installed_version)" v6.0.0
}
check 'v6 stable is the default' version_default
check 'v5 remains selectable' version_legacy
check 'version selection stops on EOF' version_eof
check 'supported and unsupported architecture URLs' url_checks
check 'valid local archive and version' install_valid
check 'corrupt archive preserves old binary' reject_archive broken
check 'missing executable preserves old binary' reject_archive missing
check 'wrong protocol preserves old binary' reject_archive v5
check 'extra archive entries are not extracted' archive_extra
check 'port bounds and leading zero input' ports
check 'IPv4 and IPv6 syntax validation' ips
check 'port reset preserves all v6 listeners' reset_multi
check 'failed config restart restores old configuration' config_rollback
check 'running upgrade preserves config' upgrade_case true false false
check 'stopped upgrade leaves service stopped' upgrade_case false false false
check 'failed upgrade startup restores old binary' upgrade_case true true false
check 'failed download never stops service' upgrade_case true false true
check 'menu stops on EOF' menu_eof
check 'help works without installing' help_nonroot
check 'online beta cannot replace requested stable release' reject_online_version
check 'missing install argument fails promptly' missing_arg
check 'nonterminal menu contains no ANSI controls' no_ansi
check 'generated service files have valid interpreter and command' service_files
check 'exported server address matches listener family' export_ip_family
check 'v6 config is protected from major version downgrade' reject_downgrade
printf '\n%s passed; %s failed\n' "$passed" "$failed"
[ "$failed" -eq 0 ]
