#!/bin/sh

if [ -z "$BASH_VERSION" ]; then
    if ! command -v bash >/dev/null 2>&1; then
        if command -v apk >/dev/null 2>&1; then
            if [ "$(id -u)" != "0" ]; then
                echo "请以 root 权限运行此脚本，以便在 Alpine 上安装 bash。"
                exit 1
            fi
            apk update && apk add --no-cache bash || exit 1
        else
            echo "请先安装 bash 后再运行此脚本。"
            exit 1
        fi
    fi
    exec bash "$0" "$@"
fi

# 定义脚本版本
SCRIPT_VERSION="20261029"

# 定义颜色代码
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
RESET='\033[0m'

SNELL_V5_VERSION="v5.0.1"
SNELL_V6_VERSION="v6.0.0"
SNELL_VERSION="${SNELL_V6_VERSION}"
SNELL_PROTOCOL_VERSION="6"

# 定义配置目录和文件
CONF_DIR="/etc/snell"
CONF_FILE="${CONF_DIR}/snell-server.conf"

# 定义安装相关变量
LOCAL_ZIP_FILE=""
SNELL_BIN="/usr/local/bin/snell-server"
OPENRC_SERVICE_FILE="/etc/init.d/snell"
SYSTEMD_SERVICE_FILE="/etc/systemd/system/snell.service"

# 非交互输出和 NO_COLOR 环境下不输出 ANSI 控制符。
if [ ! -t 1 ] || [ -n "${NO_COLOR+x}" ] || [ "${TERM:-dumb}" = "dumb" ]; then
    RED='' GREEN='' YELLOW='' CYAN='' RESET=''
fi

ui_heading() {
    printf '\n%b%s%b\n' "${CYAN}" "$1" "${RESET}"
    printf '%s\n' '────────────────────────────────────────'
}

pause_menu() {
    read -r -p "按 Enter 继续…" _pause || return 1
}

# EOF 必须退出当前流程，不能被当作默认选择。
read_input() {
    local prompt="$1" variable="$2"
    read -r -p "$prompt" "${variable?}"
}

get_installed_version() {
    "${SNELL_BIN}" -v 2>&1 | sed -n 's/.*snell-server \(v[0-9][^ ]*\).*/\1/p' | head -n 1
}

service_is_running() {
    case "$(detect_init_system)" in
        systemd) systemctl is-active --quiet snell ;;
        openrc) rc-service snell status >/dev/null 2>&1 ;;
        *) return 1 ;;
    esac
}

wait_for_service() {
    local attempt
    for ((attempt=0; attempt<5; attempt++)); do
        sleep 1
        service_is_running || return 1
    done
}

# 检测初始化系统类型
detect_init_system() {
    if [ -d /run/systemd/system ]; then
        echo "systemd"
    elif command -v rc-service &> /dev/null; then
        echo "openrc"
    else
        echo "unknown"
    fi
}

# 检测发行版类型
detect_distro() {
    if [ -f /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        echo "$ID"
    elif [ -f /etc/alpine-release ]; then
        echo "alpine"
    elif [ -f /etc/debian_version ]; then
        echo "debian"
    elif [ -f /etc/redhat-release ]; then
        if grep -q "CentOS" /etc/redhat-release; then
            echo "centos"
        elif grep -q "Red Hat" /etc/redhat-release; then
            echo "rhel"
        else
            echo "rhel"
        fi
    elif [ -f /etc/centos-release ]; then
        echo "centos"
    else
        echo "unknown"
    fi
}

# 获取适用的用户组
get_user_group() {
    local distro
    distro=$(detect_distro)

    # 检查nogroup是否存在，如果不存在则使用nobody
    if command -v getent >/dev/null 2>&1 && getent group nogroup >/dev/null 2>&1; then
        echo "nobody:nogroup"
    elif command -v getent >/dev/null 2>&1 && getent group nobody >/dev/null 2>&1; then
        echo "nobody:nobody"
    elif grep -q '^nogroup:' /etc/group 2>/dev/null; then
        echo "nobody:nogroup"
    elif grep -q '^nobody:' /etc/group 2>/dev/null; then
        echo "nobody:nobody"
    else
        # 如果都不存在，根据发行版选择
        case "$distro" in
            "alpine")
                echo "nobody:nobody"
                ;;
            "debian"|"ubuntu")
                echo "nobody:nogroup"
                ;;
            "centos"|"rhel"|"fedora")
                echo "nobody:nobody"
                ;;
            *)
                echo "nobody:nobody"
                ;;
        esac
    fi
}

# 创建 OpenRC 服务文件
create_openrc_service() {
    local install_dir="$1"
    local conf_file="$2"
    local openrc_service_file="${OPENRC_SERVICE_FILE}"
    local user_group
    user_group=$(get_user_group)
    local user
    user=${user_group%%:*}
    local group
    group=${user_group#*:}
    local distro
    distro=$(detect_distro)

    # 根据发行版选择pidfile路径
    local pidfile_path
    if [ "$distro" = "alpine" ] || [ -d "/run" ]; then
        pidfile_path="/run/snell.pid"
    else
        pidfile_path="/var/run/snell.pid"
    fi

    if ! cat > "${openrc_service_file}" << EOF
#!/sbin/openrc-run

name="snell"
description="Snell Proxy Service"
command="${install_dir}/snell-server"
command_args="-c ${conf_file}"
command_user="${user}:${group}"
pidfile="${pidfile_path}"
command_background="yes"
output_log="/var/log/snell.log"
error_log="/var/log/snell.log"

depend() {
    need net
    after firewall
}

start_pre() {
    # 确保运行目录存在
    if [ ! -d "\$(dirname \$pidfile)" ]; then
        checkpath --directory --owner root:root --mode 0755 "\$(dirname \$pidfile)"
    fi
    # 确保日志文件存在并有正确权限
    checkpath --file --owner ${user}:${group} --mode 0644 /var/log/snell.log
}
EOF

    then
        return 1
    fi
    chmod +x "${openrc_service_file}"
}

# 创建 Systemd 服务文件
create_systemd_service() {
    local install_dir="$1"
    local conf_file="$2"
    local systemd_service_file="${SYSTEMD_SERVICE_FILE}"
    local user_group
    user_group=$(get_user_group)
    local user
    user=${user_group%%:*}
    local group
    group=${user_group#*:}

    cat > "${systemd_service_file}" << EOF
[Unit]
Description=Snell Proxy Service
After=network.target

[Service]
Type=simple
User=${user}
Group=${group}
LimitNOFILE=32768
ExecStart=${install_dir}/snell-server -c ${conf_file}
AmbientCapabilities=CAP_NET_BIND_SERVICE
Restart=on-failure
RestartSec=3
StandardOutput=journal
StandardError=journal
SyslogIdentifier=snell-server

[Install]
WantedBy=multi-user.target
EOF
}

# 启动服务（支持 systemd 和 OpenRC）
start_service() {
    local init_system
    init_system=$(detect_init_system)
    
    case "$init_system" in
        "systemd")
            systemctl start snell
            ;;
        "openrc")
            rc-service snell start
            ;;
        *)
            echo -e "${RED}不支持的初始化系统${RESET}"
            return 1
            ;;
    esac
}

# 停止服务（支持 systemd 和 OpenRC）
stop_service() {
    local init_system
    init_system=$(detect_init_system)
    
    case "$init_system" in
        "systemd")
            systemctl stop snell
            ;;
        "openrc")
            rc-service snell stop
            ;;
        *)
            echo -e "${RED}不支持的初始化系统${RESET}"
            return 1
            ;;
    esac
}

# 重启服务（支持 systemd 和 OpenRC）
restart_service() {
    local init_system
    init_system=$(detect_init_system)
    
    case "$init_system" in
        "systemd")
            systemctl restart snell
            ;;
        "openrc")
            rc-service snell restart
            ;;
        *)
            echo -e "${RED}不支持的初始化系统${RESET}"
            return 1
            ;;
    esac
}

# 启用开机自启（支持 systemd 和 OpenRC）
enable_service() {
    local init_system
    init_system=$(detect_init_system)
    
    case "$init_system" in
        "systemd")
            systemctl enable snell
            ;;
        "openrc")
            rc-update add snell default
            ;;
        *)
            echo -e "${RED}不支持的初始化系统${RESET}"
            return 1
            ;;
    esac
}

# 禁用开机自启（支持 systemd 和 OpenRC）
disable_service() {
    local init_system
    init_system=$(detect_init_system)
    
    case "$init_system" in
        "systemd")
            systemctl disable snell
            ;;
        "openrc")
            rc-update del snell default
            ;;
        *)
            echo -e "${RED}不支持的初始化系统${RESET}"
            return 1
            ;;
    esac
}

# 检查服务状态（支持 systemd 和 OpenRC）
service_status() {
    local init_system
    init_system=$(detect_init_system)
    
    case "$init_system" in
        "systemd")
            systemctl --no-pager --full status snell
            ;;
        "openrc")
            rc-service snell status
            ;;
        *)
            echo -e "${RED}不支持的初始化系统${RESET}"
            return 1
            ;;
    esac
}

# 显示已安装服务的摘要状态
show_service_overview() {
    local init_system
    init_system=$(detect_init_system)

    case "$init_system" in
        "systemd")
            local active_state enabled_state service_state enabled_state_text

            active_state=$(systemctl is-active snell 2>/dev/null)
            enabled_state=$(systemctl is-enabled snell 2>/dev/null)

            case "$active_state" in
                "active")
                    service_state="运行中"
                    ;;
                "inactive")
                    service_state="已停止"
                    ;;
                "failed")
                    service_state="已失败"
                    ;;
                "activating")
                    service_state="启动中"
                    ;;
                "deactivating")
                    service_state="停止中"
                    ;;
                *)
                    service_state="${active_state:-未知}"
                    ;;
            esac

            case "$enabled_state" in
                "enabled")
                    enabled_state_text="已启用"
                    ;;
                "disabled")
                    enabled_state_text="未启用"
                    ;;
                "static")
                    enabled_state_text="静态"
                    ;;
                *)
                    enabled_state_text="${enabled_state:-未知}"
                    ;;
            esac

            echo -e "${CYAN}服务状态：${RESET}${service_state}"
            echo -e "${CYAN}开机自启：${RESET}${enabled_state_text}"
            ;;
        "openrc")
            local rc_output rc_enabled_state

            rc_output=$(rc-service snell status 2>&1)
            if echo "${rc_output}" | grep -Eqi "started|run:|running"; then
                echo -e "${CYAN}服务状态：${RESET}运行中"
            elif echo "${rc_output}" | grep -Eqi "stopped|crashed|failed"; then
                echo -e "${CYAN}服务状态：${RESET}已停止"
            else
                echo -e "${CYAN}服务状态：${RESET}${rc_output}"
            fi

            if command -v rc-update >/dev/null 2>&1 && rc-update show default 2>/dev/null | grep -q "snell"; then
                rc_enabled_state="已启用"
            else
                rc_enabled_state="未启用"
            fi
            echo -e "${CYAN}开机自启：${RESET}${rc_enabled_state}"
            ;;
        *)
            echo -e "${YELLOW}无法识别初始化系统，无法自动显示服务状态${RESET}"
            ;;
    esac
}

# 查看服务日志
view_service_logs() {
    local init_system
    init_system=$(detect_init_system)

    echo -e "${CYAN}=== Snell 日志 ===${RESET}"
    case "$init_system" in
        "systemd")
            if command -v journalctl >/dev/null 2>&1; then
                journalctl -u snell -n 100 --no-pager
            elif [ -f /var/log/snell.log ]; then
                tail -n 100 /var/log/snell.log
            elif command -v logread >/dev/null 2>&1; then
                logread 2>/dev/null | tail -n 100
            elif command -v dmesg >/dev/null 2>&1; then
                dmesg 2>/dev/null | tail -n 100
            else
                echo -e "${YELLOW}未找到可用日志来源。${RESET}"
            fi
            ;;
        "openrc")
            if [ -f /var/log/snell.log ]; then
                tail -n 100 /var/log/snell.log
            elif command -v journalctl >/dev/null 2>&1; then
                journalctl -u snell -n 100 --no-pager
            elif command -v logread >/dev/null 2>&1; then
                logread 2>/dev/null | tail -n 100
            elif command -v dmesg >/dev/null 2>&1; then
                dmesg 2>/dev/null | tail -n 100
            else
                echo -e "${YELLOW}未找到可用日志文件 /var/log/snell.log。${RESET}"
            fi
            ;;
        *)
            if [ -f /var/log/snell.log ]; then
                tail -n 100 /var/log/snell.log
            elif command -v logread >/dev/null 2>&1; then
                logread 2>/dev/null | tail -n 100
            elif command -v dmesg >/dev/null 2>&1; then
                dmesg 2>/dev/null | tail -n 100
            else
                echo -e "${YELLOW}不支持的初始化系统${RESET}"
            fi
            ;;
    esac
    echo -e "${CYAN}================${RESET}"
}

# 前台运行一次 Snell，便于排查服务启动失败
debug_run_snell() {
    if [ ! -x /usr/local/bin/snell-server ]; then
        echo -e "${RED}未找到 /usr/local/bin/snell-server。${RESET}"
        return
    fi

    if [ ! -f "${CONF_FILE}" ]; then
        echo -e "${RED}配置文件不存在: ${CONF_FILE}${RESET}"
        return
    fi

    echo -e "${YELLOW}即将停止当前 Snell 服务，并以前台方式运行一次。按 Ctrl+C 结束诊断；如返回 shell，请重新运行脚本。${RESET}"
    stop_service >/dev/null 2>&1
    /usr/local/bin/snell-server -c "${CONF_FILE}"
}

# 重载服务配置（支持 systemd 和 OpenRC）
reload_service_config() {
    local init_system
    init_system=$(detect_init_system)
    
    case "$init_system" in
        "systemd")
            systemctl daemon-reload
            ;;
        "openrc")
            # OpenRC 不需要重载配置
            return 0
            ;;
        *)
            echo -e "${RED}不支持的初始化系统${RESET}"
            return 1
            ;;
    esac
}

# 显示帮助信息
show_help() {
    echo -e "${GREEN}Snell 管理工具 v${SCRIPT_VERSION}${RESET}"
    echo ""
    echo "用法："
    echo "  $0                    # 启动交互式菜单"
    echo "  $0 -i <zip文件>       # 使用本地zip文件安装"
    echo "  $0 -h                 # 显示此帮助信息"
    echo ""
    echo "示例："
    echo "  $0 -i snell-server-v5.0.1-linux-amd64.zip"
    echo "  $0 -i snell-server-v6.0.0-linux-amd64.zip"
    echo ""
}

# 解析命令行参数
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -i|--install)
                if [ "$#" -lt 2 ] || [ -z "$2" ]; then
                    echo "错误：$1 需要指定 ZIP 文件。" >&2
                    exit 1
                fi
                LOCAL_ZIP_FILE="$2"
                if [[ ! -f "$LOCAL_ZIP_FILE" ]]; then
                    echo -e "${RED}错误：文件 '$LOCAL_ZIP_FILE' 不存在${RESET}"
                    exit 1
                fi
                if [[ ! "$LOCAL_ZIP_FILE" =~ \.zip$ ]]; then
                    echo -e "${RED}错误：文件必须是 .zip 格式${RESET}"
                    exit 1
                fi
                shift 2
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                echo -e "${RED}未知参数: $1${RESET}"
                show_help
                exit 1
                ;;
        esac
    done
}

# 等待其他包管理器进程完成
wait_for_package_manager() {
    if command -v apt &> /dev/null; then
        while fuser /var/lib/dpkg/lock >/dev/null 2>&1; do
            echo -e "${YELLOW}等待其他 apt 进程完成${RESET}"
            sleep 1
        done
    elif command -v apk &> /dev/null; then
        # Alpine 使用 apk，不需要等待锁定
        return 0
    fi
}

# 检查是否以 root 权限运行
check_root() {
    if [ "$(id -u)" != "0" ]; then
        echo -e "${RED}请以 root 权限运行此脚本.${RESET}"
        exit 1
    fi
}

# 检查 Snell 是否已安装
check_snell_installed() {
    if [ -x "${SNELL_BIN}" ]; then
        return 0
    else
        return 1
    fi
}

select_snell_version() {
    local action_name="${1:-安装}" version_choice
    while true; do
        ui_heading "${action_name} · 选择版本"
        printf '  1  Snell v5  %s\n' "${SNELL_V5_VERSION}"
        printf '  2  Snell v6  %s · 正式版，推荐\n' "${SNELL_V6_VERSION}"
        printf '  0  取消\n\n'
        read_input "选择 [0-2，默认 2]: " version_choice || return 1
        case "${version_choice}" in
            1) SNELL_VERSION="${SNELL_V5_VERSION}"; SNELL_PROTOCOL_VERSION="5"; return 0 ;;
            ""|2) SNELL_VERSION="${SNELL_V6_VERSION}"; SNELL_PROTOCOL_VERSION="6"; return 0 ;;
            0) return 1 ;;
            *) printf '%b无效选项，请输入 0、1 或 2。%b\n' "${RED}" "${RESET}" ;;
        esac
    done
}

get_snell_download_url() {
    local arch="$1"
    local version="$2"
    local protocol_version="$3"

    case "${arch}" in
        "x86_64"|"amd64")
            echo "https://dl.nssurge.com/snell/snell-server-${version}-linux-amd64.zip"
            ;;
        "i386"|"i686")
            echo "https://dl.nssurge.com/snell/snell-server-${version}-linux-i386.zip"
            ;;
        "aarch64"|"arm64")
            echo "https://dl.nssurge.com/snell/snell-server-${version}-linux-aarch64.zip"
            ;;
        "armv7l"|"armv7"|"arm")
            if [ "${protocol_version}" = "6" ]; then
                return 2
            fi
            echo "https://dl.nssurge.com/snell/snell-server-${version}-linux-armv7l.zip"
            ;;
        *)
            return 1
            ;;
    esac
}

create_snell_download_dir() {
    local download_dir

    download_dir=$(mktemp -d "${TMPDIR:-/tmp}/snell.XXXXXX" 2>/dev/null)
    if [ -z "${download_dir}" ]; then
        echo -e "${RED}创建临时下载目录失败。${RESET}" >&2
        return 1
    fi

    echo "${download_dir}"
}

download_snell_zip() {
    local url="$1"
    local output_file="$2"

    if command -v curl >/dev/null 2>&1; then
        curl -fLsS --connect-timeout 15 --max-time 180 --retry 3 --retry-delay 2 -o "${output_file}" "${url}"
    elif command -v wget >/dev/null 2>&1; then
        wget -T 30 -t 3 "${url}" -O "${output_file}"
    else
        echo -e "${RED}未找到 curl 或 wget，无法下载 Snell。${RESET}" >&2
        return 1
    fi
}

# 仅提取指定文件，在临时目录验证版本后原子替换，绝不直接解压到 PATH。
install_snell_binary() (
    local arch="$1" version="$2" protocol_version="$3"
    local install_dir="$4" local_zip_file="$5"
    local download_dir zip_file snell_url url_status binary_version staged_file=""
    download_dir=$(create_snell_download_dir) || return 1
    trap 'rm -rf -- "$download_dir"; [ -z "$staged_file" ] || rm -f -- "$staged_file"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    zip_file="${download_dir}/snell-server.zip"

    if [ -n "${local_zip_file}" ]; then
        printf '使用本地文件: %s\n' "${local_zip_file}"
        cp "${local_zip_file}" "${zip_file}" || return 1
    else
        snell_url=$(get_snell_download_url "${arch}" "${version}" "${protocol_version}")
        url_status=$?
        case "$url_status" in
            1) echo "不支持的架构: ${arch}" >&2; return 1 ;;
            2) echo "Snell v6 没有 armv7l/arm 安装包，请选择 v5。" >&2; return 1 ;;
        esac
        printf '正在下载 %s\n' "${snell_url}"
        download_snell_zip "${snell_url}" "${zip_file}" || return 1
    fi
    if [ ! -s "${zip_file}" ] || ! unzip -t "${zip_file}" >/dev/null 2>&1; then
        echo "Snell 压缩包为空或校验失败。" >&2
        return 1
    fi
    if ! unzip -p "${zip_file}" snell-server > "${download_dir}/snell-server" || [ ! -s "${download_dir}/snell-server" ]; then
        echo "压缩包缺少有效的 snell-server。" >&2
        return 1
    fi
    chmod 755 "${download_dir}/snell-server" || return 1
    binary_version=$("${download_dir}/snell-server" -v 2>&1 | sed -n 's/.*snell-server \(v[0-9][^ ]*\).*/\1/p' | head -n 1)
    if [[ ! "$binary_version" == v"${protocol_version}".* ]] || { [ -z "$local_zip_file" ] && [ "$binary_version" != "$version" ]; }; then
        echo "二进制无法运行或版本不匹配（检测到 ${binary_version:-未知}，选择 ${version}），原文件未修改。" >&2
        return 1
    fi
    mkdir -p "${install_dir}" || return 1
    staged_file=$(mktemp "${install_dir}/.snell-server.XXXXXX") || return 1
    cp "${download_dir}/snell-server" "$staged_file" && chmod 755 "$staged_file" &&
        mv -f "$staged_file" "${install_dir}/snell-server" || return 1
    staged_file=""
)

is_ipv6_address() {
    [[ "$1" == *:* ]]
}

is_public_ipv6_address() {
    local ip
    ip=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')

    ip="${ip%%%*}"
    if ! is_ipv6_address "${ip}"; then
        return 1
    fi

    # Public IPv6 addresses are global unicast addresses under 2000::/3.
    case "${ip}" in
        2*|3*)
            ;;
        *)
            return 1
            ;;
    esac

    # Exclude non-public ranges that may still appear with global scope.
    case "${ip}" in
        2001:db8:*|2001:0db8:*|2002:*)
            return 1
            ;;
    esac

    return 0
}

list_public_ipv6_addresses() {
    if [ -r /proc/sys/net/ipv6/conf/all/disable_ipv6 ] && [ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null)" = "1" ]; then
        return 1
    fi

    if command -v ip >/dev/null 2>&1; then
        while IFS= read -r ipv6_addr; do
            if is_public_ipv6_address "${ipv6_addr}"; then
                echo "${ipv6_addr}"
            fi
        done <<< "$(ip -o -6 addr show scope global 2>/dev/null | awk '{split($4, addr, "/"); if (addr[1] != "") print addr[1]}')"
        return 0
    fi

    if [ -f /proc/net/if_inet6 ]; then
        awk '
            {
                addr = tolower($1)
                if (addr ~ /^[23]/ && addr !~ /^20010db8/ && addr !~ /^2002/) {
                    printf "%s:%s:%s:%s:%s:%s:%s:%s\n",
                        substr(addr, 1, 4), substr(addr, 5, 4), substr(addr, 9, 4), substr(addr, 13, 4),
                        substr(addr, 17, 4), substr(addr, 21, 4), substr(addr, 25, 4), substr(addr, 29, 4)
                }
            }
        ' /proc/net/if_inet6
        return 0
    fi

    return 1
}

has_public_ipv6() {
    local ipv6_addr

    ipv6_addr=$(list_public_ipv6_addresses | head -n 1)
    [ -n "${ipv6_addr}" ]
}

set_ipv6_config() {
    local enable_ipv6="$1"

    sed -i '/^ipv6 = /d' "${CONF_FILE}" || return 1
    if [ "${enable_ipv6}" = "true" ]; then
        echo "ipv6 = true" >> "${CONF_FILE}"
    fi
}

set_dns_config() {
    local enable_ipv6="$1"
    local dns_servers="1.1.1.1, 8.8.8.8"

    if [ "${enable_ipv6}" = "true" ]; then
        dns_servers="${dns_servers}, 2001:4860:4860::8888"
    fi

    if grep -q "^dns = " "${CONF_FILE}"; then
        sed -i "s|^dns = .*|dns = ${dns_servers}|" "${CONF_FILE}"
    else
        sed -i "/^\\[snell-server\\]/a dns = ${dns_servers}" "${CONF_FILE}"
    fi
}

get_server_ip() {
    local enable_ipv6="$1" address
    address=$(curl -4 -fsS --connect-timeout 5 --max-time 10 https://api.ipify.org 2>/dev/null)
    if is_valid_ip "$address" && ! is_ipv6_address "$address"; then
        printf '%s\n' "$address"
        return 0
    fi
    if [ "$enable_ipv6" = true ]; then
        address=$(curl -6 -fsS --connect-timeout 5 --max-time 10 https://api6.ipify.org 2>/dev/null)
        if is_valid_ip "$address" && is_public_ipv6_address "$address"; then
            printf '%s\n' "$address"
            return 0
        fi
    fi
    echo "未能查询与监听地址匹配的公网 IP，请手动填写服务器地址。" >&2
    printf '%s\n' YOUR_SERVER_IP
}

# 安装 Snell（支持本地文件和在线下载）
install_snell() {
    if check_snell_installed || [ -e "${CONF_FILE}" ]; then
        echo "检测到已有 Snell 程序或配置，请使用升级功能；如需重装，请先备份并卸载。" >&2
        return 1
    fi
    select_snell_version "安装" || return 1
    echo -e "${CYAN}正在安装 Snell ${SNELL_VERSION}${RESET}"

    # 等待其他包管理器进程完成
    wait_for_package_manager

    # 检测初始化系统
    INIT_SYSTEM=$(detect_init_system)
    if [ "$INIT_SYSTEM" = "unknown" ]; then
        echo "不支持的初始化系统，需要 systemd 或 OpenRC。" >&2
        return 1
    fi
    echo -e "${CYAN}检测到初始化系统: ${INIT_SYSTEM}${RESET}"

    # 安装必要的软件包
    if command -v apt &> /dev/null; then
        apt update && apt install -y wget unzip curl iproute2 coreutils ca-certificates || return 1
    elif command -v apk &> /dev/null; then
        apk update && apk add --no-cache bash wget unzip curl iproute2 coreutils ca-certificates gcompat libstdc++ || return 1
    elif command -v dnf &> /dev/null; then
        dnf install -y wget unzip curl iproute2 coreutils ca-certificates || return 1
    elif command -v yum &> /dev/null; then
        yum install -y wget unzip curl iproute2 coreutils ca-certificates || return 1
    else
        echo -e "${RED}不支持的包管理器${RESET}"
        exit 1
    fi

    ARCH=$(uname -m)
    INSTALL_DIR="/usr/local/bin"

    if ! install_snell_binary "${ARCH}" "${SNELL_VERSION}" "${SNELL_PROTOCOL_VERSION}" "${INSTALL_DIR}" "${LOCAL_ZIP_FILE}"; then
        exit 1
    fi

    # 生成随机端口和密码
    RANDOM_PORT=$(shuf -i 30000-65000 -n 1)
    RANDOM_PSK=$(LC_ALL=C tr -dc A-Za-z0-9 </dev/urandom | head -c 32)

    if has_public_ipv6; then
        if [ "${SNELL_PROTOCOL_VERSION}" = "6" ]; then
            DEFAULT_LISTEN="0.0.0.0:${RANDOM_PORT},[::]:${RANDOM_PORT}"
        else
            DEFAULT_LISTEN="[::]:${RANDOM_PORT}"
        fi
        ENABLE_IPV6="true"
    else
        DEFAULT_LISTEN="0.0.0.0:${RANDOM_PORT}"
        ENABLE_IPV6="false"
        echo -e "${YELLOW}未检测到公网 IPv6，已自动使用 IPv4-only 配置。${RESET}"
    fi

    # 创建配置文件目录
    mkdir -p "${CONF_DIR}" || return 1
    local previous_umask
    previous_umask=$(umask)
    umask 027

    # 创建配置文件
    cat > "${CONF_FILE}" << EOF
[snell-server]
dns = 1.1.1.1, 8.8.8.8
listen = ${DEFAULT_LISTEN}
psk = ${RANDOM_PSK}
EOF

    umask "$previous_umask"
    local service_group
    service_group=$(get_user_group)
    service_group="${service_group#*:}"
    chown "root:${service_group}" "${CONF_DIR}" "${CONF_FILE}" || return 1
    chmod 750 "${CONF_DIR}" || return 1
    chmod 640 "${CONF_FILE}" || return 1
    SNELL_VERSION=$(get_installed_version)
    set_dns_config "${ENABLE_IPV6}"
    if [ "${ENABLE_IPV6}" = "true" ]; then
        echo "ipv6 = true" >> "${CONF_FILE}"
    fi

    # 根据初始化系统创建服务文件
    case "$INIT_SYSTEM" in
        "systemd")
            create_systemd_service "${INSTALL_DIR}" "${CONF_FILE}" || return 1
            ;;
        "openrc")
            create_openrc_service "${INSTALL_DIR}" "${CONF_FILE}" || return 1
            ;;
        *)
            echo -e "${RED}不支持的初始化系统: $INIT_SYSTEM${RESET}"
            exit 1
            ;;
    esac

    # 重载服务配置
    if ! reload_service_config; then
        echo -e "${RED}重载服务配置失败。${RESET}"
        exit 1
    fi

    # 开机自启动 Snell
    if ! enable_service; then
        echo -e "${RED}开机自启动 Snell 失败。${RESET}"
        exit 1
    fi

    # 启动 Snell 服务
    if ! start_service || ! wait_for_service; then
        echo -e "${RED}启动 Snell 服务失败，请查看服务日志。${RESET}"
        exit 1
    fi

    # 导出地址须与实际监听的协议族一致。
    HOST_IP=$(get_server_ip "${ENABLE_IPV6}")
    IP_COUNTRY="Snell"
    if is_ipv6_address "$HOST_IP"; then HOST_IP="[$HOST_IP]"; fi

    echo -e "${GREEN}Snell ${SNELL_VERSION} 安装成功${RESET}"

    if [ "${SNELL_PROTOCOL_VERSION}" = "6" ]; then
        echo -e "${YELLOW}注意：您安装了 Snell v6，请确认客户端已支持 v6 协议。${RESET}"
    fi
    echo ""

    echo "${IP_COUNTRY} = snell, ${HOST_IP}, ${RANDOM_PORT}, psk = ${RANDOM_PSK}, version = ${SNELL_PROTOCOL_VERSION}, reuse = true, tfo = true"
}

# 卸载 Snell
uninstall_snell() {
    local confirmation
    read_input "卸载将删除程序和配置（含 PSK），输入 yes 确认: " confirmation || return 1
    [ "$confirmation" = yes ] || { echo "已取消卸载。"; return 0; }
    echo -e "${CYAN}正在卸载 Snell${RESET}"

    # 检测初始化系统
    INIT_SYSTEM=$(detect_init_system)

    # 停止 Snell 服务
    if ! stop_service; then
        echo -e "${RED}停止 Snell 服务失败。${RESET}"
        exit 1
    fi

    # 禁用开机自启动
    if ! disable_service; then
        echo -e "${RED}禁用开机自启动失败。${RESET}"
        exit 1
    fi

    # 根据初始化系统删除服务文件
    case "$INIT_SYSTEM" in
        "systemd")
            rm -f /etc/systemd/system/snell.service /lib/systemd/system/snell.service
            systemctl daemon-reload
            ;;
        "openrc")
            rm -f /etc/init.d/snell
            ;;
        *)
            echo -e "${YELLOW}未知的初始化系统: $INIT_SYSTEM，跳过服务文件删除${RESET}"
            ;;
    esac


    # 删除安装的文件和目录
    rm -f /usr/local/bin/snell-server
    rm -rf /etc/snell

    echo -e "${GREEN}Snell 卸载成功${RESET}"
}

# 升级 Snell
# 下载和验证均在停服前完成；失败时恢复旧程序与原有服务状态。
upgrade_snell() (
    local stage_dir backup_file was_running=false
    check_snell_installed || { echo "Snell 未安装，无法升级。" >&2; return 1; }
    select_snell_version "升级" || return 1
    if [[ "$(get_installed_version)" == v6.* ]] && [ "$SNELL_PROTOCOL_VERSION" = 5 ]; then
        echo "为避免 v6 配置不兼容，升级功能不执行 v6 到 v5 的降级。" >&2
        return 1
    fi
    stage_dir=$(create_snell_download_dir) || return 1
    backup_file=""
    trap 'rm -rf -- "$stage_dir"; [ -z "$backup_file" ] || rm -f -- "$backup_file"' EXIT
    install_snell_binary "$(uname -m)" "$SNELL_VERSION" "$SNELL_PROTOCOL_VERSION" "$stage_dir" "" || return 1
    backup_file=$(mktemp "$(dirname "$SNELL_BIN")/.snell-backup.XXXXXX") || return 1
    cp -p "$SNELL_BIN" "$backup_file" || return 1
    service_is_running && was_running=true

    rollback_upgrade() {
        if ! mv -f "$backup_file" "$SNELL_BIN"; then
            echo "恢复旧程序失败，备份保留在 $backup_file。" >&2
            backup_file=""
            return 1
        fi
        backup_file=""
        if [ "$was_running" = true ]; then
            restart_service && wait_for_service || echo "旧程序已恢复，但服务恢复失败，请查看日志。" >&2
        fi
    }
    trap 'rollback_upgrade; exit 130' INT
    trap 'rollback_upgrade; exit 143' TERM
    if [ "$was_running" = true ] && ! stop_service; then
        echo "停止服务失败，已取消升级。" >&2
        return 1
    fi
    local replacement
    replacement=$(mktemp "$(dirname "$SNELL_BIN")/.snell-server.XXXXXX") || { rollback_upgrade; return 1; }
    if ! cp "$stage_dir/snell-server" "$replacement" || ! chmod 755 "$replacement" || ! mv -f "$replacement" "$SNELL_BIN"; then
        rm -f "$replacement"
        rollback_upgrade
        return 1
    fi
    if [ "$was_running" = true ] && { ! start_service || ! wait_for_service; }; then
        echo "新版本启动失败，正在回滚。" >&2
        rollback_upgrade
        return 1
    fi
    trap - INT TERM
    printf '%bSnell 已升级至 %s；配置已保留。%b\n' "$GREEN" "$SNELL_VERSION" "$RESET"
    [ "$was_running" = true ] || echo "服务保持停止状态。"
    echo "客户端请使用 version=${SNELL_PROTOCOL_VERSION}，并与服务端 mode 保持一致。"
)

# 显示配置
show_config() {
    if [ ! -f "${CONF_FILE}" ]; then
        echo -e "${RED}配置文件不存在。${RESET}"
        return
    fi

    echo -e "${GREEN}=== 当前 Snell 配置 ===${RESET}"
    cat "${CONF_FILE}"
    echo -e "${GREEN}========================${RESET}"
}

# 配置变更失败时恢复旧文件；已停止的服务保持停止。
begin_config_change() {
    CONFIG_BACKUP=$(mktemp "${CONF_FILE}.backup.XXXXXX") || return 1
    cp -p "$CONF_FILE" "$CONFIG_BACKUP" || { rm -f "$CONFIG_BACKUP"; return 1; }
    CONFIG_WAS_RUNNING=false
    service_is_running && CONFIG_WAS_RUNNING=true
    return 0
}

finish_config_change() {
    if [ "$CONFIG_WAS_RUNNING" = true ] && { ! restart_service || ! wait_for_service; }; then
        echo "新配置启动失败，正在恢复原配置。" >&2
        mv -f "$CONFIG_BACKUP" "$CONF_FILE" || return 1
        restart_service && wait_for_service || echo "原配置已恢复，但服务恢复失败，请查看日志。" >&2
        return 1
    fi
    rm -f "$CONFIG_BACKUP"
    [ "$CONFIG_WAS_RUNNING" = true ] || echo "服务保持停止状态，下次启动时应用新配置。"
    return 0
}

cancel_config_change() {
    mv -f "$CONFIG_BACKUP" "$CONF_FILE"
    return 1
}

regenerate_psk() {
    [ -f "$CONF_FILE" ] || { echo "配置文件不存在。" >&2; return 1; }
    local new_psk
    new_psk=$(LC_ALL=C tr -dc A-Za-z0-9 </dev/urandom | head -c 32)
    [ "${#new_psk}" -eq 32 ] || return 1
    begin_config_change || return 1
    sed -i "s/^psk = .*/psk = ${new_psk}/" "$CONF_FILE" || { cancel_config_change; return 1; }
    finish_config_change || return 1
    printf '%bPSK 已重新生成，请同步更新客户端。%b\n' "$GREEN" "$RESET"
}

valid_port() {
    [[ "$1" =~ ^[0-9]{1,5}$ ]] && [ "$((10#$1))" -ge 1 ] && [ "$((10#$1))" -le 65535 ]
}

# 保留 v6 的全部监听地址，只替换各地址的端口。
reset_port() {
    [ -f "$CONF_FILE" ] || { echo "配置文件不存在。" >&2; return 1; }
    local input_port new_port current_listen new_listen
    read_input "新端口 [1-65535，回车或 0 随机]: " input_port || return 1
    if [ -z "$input_port" ] || [ "$input_port" = 0 ]; then
        new_port=$(shuf -i 30000-65000 -n 1) || return 1
    elif valid_port "$input_port"; then
        new_port=$((10#$input_port))
    else
        echo "端口必须在 1-65535 之间。" >&2
        return 1
    fi
    current_listen=$(sed -n 's/^listen = //p' "$CONF_FILE" | head -n 1)
    [ -n "$current_listen" ] || { echo "无法读取监听地址。" >&2; return 1; }
    new_listen=$(printf '%s\n' "$current_listen" | awk -v port="$new_port" 'BEGIN { FS=","; OFS="," } { for (i=1; i<=NF; i++) sub(/:[0-9]+$/, ":" port, $i); print }')
    begin_config_change || return 1
    sed -i "s|^listen = .*|listen = ${new_listen}|" "$CONF_FILE" || { cancel_config_change; return 1; }
    finish_config_change || return 1
    printf '%b端口已更新为 %s。%b\n' "$GREEN" "$new_port" "$RESET"
}

is_valid_ip() {
    local value="$1" part count=0 compressed=false
    local -a parts
    if [[ "$value" != *:* ]]; then
        [[ "$value" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
        IFS=. read -r -a parts <<< "$value"
        for part in "${parts[@]}"; do [ "$((10#$part))" -le 255 ] || return 1; done
        return 0
    fi
    [[ "$value" =~ ^[0-9a-fA-F:]+$ ]] && [[ "$value" != *:::* ]] || return 1
    if [[ "$value" == :* && "$value" != ::* ]] || [[ "$value" == *: && "$value" != *:: ]]; then return 1; fi
    if [[ "$value" == *::* ]]; then
        compressed=true
        part="${value#*::}"
        [[ "$part" != *::* ]] || return 1
    else
        [[ "$value" != :* && "$value" != *: ]] || return 1
    fi
    IFS=: read -r -a parts <<< "$value"
    for part in "${parts[@]}"; do
        [ -n "$part" ] || continue
        [ "${#part}" -le 4 ] || return 1
        count=$((count + 1))
    done
    if [ "$compressed" = true ]; then [ "$count" -lt 8 ]; else [ "$count" -eq 8 ]; fi
}

format_listen_address() {
    if is_ipv6_address "$1"; then printf '[%s]:%s\n' "$1" "$2"; else printf '%s:%s\n' "$1" "$2"; fi
}

# 获取本机网卡IP地址列表
get_network_interfaces() {
    # 初始化数组
    declare -a ip_list
    PUBLIC_IP_OPTION=""
    IPV6_AVAILABLE="false"

    if has_public_ipv6; then
        IPV6_AVAILABLE="true"
    fi

    # 添加固定选项
    if [ "${IPV6_AVAILABLE}" = "true" ]; then
        ip_list+=("::0")  # 监听所有IPv4和IPv6地址
    fi
    ip_list+=("0.0.0.0")  # 仅监听所有IPv4地址

    # 获取公网IP
    public_ip=$(curl -fsS --connect-timeout 5 --max-time 10 https://api.ipify.org 2>/dev/null | tr -d '[:space:]')
    if is_valid_ip "${public_ip}" && { ! is_ipv6_address "${public_ip}" || is_public_ipv6_address "${public_ip}"; }; then
        PUBLIC_IP_OPTION=$((${#ip_list[@]} + 1))
        ip_list+=("${public_ip}")
    fi

    # 获取本地IPv4地址
    while IFS= read -r ip; do
        if [ -n "${ip}" ]; then
            ip_list+=("${ip}")
        fi
    done <<< "$(ip -o -4 addr show | awk '{split($4, addr, "/"); if (addr[1] != "127.0.0.1") print addr[1]}')"

    # 获取本地公网IPv6地址
    if [ "${IPV6_AVAILABLE}" = "true" ]; then
        while IFS= read -r ip; do
            if [ -n "${ip}" ]; then
                ip_list+=("${ip}")
            fi
        done <<< "$(list_public_ipv6_addresses)"
    fi

    # 显示IP列表
    echo -e "${CYAN}可用的IP地址：${RESET}"
    local option_num=1
    for ip in "${ip_list[@]}"; do
        if [ "${ip}" = "::0" ]; then
            echo "${option_num}. ${ip} (监听所有IPv4和IPv6地址)"
        elif [ "${ip}" = "0.0.0.0" ]; then
            echo "${option_num}. ${ip} (仅监听所有IPv4地址)"
        elif [ -n "${PUBLIC_IP_OPTION}" ] && [ "${option_num}" -eq "${PUBLIC_IP_OPTION}" ]; then
            echo "${option_num}. ${ip} (公网IP)"
        else
            echo "${option_num}. ${ip}"
        fi
        option_num=$((option_num + 1))
    done

    echo "${option_num}. 自定义IP地址"
    LAST_OPTION=${option_num}

    # 保存IP列表供其他函数使用
    IP_LIST=("${ip_list[@]}")
}

# 获取指定选项对应的IP地址
get_ip_by_option() {
    local option=$1

    # 检查选项是否在有效范围内
    if [ "${option}" -ge 1 ] && [ "${option}" -lt "${LAST_OPTION}" ]; then
        echo "${IP_LIST[${option}-1]}"
        return 0
    fi

    return 1
}

# 修改监听IP
change_listen_ip() {
    local ip_choice=""
    if [ ! -f "${CONF_FILE}" ]; then
        echo -e "${RED}配置文件不存在，无法修改监听IP。${RESET}"
        return
    fi

    get_network_interfaces

    read_input "请选择监听地址类型 [1-${LAST_OPTION}]: " ip_choice || return 1

    if [ "${ip_choice}" = "${LAST_OPTION}" ]; then
        read_input "请输入要监听的IP地址: " NEW_IP || return 1
        # 简单的IP地址格式验证
        if ! is_valid_ip "$NEW_IP"; then
            echo -e "${RED}无效的IP地址格式${RESET}"
            return
        fi
    elif [ "${ip_choice}" -ge 1 ] 2>/dev/null && [ "${ip_choice}" -lt "${LAST_OPTION}" ] 2>/dev/null; then
        local selected_ip
        selected_ip=$(get_ip_by_option "${ip_choice}")
        if [ ! -z "${selected_ip}" ]; then
            NEW_IP="${selected_ip}"
        else
            echo -e "${RED}无效的选项${RESET}"
            return
        fi
    else
        echo -e "${RED}无效的选项${RESET}"
        return
    fi

    if is_ipv6_address "${NEW_IP}" && [ "${IPV6_AVAILABLE}" != "true" ]; then
        echo -e "${RED}当前环境未检测到公网 IPv6，无法切换到 IPv6 监听地址。${RESET}"
        return
    fi
    if is_ipv6_address "${NEW_IP}" && [ "${NEW_IP}" != "::0" ] && ! is_public_ipv6_address "${NEW_IP}"; then
        echo -e "${RED}请输入公网 IPv6 地址，或选择 ::0 监听所有 IPv6 地址。${RESET}"
        return
    fi

    # 获取当前端口号
    CURRENT_PORT=$(grep -m 1 "^listen = " "${CONF_FILE}" | grep -o '[0-9]\+$')
    if [ -z "${CURRENT_PORT}" ]; then
        echo -e "${RED}无法读取当前监听端口。${RESET}"
        return
    fi

    local new_listen
    new_listen=$(format_listen_address "$NEW_IP" "$CURRENT_PORT")
    if [ "$NEW_IP" = "::0" ] && [[ "$(get_installed_version)" == v6.* ]]; then
        new_listen="0.0.0.0:${CURRENT_PORT},[::]:${CURRENT_PORT}"
    fi
    begin_config_change || return 1
    sed -i "s|^listen = .*|listen = ${new_listen}|" "${CONF_FILE}" || { cancel_config_change; return 1; }

    if is_ipv6_address "${NEW_IP}"; then
        if ! set_dns_config "true" || ! set_ipv6_config "true"; then cancel_config_change; return 1; fi
    else
        if ! set_dns_config "false" || ! set_ipv6_config "false"; then cancel_config_change; return 1; fi
    fi

    # 重启服务以应用新配置
    if finish_config_change; then
        echo -e "${GREEN}监听IP已成功修改为 ${NEW_IP}。${RESET}"
    fi
}

# 配置管理子菜单
config_menu() {
    local config_choice=""
    while true; do
        ui_heading "配置管理"
        echo "1. 显示当前配置"
        echo "2. 重新生成 PSK"
        echo "3. 重置端口"
        echo "4. 修改监听IP"
        echo "0. 返回主菜单"

        read_input "请输入选项编号: " config_choice || return 1
        echo ""

        case "${config_choice}" in
            1)
                show_config
                pause_menu || return
                ;;
            2)
                regenerate_psk
                pause_menu || return
                ;;
            3)
                reset_port
                pause_menu || return
                ;;
            4)
                change_listen_ip
                pause_menu || return
                ;;
            0)
                return
                ;;
            *)
                echo -e "${RED}无效的选项${RESET}"
                pause_menu || return
                ;;
        esac
    done
}

# 服务管理函数
manage_service() {
    local service_choice=""
    while true; do
        ui_heading "服务管理"
        show_service_overview
        echo ""
        echo "1. 启动服务"
        echo "2. 停止服务"
        echo "3. 重启服务"
        echo "4. 查看服务状态"
        echo "5. 查看服务日志"
        echo "6. 前台诊断启动"
        echo "0. 返回主菜单"


        read_input "请选择操作 [0-6]: " service_choice || return 1
        echo ""

        case "${service_choice}" in
            1)
                if start_service; then
                    echo -e "${GREEN}Snell 服务已启动${RESET}"
                else
                    echo -e "${RED}启动 Snell 服务失败${RESET}"
                fi
                pause_menu || return
                ;;
            2)
                if stop_service; then
                    echo -e "${GREEN}Snell 服务已停止${RESET}"
                else
                    echo -e "${RED}停止 Snell 服务失败${RESET}"
                fi
                pause_menu || return
                ;;
            3)
                if restart_service; then
                    echo -e "${GREEN}Snell 服务已重启${RESET}"
                else
                    echo -e "${RED}重启 Snell 服务失败${RESET}"
                fi
                pause_menu || return
                ;;
            4)
                echo -e "${CYAN}Snell 服务状态：${RESET}"
                service_status
                pause_menu || return
                ;;
            5)
                view_service_logs
                pause_menu || return
                ;;
            6)
                debug_run_snell
                pause_menu || return
                ;;
            0)
                return
                ;;
            *)
                echo -e "${RED}无效的选项${RESET}"
                pause_menu || return
                ;;
        esac
    done
}

# 显示菜单
show_menu() {
    choice=""
    if [ -t 1 ] && [ "${TERM:-dumb}" != "dumb" ]; then clear; fi
    ui_heading "Snell · 服务器管理"
    printf '脚本 %s  ·  %s / %s\n\n' "$SCRIPT_VERSION" "$(uname -m)" "$(detect_init_system)"
    if check_snell_installed; then
        printf '%b已安装  %s%b\n' "$GREEN" "$(get_installed_version)" "$RESET"
        show_service_overview
        if [ -f "$CONF_FILE" ]; then
            printf '监听地址：%s\n' "$(sed -n 's/^listen = //p' "$CONF_FILE" | head -n 1)"
        fi
    else
        printf '%b尚未安装%b  ·  推荐 Snell %s 正式版\n' "$YELLOW" "$RESET" "$SNELL_V6_VERSION"
    fi
    printf '\n  部署\n    1  安装 Snell        3  升级版本\n    2  卸载 Snell\n\n  管理\n    4  配置管理          5  服务管理\n\n    0  退出\n\n'
    read_input "选择 [0-5]: " choice || return 1
    echo ""
}

main() {
    # 主循环
    parse_arguments "$@"
    check_root
    if [ "$(uname -s)" != "Linux" ]; then
        echo "安装与服务管理仅支持 Linux。" >&2
        return 1
    fi

    # 如果指定了本地zip文件，直接安装
    if [[ -n "$LOCAL_ZIP_FILE" ]]; then
        echo -e "${CYAN}检测到本地安装文件，开始安装...${RESET}"
        install_snell
        return $?
    fi

    # 否则进入交互式菜单
    while true; do
        show_menu || return 0
        case "${choice}" in
            1)
                install_snell
                pause_menu || return
                ;;
            2)
                uninstall_snell
                pause_menu || return
                ;;
            3)
                upgrade_snell
                pause_menu || return
                ;;
            4)
                config_menu
                ;;
            5)
                manage_service
                ;;
            0)
                echo -e "${GREEN}已退出 Snell 管理脚本${RESET}"
                return 0
                ;;
            *)
                echo -e "${RED}无效的选项${RESET}"
                pause_menu || return
                ;;
        esac
    done

}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    main "$@"
fi
