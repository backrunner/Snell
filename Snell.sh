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
SCRIPT_VERSION="20260613"

# 定义颜色代码
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
RESET='\033[0m'

SNELL_V5_VERSION="v5.0.1"
SNELL_V6_VERSION="v6.0.0b3"
SNELL_VERSION="${SNELL_V5_VERSION}"
SNELL_PROTOCOL_VERSION="5"

# 定义配置目录和文件
CONF_DIR="/etc/snell"
CONF_FILE="${CONF_DIR}/snell-server.conf"

# 定义安装相关变量
LOCAL_ZIP_FILE=""

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
    local distro=$(detect_distro)

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
    local openrc_service_file="/etc/init.d/snell"
    local user_group=$(get_user_group)
    local user=$(echo $user_group | cut -d: -f1)
    local group=$(echo $user_group | cut -d: -f2)
    local distro=$(detect_distro)

    # 根据发行版选择pidfile路径
    local pidfile_path
    if [ "$distro" = "alpine" ] || [ -d "/run" ]; then
        pidfile_path="/run/snell.pid"
    else
        pidfile_path="/var/run/snell.pid"
    fi

    cat > ${openrc_service_file} << EOF
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

    chmod +x ${openrc_service_file}
}

# 创建 Systemd 服务文件
create_systemd_service() {
    local install_dir="$1"
    local conf_file="$2"
    local systemd_service_file="/lib/systemd/system/snell.service"
    local user_group=$(get_user_group)
    local user=$(echo $user_group | cut -d: -f1)
    local group=$(echo $user_group | cut -d: -f2)

    cat > ${systemd_service_file} << EOF
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
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=snell-server

[Install]
WantedBy=multi-user.target
EOF
}

# 启动服务（支持 systemd 和 OpenRC）
start_service() {
    local init_system=$(detect_init_system)
    
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
    local init_system=$(detect_init_system)
    
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
    local init_system=$(detect_init_system)
    
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
    local init_system=$(detect_init_system)
    
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
    local init_system=$(detect_init_system)
    
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
    local init_system=$(detect_init_system)
    
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
    local init_system=$(detect_init_system)

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
    local init_system=$(detect_init_system)

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
    local init_system=$(detect_init_system)
    
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
    echo "  $0 -i snell-server-v6.0.0b3-linux-amd64.zip"
    echo ""
}

# 解析命令行参数
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -i|--install)
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
    if command -v snell-server &> /dev/null; then
        return 0
    else
        return 1
    fi
}

select_snell_version() {
    local action_name="${1:-安装}"

    while true; do
        echo -e "${CYAN}请选择要${action_name}的 Snell 版本:${RESET}"
        echo "1. Snell v5 (${SNELL_V5_VERSION})"
        echo "2. Snell v6 (${SNELL_V6_VERSION})"
        read -p "请输入选项编号 [1-2，默认 1]: " version_choice

        case "${version_choice}" in
            ""|1)
                SNELL_VERSION="${SNELL_V5_VERSION}"
                SNELL_PROTOCOL_VERSION="5"
                return 0
                ;;
            2)
                SNELL_VERSION="${SNELL_V6_VERSION}"
                SNELL_PROTOCOL_VERSION="6"
                return 0
                ;;
            *)
                echo -e "${RED}无效的选项${RESET}"
                ;;
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

is_ipv6_address() {
    [[ "$1" == *:* ]]
}

is_public_ipv6_address() {
    local ip="${1,,}"

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

    sed -i '/^ipv6 = /d' "${CONF_FILE}"
    if [ "${enable_ipv6}" = "true" ]; then
        echo "ipv6 = true" >> "${CONF_FILE}"
    fi
}

# 安装 Snell（支持本地文件和在线下载）
install_snell() {
    select_snell_version "安装"
    echo -e "${CYAN}正在安装 Snell ${SNELL_VERSION}${RESET}"

    # 等待其他包管理器进程完成
    wait_for_package_manager

    # 检测初始化系统
    INIT_SYSTEM=$(detect_init_system)
    echo -e "${CYAN}检测到初始化系统: ${INIT_SYSTEM}${RESET}"

    # 安装必要的软件包
    if command -v apt &> /dev/null; then
        apt update && apt install -y wget unzip curl iproute2 coreutils
    elif command -v apk &> /dev/null; then
        apk update && apk add --no-cache bash wget unzip curl iproute2 coreutils
    elif command -v dnf &> /dev/null; then
        dnf install -y wget unzip curl iproute2 coreutils
    elif command -v yum &> /dev/null; then
        yum install -y wget unzip curl iproute2 coreutils
    else
        echo -e "${RED}不支持的包管理器${RESET}"
        exit 1
    fi

    ARCH=$(uname -m)
    INSTALL_DIR="/usr/local/bin"

    # 判断是使用本地文件还是在线下载
    if [[ -n "$LOCAL_ZIP_FILE" ]]; then
        echo -e "${CYAN}使用本地文件: $LOCAL_ZIP_FILE${RESET}"
        cp "$LOCAL_ZIP_FILE" snell-server.zip
        if [ $? -ne 0 ]; then
            echo -e "${RED}复制本地文件失败。${RESET}"
            exit 1
        fi
    else
        SNELL_URL=$(get_snell_download_url "${ARCH}" "${SNELL_VERSION}" "${SNELL_PROTOCOL_VERSION}")
        url_status=$?
        if [ ${url_status} -eq 1 ]; then
            echo -e "${RED}不支持的架构: ${ARCH}${RESET}"
            echo -e "${YELLOW}支持的架构: x86_64, i386, aarch64, armv7l${RESET}"
            exit 1
        elif [ ${url_status} -eq 2 ]; then
            echo -e "${RED}Snell v6 暂不支持 armv7l/arm 架构。${RESET}"
            echo -e "${YELLOW}请改选 Snell v5，或使用 x86_64、i386、aarch64 架构安装 v6。${RESET}"
            exit 1
        fi

        echo -e "${CYAN}正在下载 ${SNELL_URL}${RESET}"
        wget ${SNELL_URL} -O snell-server.zip
        if [ $? -ne 0 ]; then
            echo -e "${RED}下载 Snell 失败。${RESET}"
            exit 1
        fi
    fi

    # 解压缩文件到指定目录
    unzip -o snell-server.zip -d ${INSTALL_DIR}
    if [ $? -ne 0 ]; then
        echo -e "${RED}解压缩 Snell 失败。${RESET}"
        exit 1
    fi

    # 删除下载的 zip 文件
    rm snell-server.zip

    # 赋予执行权限
    chmod +x ${INSTALL_DIR}/snell-server

    # 生成随机端口和密码
    RANDOM_PORT=$(shuf -i 30000-65000 -n 1)
    RANDOM_PSK=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 20)

    if has_public_ipv6; then
        DEFAULT_LISTEN="::0:${RANDOM_PORT}"
        ENABLE_IPV6="true"
    else
        DEFAULT_LISTEN="0.0.0.0:${RANDOM_PORT}"
        ENABLE_IPV6="false"
        echo -e "${YELLOW}未检测到公网 IPv6，已自动使用 IPv4-only 配置。${RESET}"
    fi

    # 创建配置文件目录
    mkdir -p ${CONF_DIR}

    # 创建配置文件
    cat > ${CONF_FILE} << EOF
[snell-server]
dns = 1.1.1.1, 8.8.8.8, 2001:4860:4860::8888
listen = ${DEFAULT_LISTEN}
psk = ${RANDOM_PSK}
EOF

    if [ "${ENABLE_IPV6}" = "true" ]; then
        echo "ipv6 = true" >> "${CONF_FILE}"
    fi

    # 根据初始化系统创建服务文件
    case "$INIT_SYSTEM" in
        "systemd")
            create_systemd_service ${INSTALL_DIR} ${CONF_FILE}
            ;;
        "openrc")
            create_openrc_service ${INSTALL_DIR} ${CONF_FILE}
            ;;
        *)
            echo -e "${RED}不支持的初始化系统: $INIT_SYSTEM${RESET}"
            exit 1
            ;;
    esac

    # 重载服务配置
    reload_service_config
    if [ $? -ne 0 ]; then
        echo -e "${RED}重载服务配置失败。${RESET}"
        exit 1
    fi

    # 开机自启动 Snell
    enable_service
    if [ $? -ne 0 ]; then
        echo -e "${RED}开机自启动 Snell 失败。${RESET}"
        exit 1
    fi

    # 启动 Snell 服务
    start_service
    if [ $? -ne 0 ]; then
        echo -e "${RED}启动 Snell 服务失败。${RESET}"
        exit 1
    fi

    # 获取本机IP地址
    HOST_IP=$(curl -s http://checkip.amazonaws.com)

    # 获取IP所在国家
    IP_COUNTRY=$(curl -s http://ipinfo.io/${HOST_IP}/country)

    echo -e "${GREEN}Snell ${SNELL_VERSION} 安装成功${RESET}"

    if [ "${SNELL_PROTOCOL_VERSION}" = "6" ]; then
        echo -e "${YELLOW}注意：您安装了 Snell v6，请确认客户端已支持 v6 协议。${RESET}"
    fi
    echo ""

    echo "${IP_COUNTRY} = snell, ${HOST_IP}, ${RANDOM_PORT}, psk = ${RANDOM_PSK}, version = ${SNELL_PROTOCOL_VERSION}, reuse = true, tfo = true"
}

# 卸载 Snell
uninstall_snell() {
    echo -e "${CYAN}正在卸载 Snell${RESET}"

    # 检测初始化系统
    INIT_SYSTEM=$(detect_init_system)

    # 停止 Snell 服务
    stop_service
    if [ $? -ne 0 ]; then
        echo -e "${RED}停止 Snell 服务失败。${RESET}"
        exit 1
    fi

    # 禁用开机自启动
    disable_service
    if [ $? -ne 0 ]; then
        echo -e "${RED}禁用开机自启动失败。${RESET}"
        exit 1
    fi

    # 根据初始化系统删除服务文件
    case "$INIT_SYSTEM" in
        "systemd")
            rm -f /lib/systemd/system/snell.service
            ;;
        "openrc")
            rm -f /etc/init.d/snell
            ;;
        *)
            echo -e "${YELLOW}未知的初始化系统: $INIT_SYSTEM，跳过服务文件删除${RESET}"
            ;;
    esac

    if [ $? -ne 0 ]; then
        echo -e "${RED}删除服务文件失败。${RESET}"
        exit 1
    fi

    # 删除安装的文件和目录
    rm -f /usr/local/bin/snell-server
    rm -rf /etc/snell

    echo -e "${GREEN}Snell 卸载成功${RESET}"
}

# 升级 Snell
upgrade_snell() {
    select_snell_version "升级"
    echo -e "${CYAN}正在升级 Snell 到 ${SNELL_VERSION}${RESET}"

    # 检查 Snell 是否已安装
    if ! check_snell_installed; then
        echo -e "${RED}Snell 未安装，无法升级。${RESET}"
        return
    fi

    # 停止 Snell 服务
    stop_service

    # 备份原配置文件
    cp /etc/snell/snell-server.conf /etc/snell/snell-server.conf.bak

    # 下载最新版本的 Snell
    ARCH=$(uname -m)
    INSTALL_DIR="/usr/local/bin"

    SNELL_URL=$(get_snell_download_url "${ARCH}" "${SNELL_VERSION}" "${SNELL_PROTOCOL_VERSION}")
    url_status=$?
    if [ ${url_status} -eq 1 ]; then
        echo -e "${RED}不支持的架构: ${ARCH}${RESET}"
        echo -e "${YELLOW}支持的架构: x86_64, i386, aarch64, armv7l${RESET}"
        start_service
        return
    elif [ ${url_status} -eq 2 ]; then
        echo -e "${RED}Snell v6 暂不支持 armv7l/arm 架构。${RESET}"
        echo -e "${YELLOW}请改选 Snell v5，或使用 x86_64、i386、aarch64 架构安装 v6。${RESET}"
        start_service
        return
    fi

    wget ${SNELL_URL} -O snell-server.zip
    if [ $? -ne 0 ]; then
        echo -e "${RED}下载版本 ${SNELL_VERSION} 失败。${RESET}"
        start_service
        return
    fi

    # 解压缩并替换原文件
    unzip -o snell-server.zip -d ${INSTALL_DIR}
    if [ $? -ne 0 ]; then
        echo -e "${RED}解压缩 Snell 失败。${RESET}"
        start_service
        return
    fi

    # 删除下载的 zip 文件
    rm snell-server.zip

    # 赋予执行权限
    chmod +x ${INSTALL_DIR}/snell-server

    # 启动 Snell 服务
    start_service
    if [ $? -ne 0 ]; then
        echo -e "${RED}启动 Snell 服务失败。${RESET}"
        return
    fi

    echo -e "${GREEN}Snell 升级到版本 ${SNELL_VERSION} 成功${RESET}"
}

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

# 重新生成 PSK
regenerate_psk() {
    if [ ! -f "${CONF_FILE}" ]; then
        echo -e "${RED}配置文件不存在，无法重新生成 PSK。${RESET}"
        return
    fi

    NEW_PSK=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 20)
    sed -i "s/^psk = .*/psk = ${NEW_PSK}/" "${CONF_FILE}"
    if [ $? -ne 0 ]; then
        echo -e "${RED}更新 PSK 失败。${RESET}"
        return
    fi

    restart_service
    if [ $? -ne 0 ]; then
        echo -e "${RED}重启 Snell 服务失败。${RESET}"
        return
    fi

    echo -e "${GREEN}PSK 已成功重新生成并应用。${RESET}"
}

# 重启 Snell 服务的辅助函数
restart_snell_service() {
    echo -e "${CYAN}正在重启 Snell 服务...${RESET}"
    restart_service
    if [ $? -ne 0 ]; then
        echo -e "${RED}重启 Snell 服务失败。${RESET}"
        return 1
    fi
    echo -e "${GREEN}Snell 服务已成功重启。${RESET}"
    return 0
}

# 重置端口
reset_port() {
    if [ ! -f "${CONF_FILE}" ]; then
        echo -e "${RED}配置文件不存在，无法重置端口。${RESET}"
        return
    fi

    read -p "请输入新端口号 (1-65535，输入0或直接回车将随机生成): " INPUT_PORT

    # 验证输入的端口号
    if [[ -z "${INPUT_PORT}" ]] || [[ "${INPUT_PORT}" == "0" ]]; then
        NEW_PORT=$(shuf -i 30000-65000 -n 1)
        echo -e "${YELLOW}将使用随机生成的端口: ${NEW_PORT}${RESET}"
    elif ! [[ "${INPUT_PORT}" =~ ^[0-9]+$ ]] || [ "${INPUT_PORT}" -lt 1 ] || [ "${INPUT_PORT}" -gt 65535 ]; then
        echo -e "${RED}无效的端口号，端口号必须在 1-65535 之间${RESET}"
        return
    else
        NEW_PORT="${INPUT_PORT}"
    fi

    # 更新配置文件中的端口
    CURRENT_LISTEN=$(grep -m 1 "^listen = " "${CONF_FILE}" | sed "s/^listen = //")
    CURRENT_IP="${CURRENT_LISTEN%:*}"
    if [ -z "${CURRENT_IP}" ] || [ "${CURRENT_IP}" = "${CURRENT_LISTEN}" ]; then
        if has_public_ipv6; then
            CURRENT_IP="::0"
        else
            CURRENT_IP="0.0.0.0"
        fi
    fi

    sed -i "s|^listen = .*|listen = ${CURRENT_IP}:${NEW_PORT}|" "${CONF_FILE}"
    if [ $? -ne 0 ]; then
        echo -e "${RED}更新端口失败。${RESET}"
        return
    fi

    # 重启服务以应用新配置
    restart_snell_service
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}端口已成功重置为 ${NEW_PORT}。${RESET}"
    fi
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
    public_ip=$(curl -s http://checkip.amazonaws.com | tr -d '[:space:]')
    if [ -n "${public_ip}" ] && { ! is_ipv6_address "${public_ip}" || is_public_ipv6_address "${public_ip}"; }; then
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
    if [ ! -f "${CONF_FILE}" ]; then
        echo -e "${RED}配置文件不存在，无法修改监听IP。${RESET}"
        return
    fi

    get_network_interfaces

    read -p "请选择监听地址类型 [1-${LAST_OPTION}]: " ip_choice

    if [ "${ip_choice}" = "${LAST_OPTION}" ]; then
        read -p "请输入要监听的IP地址: " NEW_IP
        # 简单的IP地址格式验证
        if ! [[ ${NEW_IP} =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && ! [[ ${NEW_IP} =~ ^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$ ]]; then
            echo -e "${RED}无效的IP地址格式${RESET}"
            return
        fi
    elif [ "${ip_choice}" -ge 1 ] 2>/dev/null && [ "${ip_choice}" -lt "${LAST_OPTION}" ] 2>/dev/null; then
        local selected_ip=$(get_ip_by_option "${ip_choice}")
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

    # 更新配置文件中的监听地址
    sed -i "s|^listen = .*|listen = ${NEW_IP}:${CURRENT_PORT}|" "${CONF_FILE}"
    if [ $? -ne 0 ]; then
        echo -e "${RED}更新监听IP失败。${RESET}"
        return
    fi

    if is_ipv6_address "${NEW_IP}"; then
        set_ipv6_config "true"
    else
        set_ipv6_config "false"
    fi

    # 重启服务以应用新配置
    restart_snell_service
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}监听IP已成功修改为 ${NEW_IP}。${RESET}"
    fi
}

# 配置管理子菜单
config_menu() {
    while true; do
        echo -e "${GREEN}=== 配置管理 ===${RESET}"
        echo "1. 显示当前配置"
        echo "2. 重新生成 PSK"
        echo "3. 重置端口"
        echo "4. 修改监听IP"
        echo "0. 返回主菜单"
        echo -e "${GREEN}================${RESET}"
        read -p "请输入选项编号: " config_choice
        echo ""

        case "${config_choice}" in
            1)
                show_config
                read -p "按 enter 键继续..."
                ;;
            2)
                regenerate_psk
                read -p "按 enter 键继续..."
                ;;
            3)
                reset_port
                read -p "按 enter 键继续..."
                ;;
            4)
                change_listen_ip
                read -p "按 enter 键继续..."
                ;;
            0)
                return
                ;;
            *)
                echo -e "${RED}无效的选项${RESET}"
                read -p "按 enter 键继续..."
                ;;
        esac
    done
}

# 服务管理函数
manage_service() {
    while true; do
        echo -e "${GREEN}=== Snell 服务管理 ===${RESET}"
        echo "1. 启动服务"
        echo "2. 停止服务"
        echo "3. 重启服务"
        echo "4. 查看服务状态"
        echo "5. 查看服务日志"
        echo "6. 前台诊断启动"
        echo "0. 返回主菜单"
        echo -e "${GREEN}==================${RESET}"

        read -p "请选择操作 [0-6]: " service_choice
        echo ""

        case "${service_choice}" in
            1)
                start_service
                if [ $? -eq 0 ]; then
                    echo -e "${GREEN}Snell 服务已启动${RESET}"
                else
                    echo -e "${RED}启动 Snell 服务失败${RESET}"
                fi
                read -p "按 enter 键继续..."
                ;;
            2)
                stop_service
                if [ $? -eq 0 ]; then
                    echo -e "${GREEN}Snell 服务已停止${RESET}"
                else
                    echo -e "${RED}停止 Snell 服务失败${RESET}"
                fi
                read -p "按 enter 键继续..."
                ;;
            3)
                restart_service
                if [ $? -eq 0 ]; then
                    echo -e "${GREEN}Snell 服务已重启${RESET}"
                else
                    echo -e "${RED}重启 Snell 服务失败${RESET}"
                fi
                read -p "按 enter 键继续..."
                ;;
            4)
                echo -e "${CYAN}Snell 服务状态：${RESET}"
                service_status
                read -p "按 enter 键继续..."
                ;;
            5)
                view_service_logs
                read -p "按 enter 键继续..."
                ;;
            6)
                debug_run_snell
                read -p "按 enter 键继续..."
                ;;
            0)
                return
                ;;
            *)
                echo -e "${RED}无效的选项${RESET}"
                read -p "按 enter 键继续..."
                ;;
        esac
    done
}

# 显示菜单
show_menu() {
    clear
    check_snell_installed
    snell_status=$?
    echo -e "${GREEN}=== Snell 管理工具 v${SCRIPT_VERSION} ===${RESET}"
    echo -e "${GREEN}当前状态: $(if [ ${snell_status} -eq 0 ]; then echo -e "${GREEN}已安装${RESET}"; else echo -e "${RED}未安装${RESET}"; fi)${RESET}"
    if [ ${snell_status} -eq 0 ]; then
        show_service_overview
    else
        echo -e "可安装版本: v5 (${SNELL_V5_VERSION}) / v6 (${SNELL_V6_VERSION})"
    fi
    echo "1. 安装 Snell"
    echo "2. 卸载 Snell"
    echo "3. 升级 Snell"
    echo "4. 配置管理"
    echo "5. 服务管理"
    echo "0. 退出"
    echo -e "${GREEN}=====================================${RESET}"
    read -p "请输入选项编号: " choice
    echo ""
}

# 主循环
check_root
parse_arguments "$@"

# 如果指定了本地zip文件，直接安装
if [[ -n "$LOCAL_ZIP_FILE" ]]; then
    echo -e "${CYAN}检测到本地安装文件，开始安装...${RESET}"
    install_snell
    exit 0
fi

# 否则进入交互式菜单
while true; do
    show_menu
    case "${choice}" in
        1)
            install_snell
            read -p "按 enter 键继续..."
            ;;
        2)
            uninstall_snell
            read -p "按 enter 键继续..."
            ;;
        3)
            upgrade_snell
            read -p "按 enter 键继续..."
            ;;
        4)
            config_menu
            ;;
        5)
            manage_service
            ;;
        0)
            echo -e "${GREEN}已退出 Snell 管理脚本${RESET}"
            exit 0
            ;;
        *)
            echo -e "${RED}无效的选项${RESET}"
            read -p "按 enter 键继续..."
            ;;
    esac
done
