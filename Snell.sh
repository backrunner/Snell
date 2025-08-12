#!/bin/bash

# 定义脚本版本
SCRIPT_VERSION="20250708"

# 定义颜色代码
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
RESET='\033[0m'

SNELL_VERSION="v5.0.0"

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

# 创建 OpenRC 服务文件
create_openrc_service() {
    local install_dir="$1"
    local conf_file="$2"
    local openrc_service_file="/etc/init.d/snell"

    cat > ${openrc_service_file} << EOF
#!/sbin/openrc-run

name="snell"
description="Snell Proxy Service"
command="${install_dir}/snell-server"
command_args="-c ${conf_file}"
command_user="nobody"
command_group="nogroup"
pidfile="/var/run/snell.pid"
command_background="yes"

depend() {
    need net
    after firewall
}

start_pre() {
    checkpath --directory --owner \$command_user:\$command_group --mode 0755 /run
}
EOF

    chmod +x ${openrc_service_file}
}

# 创建 Systemd 服务文件
create_systemd_service() {
    local install_dir="$1"
    local conf_file="$2"
    local systemd_service_file="/lib/systemd/system/snell.service"

    cat > ${systemd_service_file} << EOF
[Unit]
Description=Snell Proxy Service
After=network.target

[Service]
Type=simple
User=nobody
Group=nogroup
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
            systemctl status snell
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
    echo "  $0 -i <zip文件>       # 直接安装本地zip文件"
    echo "  $0 -h                 # 显示此帮助信息"
    echo ""
    echo "示例："
    echo "  $0 -i snell-server-v5.0.0-linux-amd64.zip"
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

# 安装 Snell（支持本地文件和在线下载）
install_snell() {
    echo -e "${CYAN}正在安装 Snell ${SNELL_VERSION}${RESET}"

    # 等待其他包管理器进程完成
    wait_for_package_manager

    # 检测初始化系统
    INIT_SYSTEM=$(detect_init_system)
    echo -e "${CYAN}检测到初始化系统: ${INIT_SYSTEM}${RESET}"

    # 安装必要的软件包
    if command -v apt &> /dev/null; then
        apt update && apt install -y wget unzip
    elif command -v apk &> /dev/null; then
        apk update && apk add --no-cache wget unzip
    else
        echo -e "${RED}不支持的包管理器${RESET}"
        exit 1
    fi

    ARCH=$(arch)
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
        # 在线下载 Snell 服务器文件
        SNELL_URL=""
        if [[ ${ARCH} == "aarch64" ]]; then
            SNELL_URL="https://dl.nssurge.com/snell/snell-server-${SNELL_VERSION}-linux-aarch64.zip"
        else
            SNELL_URL="https://dl.nssurge.com/snell/snell-server-${SNELL_VERSION}-linux-amd64.zip"
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

    # 创建配置文件目录
    mkdir -p ${CONF_DIR}

    # 创建配置文件
    cat > ${CONF_FILE} << EOF
[snell-server]
dns = 1.1.1.1, 8.8.8.8, 2001:4860:4860::8888
listen = ::0:${RANDOM_PORT}
psk = ${RANDOM_PSK}
ipv6 = true
EOF

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

    # 显示 v5 版本的客户端兼容性警告
    echo -e "${YELLOW}注意：您安装了 Snell v5，请检查您的客户端是否支持 v5 协议。${RESET}"
    echo -e "${YELLOW}如果客户端不支持 v5，可以将下面配置中的 version = 5 改为 version = 4${RESET}"
    echo ""

    echo "${IP_COUNTRY} = snell, ${HOST_IP}, ${RANDOM_PORT}, psk = ${RANDOM_PSK}, version = 5, reuse = true, tfo = true"
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
    ARCH=$(arch)
    SNELL_URL=""
    INSTALL_DIR="/usr/local/bin"

    if [[ ${ARCH} == "aarch64" ]]; then
        SNELL_URL="https://dl.nssurge.com/snell/snell-server-${SNELL_VERSION}-linux-aarch64.zip"
    else
        SNELL_URL="https://dl.nssurge.com/snell/snell-server-${SNELL_VERSION}-linux-amd64.zip"
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
    sed -i "s/^listen = ::0:[0-9]\+/listen = ::0:${NEW_PORT}/" "${CONF_FILE}"
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

    # 添加固定选项
    ip_list+=("::0")  # 监听所有IPv4和IPv6地址
    ip_list+=("0.0.0.0")  # 仅监听所有IPv4地址

    # 获取公网IP
    public_ip=$(curl -s http://checkip.amazonaws.com)
    if [ ! -z "${public_ip}" ]; then
        ip_list+=("${public_ip}")
        PUBLIC_IP_OPTION=3
    fi

    # 获取本地IPv4地址
    while IFS= read -r ip; do
        ip_list+=("${ip}")
    done <<< "$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1')"

    # 获取本地IPv6地址
    while IFS= read -r ip; do
        ip_list+=("${ip}")
    done <<< "$(ip -6 addr show | grep -oP '(?<=inet6\s)[0-9a-fA-F:]+' | grep -v '^fe80' | grep -v '^::1$')"

    # 显示IP列表
    echo -e "${CYAN}可用的IP地址：${RESET}"
    echo "1. ${ip_list[0]} (监听所有IPv4和IPv6地址)"
    echo "2. ${ip_list[1]} (仅监听所有IPv4地址)"

    local option_num=3
    if [ ! -z "${public_ip}" ]; then
        echo "${option_num}. ${ip_list[2]} (公网IP)"
        option_num=$((option_num + 1))
    fi

    # 显示本地IPv4地址
    local ipv4_start=${option_num}
    local ipv4_count=0
    while [ ${ipv4_count} -lt $(grep -c '^[0-9]' <<< "$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1')") ]; do
        echo "${option_num}. ${ip_list[${option_num}-1]}"
        option_num=$((option_num + 1))
        ipv4_count=$((ipv4_count + 1))
    done

    # 显示本地IPv6地址
    if [ $ipv4_count -gt 0 ]; then
        echo -e "\n本地IPv6地址："
    fi
    while [ ${option_num} -lt ${#ip_list[@]} ]; do
        echo "${option_num}. ${ip_list[${option_num}-1]}"
        option_num=$((option_num + 1))
    done

    echo "${option_num}. 自定义IP地址"
    LAST_OPTION=${option_num}

    # 导出IP列表供其他函数使用
    export IP_LIST=("${ip_list[@]}")
}

# 获取指定选项对应的IP地址
get_ip_by_option() {
    local option=$1

    # 检查选项是否在有效范围内
    if [ ${option} -ge 1 ] && [ ${option} -lt ${LAST_OPTION} ]; then
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

    case "${ip_choice}" in
        1)
            NEW_IP="::0"
            ;;
        2)
            NEW_IP="0.0.0.0"
            ;;
        ${PUBLIC_IP_OPTION})
            NEW_IP=$(curl -s http://checkip.amazonaws.com)
            ;;
        ${LAST_OPTION})
            read -p "请输入要监听的IP地址: " NEW_IP
            # 简单的IP地址格式验证
            if ! [[ ${NEW_IP} =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && ! [[ ${NEW_IP} =~ ^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$ ]]; then
                echo -e "${RED}无效的IP地址格式${RESET}"
                return
            fi
            ;;
        *)
            if [ "${ip_choice}" -gt 2 ] && [ "${ip_choice}" -lt "${LAST_OPTION}" ]; then
                # 获取选择的IP地址
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
            ;;
    esac

    # 获取当前端口号
    CURRENT_PORT=$(grep "listen" "${CONF_FILE}" | grep -o '[0-9]\+$')

    # 更新配置文件中的监听地址
    sed -i "s/^listen = .*:/listen = ${NEW_IP}:/" "${CONF_FILE}"
    if [ $? -ne 0 ]; then
        echo -e "${RED}更新监听IP失败。${RESET}"
        return
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
        echo "0. 返回主菜单"
        echo -e "${GREEN}==================${RESET}"

        read -p "请选择操作 [0-4]: " service_choice
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
    echo -e "Snell 版本: ${SNELL_VERSION}"
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
            echo -e "${GREEN}已退出 Snell${RESET}"
            exit 0
            ;;
        *)
            echo -e "${RED}无效的选项${RESET}"
            read -p "按 enter 键继续..."
            ;;
    esac
done