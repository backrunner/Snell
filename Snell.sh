#!/bin/bash

# 定义脚本版本
SCRIPT_VERSION="20241127"

# 定义颜色代码
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
RESET='\033[0m'

# 定义 Snell 版本
SNELL_VERSION="v4.1.1"

# 定义配置目录和文件
CONF_DIR="/etc/snell"
CONF_FILE="${CONF_DIR}/snell-server.conf"

# 等待其他 apt 进程完成
wait_for_apt() {
    while fuser /var/lib/dpkg/lock >/dev/null 2>&1; do
        echo -e "${YELLOW}等待其他 apt 进程完成${RESET}"
        sleep 1
    done
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

# 安装 Snell
install_snell() {
    echo -e "${CYAN}正在安装 Snell${RESET}"

    # 等待其他 apt 进程完成
    wait_for_apt

    # 安装必要的软件包
    apt update && apt install -y wget unzip

    # 下载 Snell 服务器文件
    ARCH=$(arch)
    SNELL_URL=""
    INSTALL_DIR="/usr/local/bin"
    SYSTEMD_SERVICE_FILE="/lib/systemd/system/snell.service"

    if [[ ${ARCH} == "aarch64" ]]; then
        SNELL_URL="https://dl.nssurge.com/snell/snell-server-${SNELL_VERSION}-linux-aarch64.zip"
    else
        SNELL_URL="https://dl.nssurge.com/snell/snell-server-${SNELL_VERSION}-linux-amd64.zip"
    fi

    # 下载 Snell 服务器文件
    wget ${SNELL_URL} -O snell-server.zip
    if [ $? -ne 0 ]; then
        echo -e "${RED}下载 Snell 失败。${RESET}"
        exit 1
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

    # 创建 Systemd 服务文件
    cat > ${SYSTEMD_SERVICE_FILE} << EOF
[Unit]
Description=Snell Proxy Service
After=network.target

[Service]
Type=simple
User=nobody
Group=nogroup
LimitNOFILE=32768
ExecStart=${INSTALL_DIR}/snell-server -c ${CONF_FILE}
AmbientCapabilities=CAP_NET_BIND_SERVICE
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=snell-server

[Install]
WantedBy=multi-user.target
EOF

    # 重载 Systemd 配置
    systemctl daemon-reload
    if [ $? -ne 0 ]; then
        echo -e "${RED}重载 Systemd 配置失败。${RESET}"
        exit 1
    fi

    # 开机自启动 Snell
    systemctl enable snell
    if [ $? -ne 0 ]; then
        echo -e "${RED}开机自启动 Snell 失败。${RESET}"
        exit 1
    fi

    # 启动 Snell 服务
    systemctl start snell
    if [ $? -ne 0 ]; then
        echo -e "${RED}启动 Snell 服务失败。${RESET}"
        exit 1
    fi

    # 获取本机IP地址
    HOST_IP=$(curl -s http://checkip.amazonaws.com)

    # 获取IP所在国家
    IP_COUNTRY=$(curl -s http://ipinfo.io/${HOST_IP}/country)

    echo -e "${GREEN}Snell 安装成功${RESET}"
    echo "${IP_COUNTRY} = snell, ${HOST_IP}, ${RANDOM_PORT}, psk = ${RANDOM_PSK}, version = 4, reuse = true, tfo = true"
}

# 卸载 Snell
uninstall_snell() {
    echo -e "${CYAN}正在卸载 Snell${RESET}"

    # 停止 Snell 服务
    systemctl stop snell
    if [ $? -ne 0 ]; then
        echo -e "${RED}停止 Snell 服务失败。${RESET}"
        exit 1
    fi

    # 禁用开机自启动
    systemctl disable snell
    if [ $? -ne 0 ]; then
        echo -e "${RED}禁用开机自启动失败。${RESET}"
        exit 1
    fi

    # 删除 Systemd 服务文件
    rm /lib/systemd/system/snell.service
    if [ $? -ne 0 ]; then
        echo -e "${RED}删除 Systemd 服务文件失败。${RESET}"
        exit 1
    fi

    # 删除安装的文件和目录
    rm /usr/local/bin/snell-server
    rm -rf /etc/snell

    echo -e "${GREEN}Snell 卸载成功${RESET}"
}

# 升级 Snell
upgrade_snell() {
    echo -e "${CYAN}正在升级 Snell${RESET}"

    # 检查 Snell 是否已安装
    if ! check_snell_installed; then
        echo -e "${RED}Snell 未安装，无法升级。${RESET}"
        return
    fi

    # 停止 Snell 服务
    systemctl stop snell

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
        echo -e "${RED}下载最新版 Snell 失败。${RESET}"
        systemctl start snell
        return
    fi

    # 解压缩并替换原文件
    unzip -o snell-server.zip -d ${INSTALL_DIR}
    if [ $? -ne 0 ]; then
        echo -e "${RED}解压缩 Snell 失败。${RESET}"
        systemctl start snell
        return
    fi

    # 删除下载的 zip 文件
    rm snell-server.zip

    # 赋予执行权限
    chmod +x ${INSTALL_DIR}/snell-server

    # 启动 Snell 服务
    systemctl start snell
    if [ $? -ne 0 ]; then
        echo -e "${RED}启动 Snell 服务失败。${RESET}"
        return
    fi

    echo -e "${GREEN}Snell 升级成功${RESET}"
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

    systemctl restart snell
    if [ $? -ne 0 ]; then
        echo -e "${RED}重启 Snell 服务失败。${RESET}"
        return
    fi

    echo -e "${GREEN}PSK 已成功重新生成并应用。${RESET}"
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

    sed -i "s/^listen = ::0:[0-9]\+/listen = ::0:${NEW_PORT}/" "${CONF_FILE}"
    if [ $? -ne 0 ]; then
        echo -e "${RED}更新端口失败。${RESET}"
        return
    fi

    systemctl restart snell
    if [ $? -ne 0 ]; then
        echo -e "${RED}重启 Snell 服务失败。${RESET}"
        return
    fi

    echo -e "${GREEN}端口已成功重置为 ${NEW_PORT} 并应用。${RESET}"
}

# 配置管理子菜单
config_menu() {
    while true; do
        echo -e "${GREEN}=== 配置管理 ===${RESET}"
        echo "1. 显示当前配置"
        echo "2. 重新生成 PSK"
        echo "3. 重置端口"
        echo "0. 返回主菜单"
        echo -e "${GREEN}================${RESET}"
        read -p "请输入选项编号: " config_choice
        echo ""

        case "${config_choice}" in
            1)
                show_config
                ;;
            2)
                regenerate_psk
                ;;
            3)
                reset_port
                ;;
            0)
                break
                ;;
            *)
                echo -e "${RED}无效的选项${RESET}"
                ;;
        esac
        read -p "按 enter 键继续..."
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
    echo "0. 退出"
    echo -e "${GREEN}=====================================${RESET}"
    read -p "请输入选项编号: " choice
    echo ""
}

# 主循环
check_root
while true; do
    show_menu
    case "${choice}" in
        1)
            install_snell
            ;;
        2)
            uninstall_snell
            ;;
        3)
            upgrade_snell
            ;;
        4)
            config_menu
            ;;
        0)
            echo -e "${GREEN}已退出 Snell${RESET}"
            exit 0
            ;;
        *)
            echo -e "${RED}无效的选项${RESET}"
            ;;
    esac
    read -p "按 enter 键继续..."
done