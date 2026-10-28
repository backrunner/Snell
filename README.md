# Snell

这个 Bash 脚本可以帮助你快速部署 Snell 代理服务器。

## 一键脚本

```bash
wget -q https://raw.githubusercontent.com/backrunner/Snell/main/Snell.sh -O Snell.sh && chmod +x Snell.sh && ./Snell.sh
```
```
curl -fLsS -o Snell.sh https://raw.githubusercontent.com/backrunner/Snell/main/Snell.sh && chmod +x Snell.sh && ./Snell.sh
```

## 详细说明

- 以 root 运行，在菜单选择 `1` 安装，回车默认选择 **Snell v6.0.0 正式版**；也可选择 v5.0.1。
- 支持 Linux + systemd / OpenRC；v6 官方安装包支持 x86_64、i386、aarch64，不支持 ARMv7。
- Alpine 安装时自动补齐 `gcompat` 和 `libstdc++` 运行依赖。
- 下载来自 [Snell 官方发布页](https://kb.nssurge.com/surge-knowledge-base/zh/release-notes/snell)，版本固定为脚本内置正式版，不自动追踪 Beta 或后续版本。
- 脚本会自动生成随机端口和预共享密钥（PSK），并配置在 Snell 服务器中。
- 执行完脚本后，你会得到服务器的 IP 地址、端口号、PSK 等相关信息。

## 管理与升级

主菜单保留原编号：`3` 升级、`4` 配置管理、`5` 服务管理。主界面显示已安装版本、服务状态、自启状态和监听地址；支持 `NO_COLOR=1`。

升级先下载并检查 ZIP、可执行性和版本，再替换程序。原配置和运行/停止状态会保留，不支持直接从 v6 降级到 v5；运行中的服务若升级后启动失败，将恢复旧程序。修改配置导致重启失败时也会恢复旧配置。已停止的服务在配置修改后保持停止。

v6 客户端须支持 Snell v6，使用 `version = 6`，并与服务端的 `mode` 一致。安装后请在防火墙和云安全组开放输出的 TCP 端口。v6 已移除 QUIC Proxy Mode。

本地 ZIP 安装（仍需联网安装系统依赖）：

```bash
bash Snell.sh -i snell-server-v6.0.0-linux-amd64.zip
```

请选择与本地包匹配的 v5/v6；架构或协议不匹配会拒绝安装。已有安装请使用升级功能，避免重装覆盖配置。

## 验证

```bash
bash -n Snell.sh
shellcheck -s bash Snell.sh tests/*.sh
bash tests/regression.sh
# Linux，需 curl/unzip/python3；下载官方包，启动真实进程并检查 IPv4/IPv6 监听
bash tests/download-smoke.sh
```

回归测试使用临时目录和模拟服务，覆盖损坏包、版本不匹配、升级回滚、服务停止状态保留、多地址端口修改、IP/端口输入和 EOF；不会修改本机服务。

## License

GPL-3.0 (Based on the original version)
