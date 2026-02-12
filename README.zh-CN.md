# Xray 一键部署（REALITY）

面向隐私与可审计的一键部署脚本（VLESS + REALITY + xtls-rprx-vision）。

语言：简体中文 | [English](README.md)

## 功能

- VLESS + REALITY + xtls-rprx-vision（TCP）
- 多用户管理脚本
- systemd 服务
- 启用 BBR
- 自动配置防火墙（UFW 或 firewalld）
- 强随机 UUID、shortId、Reality 密钥对
- 处理旧服务与旧配置（安全迁移）

## 支持系统

- Ubuntu 22.04 / 24.04
- Debian 11 / 12
- Rocky / Alma 8 / 9
- CentOS 7 / 8

## 快速开始

```bash
chmod +x install.sh
sudo ./install.sh
```

安装过程中会提示输入：

- 监听端口（默认 443）
- Reality 伪装域名 SNI（默认 www.microsoft.com）
- 客户端链接中使用的公网地址（IP 或域名）

如果检测到旧的代理服务，安装器会提示停止/禁用并可选将旧配置移动到
`/opt/xray/backup-<timestamp>`。

安装完成后会输出：

- Public key
- UUID
- shortId
- 可直接导入的 vless:// 链接

## 管理脚本

脚本会安装到服务器的 `/opt/xray/scripts/`。

新增用户：

```bash
sudo /opt/xray/scripts/add_user.sh <username>
```

删除用户：

```bash
sudo /opt/xray/scripts/remove_user.sh <UUID>
```

列出用户：

```bash
sudo /opt/xray/scripts/list_users.sh
```

导出全部链接：

```bash
sudo /opt/xray/scripts/export_links.sh
```

## 文件说明

- `install.sh` 主安装脚本
- `scripts/` 管理脚本（会复制到 `/opt/xray/scripts/`）
- `systemd/xray.service` systemd 服务模板

## 说明

- 建议在全新服务器上运行。
- 脚本可重复执行，不会重复安装。
- 日志目录：`/opt/xray/logs/`。

## License

见 `LICENSE`。