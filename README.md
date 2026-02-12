# Xray One-Key (REALITY)

Privacy-first, auditable deployment scripts for Xray (VLESS + REALITY + xtls-rprx-vision).

Language: English | [简体中文](README.zh-CN.md)

## Features

- VLESS + REALITY + xtls-rprx-vision on TCP
- Multi-user management scripts
- Systemd service unit
- BBR enabled
- Firewall configured (UFW or firewalld)
- Strong random UUID, shortId, and Reality key pair
- Safe handling of legacy services and configs

## Supported OS

- Ubuntu 22.04 / 24.04
- Debian 11 / 12
- Rocky / Alma 8 / 9
- CentOS 7 / 8

## Quick Start

```bash
chmod +x install.sh
sudo ./install.sh
```

You will be prompted for:

- Listen port (default 443)
- ServerName (SNI) for Reality (default www.microsoft.com)
- Public address for client links (IP or domain)

If legacy proxy services are detected, the installer will ask to stop/disable them
and optionally move legacy configs into `/opt/xray/backup-<timestamp>`.

After install, the script prints:

- Public key
- UUID
- shortId
- A ready-to-import vless:// link

## Management Scripts

Scripts are installed into `/opt/xray/scripts/` on the server.

Add user:

```bash
sudo /opt/xray/scripts/add_user.sh <username>
```

Remove user:

```bash
sudo /opt/xray/scripts/remove_user.sh <UUID>
```

List users:

```bash
sudo /opt/xray/scripts/list_users.sh
```

Export links:

```bash
sudo /opt/xray/scripts/export_links.sh
```

## Files

- `install.sh` main installer
- `scripts/` management scripts (copied into `/opt/xray/scripts/`)
- `systemd/xray.service` systemd unit template

## Notes

- Run on a fresh server for best results.
- The installer is safe to re-run and will avoid duplicate installs.
- Logs are stored in `/opt/xray/logs/`.

## License

See `LICENSE`.