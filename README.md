# Xray One-Key (Multi-Mode)

Privacy-first, auditable deployment scripts for Xray.

Language: English | [Chinese (Simplified)](README.zh-CN.md)

## Features

- Selectable deployment mode:
  - `VLESS + REALITY + xtls-rprx-vision` (TCP)
  - `VMess + WS + TLS`
  - `VMess + WS behind Nginx` (Xray no TLS, client TLS on Nginx)
  - `VLESS + WS + TLS` (CDN-friendly)
- Multi-user management scripts
- Systemd service unit
- BBR enabled
- Firewall configured (UFW or firewalld)
- Safe handling of legacy services and configs
- Interactive installer UI with `gum` (auto-install; fallback to plain prompts)
- Step progress and spinner feedback for long-running operations

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

Disable enhanced UI and use plain prompts only:

```bash
sudo ./install.sh --no-ui
```

You will be prompted for:

- Deployment mode (Reality or VMess)
- Listen port (default `443`)
- ServerName (SNI)
- Public address for client links (IP or domain)

Additional prompts for `VMess + WS + TLS`:

- WebSocket path (default `/ws`)
- TLS certificate file path
- TLS private key file path
- If cert/key are missing, installer can generate a self-signed cert

Additional prompts for `VLESS + WS + TLS`:

- WebSocket path (default `/ws`)
- TLS certificate file path
- TLS private key file path
- If cert/key are missing, installer can generate a self-signed cert

Additional prompts for `VMess + WS behind Nginx`:

- Backend listen port on Xray (for example `10000`)
- WebSocket path (default `/ws`)
- Client entry port on Nginx for link export (default `443`)
- Optional: auto update/create Nginx server config and reload Nginx

After install, the script prints a ready-to-import link (`vless://` or `vmess://` depending on mode).

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

All scripts auto-detect current mode and generate matching links.

## Files

- `install.sh` main installer
- `scripts/` management scripts (copied into `/opt/xray/scripts/`)
- `systemd/xray.service` systemd unit template

## Notes

- Run on a fresh server for best results.
- The installer is safe to re-run and will avoid duplicate installs.
- Logs are stored in `/opt/xray/logs/`.
- Log rotation is configured to prevent disk overflow (daily, keep 7 days, compressed).

## License

See `LICENSE`.
