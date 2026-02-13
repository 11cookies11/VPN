#!/usr/bin/env bash
set -euo pipefail

NO_UI=0
USE_GUM=0
STEP_CURRENT=0
STEP_TOTAL=12

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --no-ui)
        NO_UI=1
        ;;
      *)
        echo "Unknown option: $1" >&2
        echo "Usage: $0 [--no-ui]" >&2
        exit 1
        ;;
    esac
    shift
  done
}

ui_info() {
  local msg="$1"
  if [ "$USE_GUM" -eq 1 ]; then
    gum style --foreground 212 "INFO  ${msg}"
  else
    echo "[INFO] ${msg}"
  fi
}

ui_warn() {
  local msg="$1"
  if [ "$USE_GUM" -eq 1 ]; then
    gum style --foreground 214 "WARN  ${msg}"
  else
    echo "[WARN] ${msg}"
  fi
}

ui_success() {
  local msg="$1"
  if [ "$USE_GUM" -eq 1 ]; then
    gum style --foreground 42 "OK    ${msg}"
  else
    echo "[ OK ] ${msg}"
  fi
}

ui_error() {
  local msg="$1"
  if [ "$USE_GUM" -eq 1 ]; then
    gum style --foreground 196 "ERROR ${msg}" >&2
  else
    echo "[ERR ] ${msg}" >&2
  fi
}

ui_heading() {
  local msg="$1"
  if [ "$USE_GUM" -eq 1 ]; then
    gum style --bold --foreground 39 "${msg}"
  else
    echo ""
    echo "== ${msg} =="
  fi
}

ui_step() {
  local msg="$1"
  STEP_CURRENT=$((STEP_CURRENT + 1))
  if [ "$USE_GUM" -eq 1 ]; then
    gum style --bold --foreground 81 "[${STEP_CURRENT}/${STEP_TOTAL}] ${msg}"
  else
    echo ""
    echo "[${STEP_CURRENT}/${STEP_TOTAL}] ${msg}"
  fi
}

ui_banner() {
  if [ "$USE_GUM" -eq 1 ]; then
    gum style --border rounded --margin "1 0" --padding "1 2" --foreground 45 --border-foreground 45 \
      "Xray One-Key Installer" \
      "Interactive mode: gum"
  else
    echo "Xray One-Key Installer"
  fi
}

ui_run() {
  local title="$1"
  shift

  if [ "$USE_GUM" -eq 1 ]; then
    local log_file
    log_file="$(mktemp)"
    if gum spin --spinner dot --title "$title" -- "$@" >"$log_file" 2>&1; then
      rm -f "$log_file"
      return 0
    fi
    ui_error "${title} failed"
    cat "$log_file" >&2
    rm -f "$log_file"
    return 1
  fi

  ui_info "$title"
  "$@"
}

ui_input() {
  local prompt="$1"
  local default="$2"
  local input=""
  if [ "$USE_GUM" -eq 1 ]; then
    input="$(gum input --prompt "${prompt}: " --value "$default")"
  else
    read -r -p "${prompt} [${default}]: " input
  fi

  if [ -z "$input" ]; then
    printf "%s\n" "$default"
  else
    printf "%s\n" "$input"
  fi
}

ui_confirm() {
  local prompt="$1"
  local default="${2:-N}"

  if [ "$USE_GUM" -eq 1 ]; then
    if [ "$default" = "Y" ]; then
      gum confirm --default=true "$prompt"
    else
      gum confirm "$prompt"
    fi
    return $?
  fi

  local input
  if [ "$default" = "Y" ]; then
    read -r -p "${prompt} (Y/n): " input
    case "${input:-Y}" in
      y|Y) return 0 ;;
      *) return 1 ;;
    esac
  else
    read -r -p "${prompt} (y/N): " input
    case "${input:-N}" in
      y|Y) return 0 ;;
      *) return 1 ;;
    esac
  fi
}

ui_choose() {
  local prompt="$1"
  shift

  if [ "$USE_GUM" -eq 1 ]; then
    gum choose --header "$prompt" "$@"
    return 0
  fi

  local idx=1
  local opt
  echo "$prompt"
  for opt in "$@"; do
    echo "  ${idx}) ${opt}"
    idx=$((idx + 1))
  done

  local choice
  while true; do
    read -r -p "Select [1]: " choice
    choice="${choice:-1}"
    if [ "$choice" -ge 1 ] 2>/dev/null && [ "$choice" -le $# ] 2>/dev/null; then
      eval "printf '%s\n' \"\${$choice}\""
      return 0
    fi
    echo "Invalid selection."
  done
}

install_gum() {
  local arch raw_arch version version_plain url tmp
  raw_arch="$(uname -m)"
  case "$raw_arch" in
    x86_64|amd64) arch="x86_64" ;;
    aarch64|arm64) arch="arm64" ;;
    *)
      ui_warn "Unsupported architecture for auto-installing gum: ${raw_arch}"
      return 1
      ;;
  esac

  version="$(curl -fsSL https://api.github.com/repos/charmbracelet/gum/releases/latest | jq -r '.tag_name' || true)"
  if [ -z "$version" ] || [ "$version" = "null" ]; then
    ui_warn "Failed to detect gum latest release."
    return 1
  fi
  version_plain="${version#v}"

  tmp="$(mktemp -d)"
  case "$PKG_MGR" in
    apt)
      case "$arch" in
        x86_64) url="https://github.com/charmbracelet/gum/releases/download/${version}/gum_${version_plain}_amd64.deb" ;;
        arm64) url="https://github.com/charmbracelet/gum/releases/download/${version}/gum_${version_plain}_arm64.deb" ;;
      esac
      wget -q -O "${tmp}/gum.deb" "$url"
      dpkg -i "${tmp}/gum.deb" >/dev/null 2>&1 || apt-get install -f -y >/dev/null 2>&1
      ;;
    dnf)
      case "$arch" in
        x86_64) url="https://github.com/charmbracelet/gum/releases/download/${version}/gum_${version_plain}_x86_64.rpm" ;;
        arm64) url="https://github.com/charmbracelet/gum/releases/download/${version}/gum_${version_plain}_arm64.rpm" ;;
      esac
      wget -q -O "${tmp}/gum.rpm" "$url"
      dnf install -y "${tmp}/gum.rpm" >/dev/null 2>&1
      ;;
    yum)
      case "$arch" in
        x86_64) url="https://github.com/charmbracelet/gum/releases/download/${version}/gum_${version_plain}_x86_64.rpm" ;;
        arm64) url="https://github.com/charmbracelet/gum/releases/download/${version}/gum_${version_plain}_arm64.rpm" ;;
      esac
      wget -q -O "${tmp}/gum.rpm" "$url"
      yum localinstall -y "${tmp}/gum.rpm" >/dev/null 2>&1
      ;;
  esac

  rm -rf "$tmp"
  command -v gum >/dev/null 2>&1
}

setup_ui() {
  if [ "$NO_UI" -eq 1 ]; then
    USE_GUM=0
    return 0
  fi

  if [ ! -t 0 ] || [ ! -t 1 ]; then
    USE_GUM=0
    return 0
  fi

  if command -v gum >/dev/null 2>&1; then
    USE_GUM=1
    return 0
  fi

  ui_info "gum not found, attempting auto-install..."
  if install_gum; then
    USE_GUM=1
    ui_success "gum installed. Enhanced interactive UI enabled."
  else
    USE_GUM=0
    ui_warn "gum install failed; falling back to plain prompts."
  fi
}

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    ui_error "Must run as root"
    exit 1
  fi
}

detect_os() {
  if [ -r /etc/os-release ]; then
    . /etc/os-release
    OS_ID="${ID:-}"
    OS_LIKE="${ID_LIKE:-}"
  else
    OS_ID=""
    OS_LIKE=""
  fi
}

detect_pkg_mgr() {
  if command -v apt-get >/dev/null 2>&1; then
    PKG_MGR="apt"
  elif command -v dnf >/dev/null 2>&1; then
    PKG_MGR="dnf"
  elif command -v yum >/dev/null 2>&1; then
    PKG_MGR="yum"
  else
    ui_error "No supported package manager found"
    exit 1
  fi
}

install_deps() {
  ui_heading "Install Dependencies"
  case "$PKG_MGR" in
    apt)
      ui_run "Updating apt package index" apt-get update -y
      ui_run "Installing dependency packages" apt-get install -y curl wget unzip jq uuid-runtime openssl ufw logrotate
      ;;
    dnf)
      ui_run "Refreshing dnf package metadata" dnf makecache -y
      ui_run "Installing dependency packages" dnf install -y curl wget unzip jq util-linux openssl firewalld logrotate
      ;;
    yum)
      ui_run "Refreshing yum package metadata" yum makecache -y
      ui_run "Installing dependency packages" yum install -y curl wget unzip jq util-linux openssl firewalld logrotate
      ;;
  esac
}

install_xray() {
  ui_heading "Install Xray Core"
  if command -v xray >/dev/null 2>&1; then
    ui_info "xray already exists, skipping install."
    return 0
  fi

  local url
  url="$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r '.assets[] | select(.name|test("linux-64.zip$")) | .browser_download_url' | head -n1)"
  if [ -z "$url" ] || [ "$url" = "null" ]; then
    ui_error "Failed to fetch Xray release URL"
    exit 1
  fi

  rm -rf /tmp/xray-install
  mkdir -p /tmp/xray-install
  ui_run "Downloading Xray release" wget -O /tmp/xray-install/xray.zip "$url"
  ui_run "Extracting Xray release archive" unzip -o /tmp/xray-install/xray.zip -d /tmp/xray-install
  ui_run "Installing Xray binary" install -m 0755 /tmp/xray-install/xray /usr/local/bin/xray
  mkdir -p /usr/local/share/xray
  if [ -f /tmp/xray-install/geoip.dat ]; then
    ui_run "Installing geoip.dat" install -m 0644 /tmp/xray-install/geoip.dat /usr/local/share/xray/geoip.dat
  fi
  if [ -f /tmp/xray-install/geosite.dat ]; then
    ui_run "Installing geosite.dat" install -m 0644 /tmp/xray-install/geosite.dat /usr/local/share/xray/geosite.dat
  fi
  rm -rf /tmp/xray-install
  ui_success "Xray core installed."
}

ensure_dirs() {
  mkdir -p /opt/xray/config /opt/xray/keys /opt/xray/logs /opt/xray/scripts
}

list_existing_services() {
  local candidates=(xray v2ray trojan trojan-go sing-box singbox shadowsocks-libev ssserver clash)
  local found=()
  local svc
  for svc in "${candidates[@]}"; do
    if systemctl list-unit-files --type=service 2>/dev/null | awk '{print $1}' | grep -qx "${svc}.service"; then
      found+=("${svc}.service")
    fi
  done
  printf "%s\n" "${found[@]}"
}

stop_disable_services() {
  local services=("$@")
  local svc
  for svc in "${services[@]}"; do
    systemctl stop "$svc" >/dev/null 2>&1 || true
    systemctl disable "$svc" >/dev/null 2>&1 || true
  done
}

backup_legacy_paths() {
  local ts
  ts="$(date +%Y%m%d-%H%M%S)"
  local backup_dir="/opt/xray/backup-${ts}"
  local paths=(/etc/xray /etc/v2ray /usr/local/etc/xray /usr/local/etc/v2ray /opt/v2ray /opt/xray)
  local moved=0

  mkdir -p "$backup_dir"
  local p
  for p in "${paths[@]}"; do
    if [ -e "$p" ] && [ "$p" != "/opt/xray" ]; then
      mv "$p" "$backup_dir/" || true
      moved=1
    fi
  done

  if [ "$moved" -eq 0 ]; then
    rmdir "$backup_dir" 2>/dev/null || true
  fi
}

handle_legacy() {
  ui_heading "Legacy Services Check"
  local services=()
  while IFS= read -r line; do
    [ -n "$line" ] && services+=("$line")
  done < <(list_existing_services)

  if [ "${#services[@]}" -gt 0 ]; then
    ui_warn "Detected existing proxy services:"
    printf " - %s\n" "${services[@]}"
    if ui_confirm "Stop and disable these services?" "N"; then
      stop_disable_services "${services[@]}"
      ui_success "Legacy services stopped/disabled."
    fi
  fi

  if [ -d /etc/xray ] || [ -d /etc/v2ray ] || [ -d /usr/local/etc/xray ] || [ -d /usr/local/etc/v2ray ] || [ -d /opt/v2ray ]; then
    ui_warn "Detected legacy config directories."
    if ui_confirm "Move legacy configs to /opt/xray/backup-<timestamp>?" "N"; then
      backup_legacy_paths
      ui_success "Legacy configs moved to backup."
    fi
  fi
}

ask() {
  local prompt="$1"
  local default="$2"
  ui_input "$prompt" "$default"
}

ask_protocol() {
  local choice
  choice="$(ui_choose \
    "Select deployment mode" \
    "VLESS + REALITY (TCP)" \
    "VMess + WS + TLS" \
    "VMess + WS behind Nginx (no TLS on Xray, client TLS on 443)" \
    "VLESS + WS + TLS (CDN-friendly)")"

  case "$choice" in
    "VLESS + REALITY (TCP)")
      PROTOCOL="vless-reality"
      ;;
    "VMess + WS + TLS")
      PROTOCOL="vmess-ws-tls"
      ;;
    "VMess + WS behind Nginx (no TLS on Xray, client TLS on 443)")
      PROTOCOL="vmess-ws-nginx"
      ;;
    "VLESS + WS + TLS (CDN-friendly)")
      PROTOCOL="vless-ws-tls"
      ;;
    *)
      ui_error "Invalid deployment mode"
      exit 1
      ;;
  esac
}

gen_reality_keys() {
  if [ ! -f /opt/xray/keys/private.key ] || [ ! -f /opt/xray/keys/public.key ]; then
    if ! /usr/local/bin/xray x25519 >/dev/null 2>&1; then
      ui_error "This Xray build does not support x25519 (required by REALITY)."
      exit 1
    fi

    local out priv pub
    out="$(/usr/local/bin/xray x25519 2>&1 || true)"
    out="$(printf "%s\n" "$out" | tr -d '\r')"
    priv="$(printf "%s\n" "$out" | awk -F':' 'tolower($0) ~ /private[[:space:]]*key/ {gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); print $2; exit}')"
    pub="$(printf "%s\n" "$out" | awk -F':' 'tolower($1) ~ /public[[:space:]]*key/ || tolower($1) ~ /password/ {gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); print $2; exit}')"
    if [ -z "$priv" ] || [ -z "$pub" ]; then
      ui_error "Failed to generate X25519 keys"
      echo "xray x25519 output:" >&2
      printf "%s\n" "$out" >&2
      exit 1
    fi
    printf "%s" "$priv" > /opt/xray/keys/private.key
    printf "%s" "$pub" > /opt/xray/keys/public.key
  fi

  if [ ! -f /opt/xray/keys/shortid ]; then
    openssl rand -hex 4 > /opt/xray/keys/shortid
  fi
}

ensure_uuid() {
  if [ ! -f /opt/xray/keys/uuid ]; then
    uuidgen > /opt/xray/keys/uuid
  fi
}

generate_self_signed_cert() {
  local sni="$1"
  local cert_file="$2"
  local key_file="$3"
  local cert_dir key_dir

  cert_dir="$(dirname "$cert_file")"
  key_dir="$(dirname "$key_file")"
  mkdir -p "$cert_dir" "$key_dir"

  openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
    -subj "/CN=${sni}" \
    -keyout "$key_file" \
    -out "$cert_file" >/dev/null 2>&1
}

write_vless_reality_config() {
  local cfg="$1"
  local port="$2"
  local sni="$3"

  echo "$PROTOCOL" > /opt/xray/keys/protocol
  echo "$port" > /opt/xray/keys/port
  echo "$sni" > /opt/xray/keys/server_name

  gen_reality_keys
  ensure_uuid

  local priv uuid shortid
  priv="$(cat /opt/xray/keys/private.key)"
  uuid="$(cat /opt/xray/keys/uuid)"
  shortid="$(cat /opt/xray/keys/shortid)"

  cat > "$cfg" <<EOF
{
  "log": {
    "access": "/opt/xray/logs/access.log",
    "error": "/opt/xray/logs/error.log",
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "tag": "vless-in",
      "listen": "0.0.0.0",
      "port": $port,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$uuid",
            "flow": "xtls-rprx-vision",
            "email": "default"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "$sni:443",
          "xver": 0,
          "serverNames": ["$sni"],
          "privateKey": "$priv",
          "shortIds": ["$shortid"]
        },
        "tcpSettings": {
          "acceptProxyProtocol": false
        },
        "sockopt": {
          "tcpFastOpen": true
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    }
  ]
}
EOF
}

write_vmess_ws_tls_config() {
  local cfg="$1"
  local port="$2"
  local sni="$3"
  local ws_path="$4"

  ensure_uuid

  local cert_file key_file
  cert_file="$(ask "TLS certificate file" "/opt/xray/keys/fullchain.pem")"
  key_file="$(ask "TLS private key file" "/opt/xray/keys/privkey.pem")"

  if [ ! -f "$cert_file" ] || [ ! -f "$key_file" ]; then
    if ui_confirm "TLS files not found. Generate self-signed cert now?" "Y"; then
      generate_self_signed_cert "$sni" "$cert_file" "$key_file"
    else
      ui_error "VMess+WS+TLS requires certificate and key files."
      exit 1
    fi
  fi

  echo "$PROTOCOL" > /opt/xray/keys/protocol
  echo "$port" > /opt/xray/keys/port
  echo "$port" > /opt/xray/keys/client_port
  echo "$sni" > /opt/xray/keys/server_name
  echo "$ws_path" > /opt/xray/keys/ws_path
  echo "$cert_file" > /opt/xray/keys/tls_cert
  echo "$key_file" > /opt/xray/keys/tls_key

  local uuid
  uuid="$(cat /opt/xray/keys/uuid)"

  cat > "$cfg" <<EOF
{
  "log": {
    "access": "/opt/xray/logs/access.log",
    "error": "/opt/xray/logs/error.log",
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "tag": "vmess-in",
      "listen": "0.0.0.0",
      "port": $port,
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "$uuid",
            "alterId": 0,
            "email": "default"
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "$cert_file",
              "keyFile": "$key_file"
            }
          ]
        },
        "wsSettings": {
          "path": "$ws_path",
          "headers": {
            "Host": "$sni"
          }
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    }
  ]
}
EOF
}

write_vless_ws_tls_config() {
  local cfg="$1"
  local port="$2"
  local sni="$3"
  local ws_path="$4"

  ensure_uuid

  local cert_file key_file
  cert_file="$(ask "TLS certificate file" "/opt/xray/keys/fullchain.pem")"
  key_file="$(ask "TLS private key file" "/opt/xray/keys/privkey.pem")"

  if [ ! -f "$cert_file" ] || [ ! -f "$key_file" ]; then
    if ui_confirm "TLS files not found. Generate self-signed cert now?" "Y"; then
      generate_self_signed_cert "$sni" "$cert_file" "$key_file"
    else
      ui_error "VLESS+WS+TLS requires certificate and key files."
      exit 1
    fi
  fi

  echo "$PROTOCOL" > /opt/xray/keys/protocol
  echo "$port" > /opt/xray/keys/port
  echo "$port" > /opt/xray/keys/client_port
  echo "$sni" > /opt/xray/keys/server_name
  echo "$ws_path" > /opt/xray/keys/ws_path
  echo "$cert_file" > /opt/xray/keys/tls_cert
  echo "$key_file" > /opt/xray/keys/tls_key

  local uuid
  uuid="$(cat /opt/xray/keys/uuid)"

  cat > "$cfg" <<EOF
{
  "log": {
    "access": "/opt/xray/logs/access.log",
    "error": "/opt/xray/logs/error.log",
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "tag": "vless-ws-tls-in",
      "listen": "0.0.0.0",
      "port": $port,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$uuid",
            "email": "default"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "$cert_file",
              "keyFile": "$key_file"
            }
          ]
        },
        "wsSettings": {
          "path": "$ws_path",
          "headers": {
            "Host": "$sni"
          }
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    }
  ]
}
EOF
}

write_vmess_ws_nginx_config() {
  local cfg="$1"
  local backend_port="$2"
  local sni="$3"
  local ws_path="$4"
  local client_port

  ensure_uuid
  client_port="$(ask "Client entry port on Nginx (for link export)" "443")"

  echo "$PROTOCOL" > /opt/xray/keys/protocol
  echo "$backend_port" > /opt/xray/keys/port
  echo "$client_port" > /opt/xray/keys/client_port
  echo "$sni" > /opt/xray/keys/server_name
  echo "$ws_path" > /opt/xray/keys/ws_path

  local uuid
  uuid="$(cat /opt/xray/keys/uuid)"

  cat > "$cfg" <<EOF
{
  "log": {
    "access": "/opt/xray/logs/access.log",
    "error": "/opt/xray/logs/error.log",
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "tag": "vmess-in-nginx",
      "listen": "127.0.0.1",
      "port": $backend_port,
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "$uuid",
            "alterId": 0,
            "email": "default"
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "path": "$ws_path",
          "headers": {
            "Host": "$sni"
          }
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    }
  ]
}
EOF
}

write_config() {
  ui_heading "Configure Xray"
  local cfg=/opt/xray/config/config.json

  if [ -f "$cfg" ]; then
    if ! ui_confirm "Config already exists. Overwrite?" "N"; then
      ui_warn "Keeping existing config."
      return 0
    fi
  fi

  ask_protocol

  local port sni
  port="$(ask "Listen port" "443")"
  if command -v ss >/dev/null 2>&1; then
    while ss -lntp 2>/dev/null | awk '{print $4}' | grep -q ":${port}$"; do
      ui_warn "Port ${port} is already in use."
      port="$(ask "Listen port" "443")"
    done
  fi
  sni="$(ask "ServerName(SNI)" "www.microsoft.com")"

  case "$PROTOCOL" in
    vless-reality)
      write_vless_reality_config "$cfg" "$port" "$sni"
      ;;
    vmess-ws-tls)
      local ws_path
      ws_path="$(ask "WebSocket path" "/ws")"
      write_vmess_ws_tls_config "$cfg" "$port" "$sni" "$ws_path"
      ;;
    vmess-ws-nginx)
      local ws_path
      ws_path="$(ask "WebSocket path" "/ws")"
      write_vmess_ws_nginx_config "$cfg" "$port" "$sni" "$ws_path"
      ;;
    vless-ws-tls)
      local ws_path
      ws_path="$(ask "WebSocket path" "/ws")"
      write_vless_ws_tls_config "$cfg" "$port" "$sni" "$ws_path"
      ;;
    *)
      ui_error "Unsupported protocol: $PROTOCOL"
      exit 1
      ;;
  esac

  jq -e . "$cfg" >/dev/null
  ui_success "Config written: ${cfg}"
}

configure_server_addr() {
  ui_heading "Configure Link Address"
  local addr_file=/opt/xray/keys/server_addr
  local auto_ip=""
  auto_ip="$(curl -s https://api.ipify.org || true)"
  local addr
  addr="$(ask "Public address for client link (IP or domain)" "${auto_ip:-YOUR_SERVER_IP}")"
  echo "$addr" > "$addr_file"
}

write_systemd() {
  ui_heading "Install Systemd Service"
  cat > /etc/systemd/system/xray.service <<'EOF'
[Unit]
Description=Xray Service
After=network.target nss-lookup.target

[Service]
Type=simple
ExecStart=/usr/local/bin/xray run -config /opt/xray/config/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
  ui_run "Reloading systemd daemon" systemctl daemon-reload
  ui_run "Enabling xray service" systemctl enable xray
}

enable_bbr() {
  ui_heading "Tune Kernel (BBR)"
  cat > /etc/sysctl.d/99-xray-bbr.conf <<'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
  ui_run "Applying sysctl settings" sysctl --system
}

configure_logrotate() {
  ui_heading "Configure Log Rotation"
  cat > /etc/logrotate.d/xray <<'EOF'
/opt/xray/logs/access.log /opt/xray/logs/error.log {
  daily
  rotate 7
  compress
  missingok
  notifempty
  copytruncate
}
EOF
  ui_success "Logrotate rule installed."
}

configure_firewall() {
  ui_heading "Configure Firewall"
  local protocol fw_port
  protocol="$(cat /opt/xray/keys/protocol 2>/dev/null || echo "vless-reality")"
  fw_port="$(cat /opt/xray/keys/port)"
  if [ "$protocol" = "vmess-ws-nginx" ]; then
    fw_port="$(cat /opt/xray/keys/client_port 2>/dev/null || echo "443")"
  fi

  if command -v ufw >/dev/null 2>&1; then
    ui_run "Allowing SSH in UFW" ufw allow OpenSSH
    ui_run "Allowing ${fw_port}/tcp in UFW" ufw allow "${fw_port}/tcp"
    ui_run "Setting UFW default deny incoming" ufw default deny incoming
    ui_run "Enabling UFW" ufw --force enable
  elif command -v firewall-cmd >/dev/null 2>&1; then
    ui_run "Ensuring firewalld service is running" systemctl enable --now firewalld
    ui_run "Allowing SSH in firewalld" firewall-cmd --permanent --add-service=ssh
    ui_run "Allowing ${fw_port}/tcp in firewalld" firewall-cmd --permanent --add-port="${fw_port}/tcp"
    ui_run "Setting firewalld default zone to public" firewall-cmd --permanent --set-default-zone=public
    ui_run "Reloading firewalld rules" firewall-cmd --reload
  fi
}

configure_nginx_for_vmess_ws_nginx() {
  ui_heading "Configure Nginx (Optional)"
  local protocol
  protocol="$(cat /opt/xray/keys/protocol 2>/dev/null || echo "vless-reality")"
  if [ "$protocol" != "vmess-ws-nginx" ]; then
    return 0
  fi

  if ! command -v nginx >/dev/null 2>&1; then
    ui_warn "Nginx not found, skip auto Nginx config."
    return 0
  fi

  if ! ui_confirm "Auto configure Nginx reverse proxy now?" "Y"; then
    return 0
  fi

  local sni ws_path backend_port client_port
  sni="$(cat /opt/xray/keys/server_name)"
  ws_path="$(cat /opt/xray/keys/ws_path 2>/dev/null || echo "/ws")"
  backend_port="$(cat /opt/xray/keys/port)"
  client_port="$(cat /opt/xray/keys/client_port 2>/dev/null || echo "443")"

  local conf_file
  conf_file="$(ask "Nginx server config file to update" "/etc/nginx/conf.d/${sni}.conf")"

  local block
  block="$(cat <<EOF
# BEGIN XRAY_WS_PROXY
location ${ws_path} {
    proxy_pass http://127.0.0.1:${backend_port};
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host \$host;
    proxy_read_timeout 3600;
}
# END XRAY_WS_PROXY
EOF
)"

  if [ -f "$conf_file" ]; then
    local tmp
    tmp="$(mktemp)"

    # Remove previous managed block before re-inserting.
    awk '
      /# BEGIN XRAY_WS_PROXY/ {skip=1; next}
      /# END XRAY_WS_PROXY/ {skip=0; next}
      !skip {print}
    ' "$conf_file" > "$tmp"
    mv "$tmp" "$conf_file"

    tmp="$(mktemp)"
    awk -v block="$block" '
      { lines[NR]=$0 }
      END {
        inserted=0
        for (i=1; i<=NR; i++) {
          if (!inserted && lines[i] ~ /^[[:space:]]*}[[:space:]]*$/) {
            print block
            inserted=1
          }
          print lines[i]
        }
        if (!inserted) {
          print block
        }
      }
    ' "$conf_file" > "$tmp"
    mv "$tmp" "$conf_file"
  else
    local cert_file key_file
    cert_file="$(ask "Nginx TLS cert path" "/etc/nginx/ssl/cf.crt")"
    key_file="$(ask "Nginx TLS key path" "/etc/nginx/ssl/cf.key")"
    mkdir -p "$(dirname "$conf_file")"
    cat > "$conf_file" <<EOF
server {
    listen ${client_port} ssl http2;
    server_name ${sni};

    ssl_certificate ${cert_file};
    ssl_certificate_key ${key_file};

    location / {
        return 200 "OK";
    }

${block}
}
EOF
  fi

  if nginx -t >/dev/null 2>&1; then
    systemctl reload nginx
    ui_success "Nginx config applied: ${conf_file}"
  else
    ui_error "Nginx config test failed. Please check: ${conf_file}"
    return 1
  fi
}

install_scripts() {
  cat > /opt/xray/scripts/add_user.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Must run as root" >&2
  exit 1
fi

if [ $# -ne 1 ]; then
  echo "Usage: add_user.sh <username>" >&2
  exit 1
fi

username="$1"
config="/opt/xray/config/config.json"
protocol="$(cat /opt/xray/keys/protocol 2>/dev/null || echo "vless-reality")"
tmp="$(mktemp)"
uuid="$(uuidgen)"

case "$protocol" in
  vless-reality)
    jq --arg id "$uuid" --arg email "$username" \
      '.inbounds[0].settings.clients += [{"id":$id,"flow":"xtls-rprx-vision","email":$email}]' \
      "$config" > "$tmp"
    ;;
  vless-ws-tls)
    jq --arg id "$uuid" --arg email "$username" \
      '.inbounds[0].settings.clients += [{"id":$id,"email":$email}]' \
      "$config" > "$tmp"
    ;;
  vmess-ws-tls)
    jq --arg id "$uuid" --arg email "$username" \
      '.inbounds[0].settings.clients += [{"id":$id,"alterId":0,"email":$email}]' \
      "$config" > "$tmp"
    ;;
  vmess-ws-nginx)
    jq --arg id "$uuid" --arg email "$username" \
      '.inbounds[0].settings.clients += [{"id":$id,"alterId":0,"email":$email}]' \
      "$config" > "$tmp"
    ;;
  *)
    echo "Unsupported protocol: $protocol" >&2
    exit 1
    ;;
esac

jq -e . "$tmp" >/dev/null
mv "$tmp" "$config"

systemctl restart xray

sni="$(cat /opt/xray/keys/server_name)"
port="$(cat /opt/xray/keys/port)"
addr="$(cat /opt/xray/keys/server_addr)"
if [ -z "$addr" ]; then
  addr="YOUR_SERVER_IP"
fi

case "$protocol" in
  vless-reality)
    pub="$(cat /opt/xray/keys/public.key)"
    shortid="$(cat /opt/xray/keys/shortid)"
    echo "vless://${uuid}@${addr}:${port}?encryption=none&security=reality&sni=${sni}&fp=chrome&pbk=${pub}&sid=${shortid}&type=tcp&flow=xtls-rprx-vision#${username}"
    ;;
  vless-ws-tls)
    client_port="$(cat /opt/xray/keys/client_port 2>/dev/null || cat /opt/xray/keys/port)"
    ws_path="$(cat /opt/xray/keys/ws_path 2>/dev/null || echo "/ws")"
    ws_path_enc="${ws_path//\//%2F}"
    echo "vless://${uuid}@${addr}:${client_port}?encryption=none&security=tls&sni=${sni}&type=ws&host=${sni}&path=${ws_path_enc}#${username}"
    ;;
  vmess-ws-tls)
    client_port="$(cat /opt/xray/keys/client_port 2>/dev/null || cat /opt/xray/keys/port)"
    ws_path="$(cat /opt/xray/keys/ws_path 2>/dev/null || echo "/ws")"
    vmess_json="$(jq -nc \
      --arg ps "$username" \
      --arg add "$addr" \
      --arg port "$client_port" \
      --arg id "$uuid" \
      --arg host "$sni" \
      --arg path "$ws_path" \
      --arg sni "$sni" \
      '{v:"2",ps:$ps,add:$add,port:$port,id:$id,aid:"0",scy:"auto",net:"ws",type:"none",host:$host,path:$path,tls:"tls",sni:$sni,alpn:"http/1.1"}')"
    echo "vmess://$(printf "%s" "$vmess_json" | base64 | tr -d '\n')"
    ;;
  vmess-ws-nginx)
    client_port="$(cat /opt/xray/keys/client_port 2>/dev/null || echo "443")"
    ws_path="$(cat /opt/xray/keys/ws_path 2>/dev/null || echo "/ws")"
    vmess_json="$(jq -nc \
      --arg ps "$username" \
      --arg add "$addr" \
      --arg port "$client_port" \
      --arg id "$uuid" \
      --arg host "$sni" \
      --arg path "$ws_path" \
      --arg sni "$sni" \
      '{v:"2",ps:$ps,add:$add,port:$port,id:$id,aid:"0",scy:"auto",net:"ws",type:"none",host:$host,path:$path,tls:"tls",sni:$sni,alpn:"http/1.1"}')"
    echo "vmess://$(printf "%s" "$vmess_json" | base64 | tr -d '\n')"
    ;;
esac
EOF

  cat > /opt/xray/scripts/remove_user.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Must run as root" >&2
  exit 1
fi

if [ $# -ne 1 ]; then
  echo "Usage: remove_user.sh <UUID>" >&2
  exit 1
fi

uuid="$1"
config="/opt/xray/config/config.json"
tmp="$(mktemp)"

jq --arg id "$uuid" \
  '(.inbounds[0].settings.clients) |= map(select(.id != $id))' \
  "$config" > "$tmp"

jq -e . "$tmp" >/dev/null
mv "$tmp" "$config"

systemctl restart xray
EOF

  cat > /opt/xray/scripts/list_users.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Must run as root" >&2
  exit 1
fi

jq -r '.inbounds[0].settings.clients[] | "\(.email)\t\(.id)"' /opt/xray/config/config.json
EOF

  cat > /opt/xray/scripts/export_links.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Must run as root" >&2
  exit 1
fi

protocol="$(cat /opt/xray/keys/protocol 2>/dev/null || echo "vless-reality")"
sni="$(cat /opt/xray/keys/server_name)"
port="$(cat /opt/xray/keys/port)"
addr="$(cat /opt/xray/keys/server_addr)"
if [ -z "$addr" ]; then
  addr="YOUR_SERVER_IP"
fi

jq -r '.inbounds[0].settings.clients[] | "\(.email)\t\(.id)"' /opt/xray/config/config.json | while IFS=$'\t' read -r email uuid; do
  case "$protocol" in
    vless-reality)
      pub="$(cat /opt/xray/keys/public.key)"
      shortid="$(cat /opt/xray/keys/shortid)"
      echo "vless://${uuid}@${addr}:${port}?encryption=none&security=reality&sni=${sni}&fp=chrome&pbk=${pub}&sid=${shortid}&type=tcp&flow=xtls-rprx-vision#${email}"
      ;;
    vless-ws-tls)
      client_port="$(cat /opt/xray/keys/client_port 2>/dev/null || cat /opt/xray/keys/port)"
      ws_path="$(cat /opt/xray/keys/ws_path 2>/dev/null || echo "/ws")"
      ws_path_enc="${ws_path//\//%2F}"
      echo "vless://${uuid}@${addr}:${client_port}?encryption=none&security=tls&sni=${sni}&type=ws&host=${sni}&path=${ws_path_enc}#${email}"
      ;;
    vmess-ws-tls)
      client_port="$(cat /opt/xray/keys/client_port 2>/dev/null || cat /opt/xray/keys/port)"
      ws_path="$(cat /opt/xray/keys/ws_path 2>/dev/null || echo "/ws")"
      vmess_json="$(jq -nc \
        --arg ps "$email" \
        --arg add "$addr" \
        --arg port "$client_port" \
        --arg id "$uuid" \
        --arg host "$sni" \
        --arg path "$ws_path" \
        --arg sni "$sni" \
        '{v:"2",ps:$ps,add:$add,port:$port,id:$id,aid:"0",scy:"auto",net:"ws",type:"none",host:$host,path:$path,tls:"tls",sni:$sni,alpn:"http/1.1"}')"
      echo "vmess://$(printf "%s" "$vmess_json" | base64 | tr -d '\n')"
      ;;
    vmess-ws-nginx)
      client_port="$(cat /opt/xray/keys/client_port 2>/dev/null || echo "443")"
      ws_path="$(cat /opt/xray/keys/ws_path 2>/dev/null || echo "/ws")"
      vmess_json="$(jq -nc \
        --arg ps "$email" \
        --arg add "$addr" \
        --arg port "$client_port" \
        --arg id "$uuid" \
        --arg host "$sni" \
        --arg path "$ws_path" \
        --arg sni "$sni" \
        '{v:"2",ps:$ps,add:$add,port:$port,id:$id,aid:"0",scy:"auto",net:"ws",type:"none",host:$host,path:$path,tls:"tls",sni:$sni,alpn:"http/1.1"}')"
      echo "vmess://$(printf "%s" "$vmess_json" | base64 | tr -d '\n')"
      ;;
  esac
done
EOF

  chmod +x /opt/xray/scripts/add_user.sh \
           /opt/xray/scripts/remove_user.sh \
           /opt/xray/scripts/list_users.sh \
           /opt/xray/scripts/export_links.sh
}

print_output() {
  ui_heading "Connection Output"
  local protocol uuid addr sni port
  protocol="$(cat /opt/xray/keys/protocol 2>/dev/null || echo "vless-reality")"
  uuid="$(cat /opt/xray/keys/uuid)"
  sni="$(cat /opt/xray/keys/server_name)"
  port="$(cat /opt/xray/keys/port)"
  addr="$(cat /opt/xray/keys/server_addr)"
  if [ -z "$addr" ]; then
    addr="YOUR_SERVER_IP"
  fi

  ui_info "Protocol: $protocol"
  ui_info "UUID: $uuid"

  case "$protocol" in
    vless-reality)
      local pub shortid
      pub="$(cat /opt/xray/keys/public.key)"
      shortid="$(cat /opt/xray/keys/shortid)"
      echo "PublicKey: $pub"
      echo "shortId: $shortid"
      echo "vless://${uuid}@${addr}:${port}?encryption=none&security=reality&sni=${sni}&fp=chrome&pbk=${pub}&sid=${shortid}&type=tcp&flow=xtls-rprx-vision#default"
      ;;
    vless-ws-tls)
      local client_port ws_path ws_path_enc
      client_port="$(cat /opt/xray/keys/client_port 2>/dev/null || cat /opt/xray/keys/port)"
      ws_path="$(cat /opt/xray/keys/ws_path 2>/dev/null || echo "/ws")"
      ws_path_enc="${ws_path//\//%2F}"
      echo "vless://${uuid}@${addr}:${client_port}?encryption=none&security=tls&sni=${sni}&type=ws&host=${sni}&path=${ws_path_enc}#default"
      ;;
    vmess-ws-tls)
      local client_port ws_path vmess_json
      client_port="$(cat /opt/xray/keys/client_port 2>/dev/null || cat /opt/xray/keys/port)"
      ws_path="$(cat /opt/xray/keys/ws_path 2>/dev/null || echo "/ws")"
      vmess_json="$(jq -nc \
        --arg ps "default" \
        --arg add "$addr" \
        --arg port "$client_port" \
        --arg id "$uuid" \
        --arg host "$sni" \
        --arg path "$ws_path" \
        --arg sni "$sni" \
        '{v:"2",ps:$ps,add:$add,port:$port,id:$id,aid:"0",scy:"auto",net:"ws",type:"none",host:$host,path:$path,tls:"tls",sni:$sni,alpn:"http/1.1"}')"
      echo "vmess://$(printf "%s" "$vmess_json" | base64 | tr -d '\n')"
      ;;
    vmess-ws-nginx)
      local ws_path vmess_json
      local client_port
      client_port="$(cat /opt/xray/keys/client_port 2>/dev/null || echo "443")"
      ws_path="$(cat /opt/xray/keys/ws_path 2>/dev/null || echo "/ws")"
      vmess_json="$(jq -nc \
        --arg ps "default" \
        --arg add "$addr" \
        --arg port "$client_port" \
        --arg id "$uuid" \
        --arg host "$sni" \
        --arg path "$ws_path" \
        --arg sni "$sni" \
        '{v:"2",ps:$ps,add:$add,port:$port,id:$id,aid:"0",scy:"auto",net:"ws",type:"none",host:$host,path:$path,tls:"tls",sni:$sni,alpn:"http/1.1"}')"
      echo "vmess://$(printf "%s" "$vmess_json" | base64 | tr -d '\n')"
      echo ""
      echo "Nginx location example:"
      echo "location ${ws_path} {"
      echo "    proxy_pass http://127.0.0.1:${port};"
      echo "    proxy_http_version 1.1;"
      echo "    proxy_set_header Upgrade \$http_upgrade;"
      echo "    proxy_set_header Connection \"upgrade\";"
      echo "    proxy_set_header Host \$host;"
      echo "    proxy_read_timeout 3600;"
      echo "}"
      ;;
  esac
}

parse_args "$@"
require_root
detect_os
detect_pkg_mgr
install_deps
setup_ui
ui_banner
ui_step "Legacy Services Check"
handle_legacy
ui_step "Prepare Directories"
ensure_dirs
ui_step "Install Xray Core"
install_xray
ui_step "Configure Xray"
write_config
ui_step "Configure Link Address"
configure_server_addr
ui_step "Install Systemd Service"
write_systemd
ui_step "Tune Kernel (BBR)"
enable_bbr
ui_step "Configure Log Rotation"
configure_logrotate
ui_step "Configure Firewall"
configure_firewall
ui_step "Configure Nginx (Optional)"
configure_nginx_for_vmess_ws_nginx
ui_step "Install Management Scripts"
install_scripts
ui_step "Restart Service"
ui_run "Restarting xray service" systemctl restart xray
ui_success "xray service restarted."
print_output
