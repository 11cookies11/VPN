#!/usr/bin/env bash
set -euo pipefail

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "Must run as root" >&2
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
    echo "No supported package manager found" >&2
    exit 1
  fi
}

install_deps() {
  case "$PKG_MGR" in
    apt)
      apt-get update -y
      apt-get install -y curl wget unzip jq uuid-runtime openssl ufw logrotate
      ;;
    dnf)
      dnf makecache -y
      dnf install -y curl wget unzip jq util-linux openssl firewalld logrotate
      ;;
    yum)
      yum makecache -y
      yum install -y curl wget unzip jq util-linux openssl firewalld logrotate
      ;;
  esac
}

install_xray() {
  if command -v xray >/dev/null 2>&1; then
    return 0
  fi

  local url
  url="$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r '.assets[] | select(.name|test("linux-64.zip$")) | .browser_download_url' | head -n1)"
  if [ -z "$url" ] || [ "$url" = "null" ]; then
    echo "Failed to fetch Xray release URL" >&2
    exit 1
  fi

  rm -rf /tmp/xray-install
  mkdir -p /tmp/xray-install
  wget -O /tmp/xray-install/xray.zip "$url"
  unzip -o /tmp/xray-install/xray.zip -d /tmp/xray-install
  install -m 0755 /tmp/xray-install/xray /usr/local/bin/xray
  mkdir -p /usr/local/share/xray
  if [ -f /tmp/xray-install/geoip.dat ]; then
    install -m 0644 /tmp/xray-install/geoip.dat /usr/local/share/xray/geoip.dat
  fi
  if [ -f /tmp/xray-install/geosite.dat ]; then
    install -m 0644 /tmp/xray-install/geosite.dat /usr/local/share/xray/geosite.dat
  fi
  rm -rf /tmp/xray-install
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
  local services=()
  while IFS= read -r line; do
    [ -n "$line" ] && services+=("$line")
  done < <(list_existing_services)

  if [ "${#services[@]}" -gt 0 ]; then
    echo "Detected existing proxy services:"
    printf " - %s\n" "${services[@]}"
    read -r -p "Stop and disable these services? (y/N): " ans
    case "${ans:-N}" in
      y|Y) stop_disable_services "${services[@]}" ;;
      *) ;;
    esac
  fi

  if [ -d /etc/xray ] || [ -d /etc/v2ray ] || [ -d /usr/local/etc/xray ] || [ -d /usr/local/etc/v2ray ] || [ -d /opt/v2ray ]; then
    echo "Detected legacy config directories."
    read -r -p "Move legacy configs to /opt/xray/backup-<timestamp>? (y/N): " ans
    case "${ans:-N}" in
      y|Y) backup_legacy_paths ;;
      *) ;;
    esac
  fi
}

ask() {
  local prompt="$1"
  local default="$2"
  local input
  read -r -p "$prompt [$default]: " input
  if [ -z "$input" ]; then
    echo "$default"
  else
    echo "$input"
  fi
}

ask_protocol() {
  local choice
  echo "Select deployment mode:"
  echo "  1) VLESS + REALITY (TCP)"
  echo "  2) VMess + WS + TLS"

  while true; do
    read -r -p "Mode [1]: " choice
    case "${choice:-1}" in
      1)
        PROTOCOL="vless-reality"
        break
        ;;
      2)
        PROTOCOL="vmess-ws-tls"
        break
        ;;
      *)
        echo "Invalid option, choose 1 or 2."
        ;;
    esac
  done
}

gen_reality_keys() {
  if [ ! -f /opt/xray/keys/private.key ] || [ ! -f /opt/xray/keys/public.key ]; then
    if ! /usr/local/bin/xray x25519 >/dev/null 2>&1; then
      echo "This Xray build does not support x25519 (required by REALITY)." >&2
      exit 1
    fi

    local out priv pub
    out="$(/usr/local/bin/xray x25519 2>&1 || true)"
    out="$(printf "%s\n" "$out" | tr -d '\r')"
    priv="$(printf "%s\n" "$out" | awk -F':' 'tolower($0) ~ /private[[:space:]]*key/ {gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); print $2; exit}')"
    pub="$(printf "%s\n" "$out" | awk -F':' 'tolower($1) ~ /public[[:space:]]*key/ || tolower($1) ~ /password/ {gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); print $2; exit}')"
    if [ -z "$priv" ] || [ -z "$pub" ]; then
      echo "Failed to generate X25519 keys" >&2
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
    read -r -p "TLS files not found. Generate self-signed cert now? (Y/n): " gen_ans
    case "${gen_ans:-Y}" in
      n|N)
        echo "VMess+WS+TLS requires certificate and key files." >&2
        exit 1
        ;;
      *)
        generate_self_signed_cert "$sni" "$cert_file" "$key_file"
        ;;
    esac
  fi

  echo "$PROTOCOL" > /opt/xray/keys/protocol
  echo "$port" > /opt/xray/keys/port
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

write_config() {
  local cfg=/opt/xray/config/config.json

  if [ -f "$cfg" ]; then
    read -r -p "Config exists. Overwrite? (y/N): " ans
    case "${ans:-N}" in
      y|Y) ;;
      *) return 0 ;;
    esac
  fi

  ask_protocol

  local port sni
  port="$(ask "Listen port" "443")"
  if command -v ss >/dev/null 2>&1; then
    while ss -lntp 2>/dev/null | awk '{print $4}' | grep -q ":${port}$"; do
      echo "Port $port is already in use."
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
    *)
      echo "Unsupported protocol: $PROTOCOL" >&2
      exit 1
      ;;
  esac

  jq -e . "$cfg" >/dev/null
}

configure_server_addr() {
  local addr_file=/opt/xray/keys/server_addr
  local auto_ip=""
  auto_ip="$(curl -s https://api.ipify.org || true)"
  local addr
  addr="$(ask "Public address for client link (IP or domain)" "${auto_ip:-YOUR_SERVER_IP}")"
  echo "$addr" > "$addr_file"
}

write_systemd() {
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
  systemctl daemon-reload
  systemctl enable xray
}

enable_bbr() {
  cat > /etc/sysctl.d/99-xray-bbr.conf <<'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
  sysctl --system >/dev/null
}

configure_logrotate() {
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
}

configure_firewall() {
  if command -v ufw >/dev/null 2>&1; then
    ufw allow OpenSSH >/dev/null
    ufw allow "$(cat /opt/xray/keys/port)/tcp" >/dev/null
    ufw default deny incoming >/dev/null
    ufw --force enable >/dev/null
  elif command -v firewall-cmd >/dev/null 2>&1; then
    systemctl enable --now firewalld >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-service=ssh >/dev/null
    firewall-cmd --permanent --add-port="$(cat /opt/xray/keys/port)/tcp" >/dev/null
    firewall-cmd --permanent --set-default-zone=public >/dev/null
    firewall-cmd --reload >/dev/null
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
  vmess-ws-tls)
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
  vmess-ws-tls)
    ws_path="$(cat /opt/xray/keys/ws_path 2>/dev/null || echo "/ws")"
    vmess_json="$(jq -nc \
      --arg ps "$username" \
      --arg add "$addr" \
      --arg port "$port" \
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
    vmess-ws-tls)
      ws_path="$(cat /opt/xray/keys/ws_path 2>/dev/null || echo "/ws")"
      vmess_json="$(jq -nc \
        --arg ps "$email" \
        --arg add "$addr" \
        --arg port "$port" \
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
  local protocol uuid addr sni port
  protocol="$(cat /opt/xray/keys/protocol 2>/dev/null || echo "vless-reality")"
  uuid="$(cat /opt/xray/keys/uuid)"
  sni="$(cat /opt/xray/keys/server_name)"
  port="$(cat /opt/xray/keys/port)"
  addr="$(cat /opt/xray/keys/server_addr)"
  if [ -z "$addr" ]; then
    addr="YOUR_SERVER_IP"
  fi

  echo "Protocol: $protocol"
  echo "UUID: $uuid"

  case "$protocol" in
    vless-reality)
      local pub shortid
      pub="$(cat /opt/xray/keys/public.key)"
      shortid="$(cat /opt/xray/keys/shortid)"
      echo "PublicKey: $pub"
      echo "shortId: $shortid"
      echo "vless://${uuid}@${addr}:${port}?encryption=none&security=reality&sni=${sni}&fp=chrome&pbk=${pub}&sid=${shortid}&type=tcp&flow=xtls-rprx-vision#default"
      ;;
    vmess-ws-tls)
      local ws_path vmess_json
      ws_path="$(cat /opt/xray/keys/ws_path 2>/dev/null || echo "/ws")"
      vmess_json="$(jq -nc \
        --arg ps "default" \
        --arg add "$addr" \
        --arg port "$port" \
        --arg id "$uuid" \
        --arg host "$sni" \
        --arg path "$ws_path" \
        --arg sni "$sni" \
        '{v:"2",ps:$ps,add:$add,port:$port,id:$id,aid:"0",scy:"auto",net:"ws",type:"none",host:$host,path:$path,tls:"tls",sni:$sni,alpn:"http/1.1"}')"
      echo "vmess://$(printf "%s" "$vmess_json" | base64 | tr -d '\n')"
      ;;
  esac
}

require_root
detect_os
detect_pkg_mgr
install_deps
handle_legacy
ensure_dirs
install_xray
write_config
configure_server_addr
write_systemd
enable_bbr
configure_logrotate
configure_firewall
install_scripts
systemctl restart xray
print_output
