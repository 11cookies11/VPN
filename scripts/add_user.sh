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
