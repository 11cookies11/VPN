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
