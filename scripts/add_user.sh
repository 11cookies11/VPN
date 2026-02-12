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
tmp="$(mktemp)"
uuid="$(uuidgen)"

jq --arg id "$uuid" --arg email "$username" \
  '.inbounds[0].settings.clients += [{"id":$id,"flow":"xtls-rprx-vision","email":$email}]' \
  "$config" > "$tmp"

jq -e . "$tmp" >/dev/null
mv "$tmp" "$config"

systemctl restart xray

pub="$(cat /opt/xray/keys/public.key)"
shortid="$(cat /opt/xray/keys/shortid)"
sni="$(cat /opt/xray/keys/server_name)"
port="$(cat /opt/xray/keys/port)"
addr="$(cat /opt/xray/keys/server_addr)"
if [ -z "$addr" ]; then
  addr="YOUR_SERVER_IP"
fi

echo "vless://${uuid}@${addr}:${port}?encryption=none&security=reality&sni=${sni}&fp=chrome&pbk=${pub}&sid=${shortid}&type=tcp&flow=xtls-rprx-vision#${username}"