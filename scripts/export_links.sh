#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Must run as root" >&2
  exit 1
fi

pub="$(cat /opt/xray/keys/public.key)"
shortid="$(cat /opt/xray/keys/shortid)"
sni="$(cat /opt/xray/keys/server_name)"
port="$(cat /opt/xray/keys/port)"
addr="$(cat /opt/xray/keys/server_addr)"
if [ -z "$addr" ]; then
  addr="YOUR_SERVER_IP"
fi

jq -r '.inbounds[0].settings.clients[] | "\(.email)\t\(.id)"' /opt/xray/config/config.json | while IFS=$'\t' read -r email uuid; do
  echo "vless://${uuid}@${addr}:${port}?encryption=none&security=reality&sni=${sni}&fp=chrome&pbk=${pub}&sid=${shortid}&type=tcp&flow=xtls-rprx-vision#${email}"
done