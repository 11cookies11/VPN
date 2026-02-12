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