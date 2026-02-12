#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Must run as root" >&2
  exit 1
fi

jq -r '.inbounds[0].settings.clients[] | "\(.email)\t\(.id)"' /opt/xray/config/config.json