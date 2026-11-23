#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Please run with sudo" >&2; exit 1; }
systemctl disable --now wifi-ble.service 2>/dev/null || true
rm -f /etc/systemd/system/wifi-ble.service
rm -rf /opt/wifi-ble
systemctl daemon-reload
echo "Removed. /etc/wifi-ble/config.json was kept; delete it by hand if you want."
