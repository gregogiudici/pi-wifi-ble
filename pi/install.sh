#!/usr/bin/env bash
# Install the wifi-ble systemd service on a Raspberry Pi (Raspberry Pi OS Bookworm or newer).
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Please run with sudo: sudo ./install.sh" >&2
  exit 1
fi
cd "$(dirname "$0")"

echo "==> Installing packages"
apt-get update -q
apt-get install -y -q bluez python3-dbus python3-gi python3-cryptography

if ! systemctl is-active --quiet NetworkManager; then
  echo "NetworkManager is not running. wifi-ble needs it (default on Raspberry Pi OS Bookworm)." >&2
  echo "Enable it with: sudo raspi-config -> Advanced Options -> Network Config -> NetworkManager" >&2
  exit 1
fi

echo "==> Copying files"
install -d -m 755 /opt/wifi-ble
install -m 755 wifi_ble.py /opt/wifi-ble/wifi_ble.py
install -m 644 wifi-ble.service /etc/systemd/system/wifi-ble.service

install -d -m 700 /etc/wifi-ble
if [[ ! -f /etc/wifi-ble/config.json ]]; then
  echo "==> Creating /etc/wifi-ble/config.json with a new random secret"
  SECRET=$(python3 -c 'import secrets
a = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
print("-".join("".join(secrets.choice(a) for _ in range(4)) for _ in range(3)))')
  (umask 077; cat > /etc/wifi-ble/config.json <<EOF
{
  "secret": "${SECRET}",
  "name": "PiWiFi",
  "iface": "wlan0"
}
EOF
)
fi

echo "==> Enabling Bluetooth and the service"
rfkill unblock bluetooth || true
systemctl daemon-reload
systemctl enable bluetooth.service
systemctl enable --now wifi-ble.service
systemctl restart wifi-ble.service

echo
echo "Done. Secret to enter in the web app:"
python3 -c 'import json; print("   ", json.load(open("/etc/wifi-ble/config.json"))["secret"])'
echo
echo "Logs:   journalctl -u wifi-ble -f"
echo "Config: /etc/wifi-ble/config.json  (then: sudo systemctl restart wifi-ble)"
