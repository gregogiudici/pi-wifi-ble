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

# Bluetooth MIDI vs. Mac clients (see README, "Bluetooth MIDI and the 30-second disconnect"):
# macOS exposes a BLE MIDI service. When a Mac connects, BlueZ's MIDI plugin and WirePlumber's
# BLE MIDI monitor try to use it, the Mac asks to pair, nobody confirms it on the Pi and the
# link is dropped after the 30 s pairing timeout. By default we turn Bluetooth MIDI off.
# Set WIFI_BLE_KEEP_MIDI=1 to keep it (then pair each Mac with the Pi once).
BLUEZ_DROPIN=/etc/systemd/system/bluetooth.service.d/wifi-ble-nomidi.conf
WP_CONF=/etc/wireplumber/wireplumber.conf.d/90-wifi-ble-no-bluez-midi.conf
if [[ "${WIFI_BLE_KEEP_MIDI:-0}" == 1 ]]; then
  echo "==> Keeping Bluetooth MIDI (WIFI_BLE_KEEP_MIDI=1)"
  rm -f "$BLUEZ_DROPIN" "$WP_CONF"
  rmdir "$(dirname "$BLUEZ_DROPIN")" 2>/dev/null || true
else
  echo "==> Disabling Bluetooth MIDI (set WIFI_BLE_KEEP_MIDI=1 to keep it)"
  BLUETOOTHD=$(systemctl show -p ExecStart --value bluetooth.service | sed -n 's/.*path=\([^ ;]*\).*/\1/p')
  BLUETOOTHD=${BLUETOOTHD:-/usr/libexec/bluetooth/bluetoothd}
  install -d -m 755 "$(dirname "$BLUEZ_DROPIN")"
  cat > "$BLUEZ_DROPIN" <<EOF
# Installed by wifi-ble: disable BlueZ's Bluetooth MIDI plugin.
# Otherwise bluetoothd tries to pair with Macs and Web Bluetooth connections drop after 30 s.
[Service]
ExecStart=
ExecStart=${BLUETOOTHD} --noplugin=midi
EOF
  if command -v wireplumber >/dev/null; then
    install -d -m 755 "$(dirname "$WP_CONF")"
    cat > "$WP_CONF" <<'EOF'
# Installed by wifi-ble: disable WirePlumber's Bluetooth MIDI monitor.
# Otherwise it tries to pair with Macs and Web Bluetooth connections drop after 30 s.
wireplumber.profiles = {
  main = {
    monitor.bluez-midi = disabled
  }
}
EOF
  fi
fi

echo "==> Enabling Bluetooth and the service"
rfkill unblock bluetooth || true
systemctl daemon-reload
systemctl enable bluetooth.service
systemctl restart bluetooth.service
# WirePlumber runs per user session; restart it for every logged-in user.
for uid in $(loginctl list-users --no-legend 2>/dev/null | awk '{print $1}'); do
  user=$(id -nu "$uid" 2>/dev/null) || continue
  sudo -u "$user" XDG_RUNTIME_DIR="/run/user/$uid" systemctl --user try-restart wireplumber.service 2>/dev/null || true
done
systemctl enable --now wifi-ble.service
systemctl restart wifi-ble.service

echo
echo "Done. Secret to enter in the web app:"
python3 -c 'import json; print("   ", json.load(open("/etc/wifi-ble/config.json"))["secret"])'
echo
echo "Logs:   journalctl -u wifi-ble -f"
echo "Config: /etc/wifi-ble/config.json  (then: sudo systemctl restart wifi-ble)"
