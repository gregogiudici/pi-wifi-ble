#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Please run with sudo" >&2; exit 1; }
systemctl disable --now wifi-ble.service 2>/dev/null || true
rm -f /etc/systemd/system/wifi-ble.service
rm -rf /opt/wifi-ble
# Re-enable Bluetooth MIDI if install.sh disabled it.
if [[ -f /etc/systemd/system/bluetooth.service.d/wifi-ble-nomidi.conf ||
      -f /etc/wireplumber/wireplumber.conf.d/90-wifi-ble-no-bluez-midi.conf ]]; then
  rm -f /etc/systemd/system/bluetooth.service.d/wifi-ble-nomidi.conf
  rmdir /etc/systemd/system/bluetooth.service.d 2>/dev/null || true
  rm -f /etc/wireplumber/wireplumber.conf.d/90-wifi-ble-no-bluez-midi.conf
  systemctl daemon-reload
  systemctl restart bluetooth.service
  for uid in $(loginctl list-users --no-legend 2>/dev/null | awk '{print $1}'); do
    user=$(id -nu "$uid" 2>/dev/null) || continue
    sudo -u "$user" XDG_RUNTIME_DIR="/run/user/$uid" systemctl --user try-restart wireplumber.service 2>/dev/null || true
  done
fi
systemctl daemon-reload
echo "Removed. /etc/wifi-ble/config.json was kept; delete it by hand if you want."
