# pi-wifi-ble

Check and change a Raspberry Pi 5's Wi-Fi from your phone or laptop over **Bluetooth LE**,
using a static web page (GitHub Pages) and **Web Bluetooth**. No network connection to the Pi needed.

```
 Browser (GitHub Pages)  ── BLE GATT, AES-GCM encrypted ──▶  wifi-ble.service on the Pi ──▶ NetworkManager (nmcli)
```

What the web app can do:
- show hostname, Wi-Fi state, current SSID and signal, and **all IP addresses** (wlan0, eth0, …)
- scan for networks and join one (including hidden networks, WPA2/WPA3)
- list saved networks, switch to one, forget one

## 1. Pi setup

Requirements: Raspberry Pi OS **Bookworm or newer** (uses NetworkManager), Wi-Fi country set
(`sudo raspi-config` → Localisation → WLAN Country).

```bash
git clone https://github.com/<you>/pi-wifi-ble.git
cd pi-wifi-ble/pi
sudo ./install.sh
```

The installer:
- installs `bluez python3-dbus python3-gi python3-cryptography`
- copies `wifi_ble.py` to `/opt/wifi-ble/` and `wifi-ble.service` to `/etc/systemd/system/`
- creates `/etc/wifi-ble/config.json` (mode 600) with a **random secret** and prints it
- enables and starts the service

`/etc/wifi-ble/config.json`:

```json
{ "secret": "K7QM-2XPA-9RTD", "name": "PiWiFi", "iface": "wlan0" }
```

- `secret`: you type this in the web app. It is never sent over the air.
- `name`: the Bluetooth name. Keep it to **8 characters or fewer** so it fits in the advertisement next to the 128-bit service UUID.
- `iface`: Wi-Fi interface.

After editing: `sudo systemctl restart wifi-ble`.

Useful commands:

```bash
systemctl status wifi-ble
journalctl -u wifi-ble -f            # live logs
sudo systemctl restart wifi-ble
bluetoothctl show                    # adapter must be "Powered: yes"
sudo ./uninstall.sh
```

## 2. Web app on GitHub Pages

The web app is in `docs/` (plain HTML/CSS/JS, no build step).

1. Push this repo to GitHub.
2. **Settings → Pages → Build and deployment → Source: Deploy from a branch**, branch `main`, folder `/docs`.
3. Open `https://<you>.github.io/pi-wifi-ble/`.

Web Bluetooth only works over HTTPS (GitHub Pages is HTTPS) or `http://localhost`.
To test locally: `cd docs && python3 -m http.server 8000` and open `http://localhost:8000`.

### Browser support

| Platform | Works with |
|---|---|
| Android | Chrome, Edge, Samsung Internet |
| Windows / macOS / ChromeOS | Chrome, Edge |
| Linux | Chrome (may need `chrome://flags/#enable-experimental-web-platform-features`) |
| iPhone / iPad | **Bluefy** browser (Safari has no Web Bluetooth) |
| Firefox | not supported |

## 3. How it works

GATT service `71251336-797b-4363-b057-e8bb2bf15125`:

| Characteristic | UUID | Flags | Direction |
|---|---|---|---|
| RX | `637067ea-b46a-42b3-98d3-296897e972fc` | write | browser → Pi |
| TX | `00d343cc-dcc8-4ae2-a308-5c49ee587ccd` | notify | Pi → browser |

Messages are newline-terminated JSON split into chunks (the Pi uses the negotiated MTU,
the browser writes 128-byte pieces and falls back to 20 bytes).

Security: anyone in Bluetooth range can see the Pi, so every command is authenticated and encrypted.

1. Browser sends a random nonce `cn`, Pi answers with a random nonce `sn`.
2. Both compute `master = PBKDF2-SHA256(secret, "wifi-ble-v1", 100000)` and
   `session = HMAC-SHA256(master, "session" ‖ sn ‖ cn)`.
3. All requests and responses are AES-256-GCM with the session key (separate AAD per direction).
   Request ids must strictly increase, so replayed messages are rejected.
   A wrong secret fails decryption, and after 5 failures in 60 s the Pi stops accepting new handshakes for a minute.

Wi-Fi passwords therefore travel encrypted. On the Pi they are passed to `nmcli` on the
command line for a fraction of a second, which only local users could see. When joining a network
the Pi first brings up the new profile and only deletes the old profiles for that SSID **if the
connection succeeds**, so a mistyped password never leaves you without a working configuration.

The secret is the only thing protecting the Pi's network settings. Keep the generated 60-bit one or
use something equally long.

## 4. Troubleshooting

- **Pi doesn't show up in the chooser**: `journalctl -u wifi-ble` should say `advertising as 'PiWiFi'`.
  Check `rfkill list` (unblock with `sudo rfkill unblock bluetooth`) and `bluetoothctl show`.
  A `name` that's too long can cause `RegisterAdvertisement failed`.
- **"Wrong secret"**: compare with `sudo cat /etc/wifi-ble/config.json`. Spaces at the ends are ignored.
- **Scan finds nothing**: the WLAN country is not set, or Wi-Fi is blocked (`rfkill list`, `nmcli radio wifi on`).
- **Joining fails with "Secrets were required"**: the password is wrong.
- **Changing UUIDs**: change them in both `pi/wifi_ble.py` and `docs/app.js`.
- **Debug logs**: add `-v` to `ExecStart` in the unit file, then `sudo systemctl daemon-reload && sudo systemctl restart wifi-ble`.
  To watch raw Bluetooth traffic: `sudo btmon`.

## Layout

```
pi/
  wifi_ble.py        BLE GATT server (BlueZ D-Bus) + NetworkManager control
  wifi-ble.service   systemd unit
  install.sh         installer (packages, files, secret, enable service)
  uninstall.sh
docs/                static web app served by GitHub Pages
  index.html  app.js  style.css  .nojekyll
```
