# pi-wifi-ble

<p align="center">
  <a href="https://gregogiudici.github.io/pi-wifi-ble/">
    <img src="https://img.shields.io/badge/%F0%9F%9A%80%20Open%20the%20web%20app-gregogiudici.github.io%2Fpi--wifi--ble-2ea44f?style=for-the-badge" alt="Open the web app">
  </a>
</p>

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
sudo ./install.sh                        # Bluetooth MIDI on the Pi is turned OFF
# or
sudo WIFI_BLE_KEEP_MIDI=1 ./install.sh   # keep Bluetooth MIDI (pair each Mac once)
```

The installer:
- installs `bluez python3-dbus python3-gi python3-cryptography`
- copies `wifi_ble.py` to `/opt/wifi-ble/` and `wifi-ble.service` to `/etc/systemd/system/`
- creates `/etc/wifi-ble/config.json` (mode 600) with a **random secret** and prints it
- by default **turns off Bluetooth MIDI** on the Pi, so Macs don't get disconnected after 30 s.
  Use `WIFI_BLE_KEEP_MIDI=1` to keep it. See [Bluetooth MIDI and the 30-second disconnect](#5-bluetooth-midi-and-the-30-second-disconnect)
- enables and starts the service

Running `install.sh` again switches between the two modes; `uninstall.sh` always turns Bluetooth MIDI back on.

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

> **Try it now:** [gregogiudici.github.io/pi-wifi-ble](https://gregogiudici.github.io/pi-wifi-ble/)
> (needs a Web Bluetooth browser, see [Browser support](#browser-support), and a Pi already set up with [step 1](#1-pi-setup))

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
- **Connection drops after about 30 s (usually from a Mac)**: see
  [Bluetooth MIDI and the 30-second disconnect](#5-bluetooth-midi-and-the-30-second-disconnect).
- **"Wrong secret"**: compare with `sudo cat /etc/wifi-ble/config.json`. Spaces at the ends are ignored.
- **Scan finds nothing**: the WLAN country is not set, or Wi-Fi is blocked (`rfkill list`, `nmcli radio wifi on`).
- **Joining fails with "Secrets were required"**: the password is wrong.
- **Changing UUIDs**: change them in both `pi/wifi_ble.py` and `docs/app.js`.
- **Debug logs**: add `-v` to `ExecStart` in the unit file, then `sudo systemctl daemon-reload && sudo systemctl restart wifi-ble`.
  To watch raw Bluetooth traffic: `sudo btmon`.

## 5. Bluetooth MIDI and the 30-second disconnect

**Symptom:** the web app connects and works, then says *Bluetooth connection closed* about 30 s
later, every time. `journalctl -u wifi-ble` shows `client disconnected` roughly 30 s after `client hello`.
It mostly happens with **Macs**.

**Why:** macOS exposes a Bluetooth LE MIDI service. Raspberry Pi OS has two components that
automatically use any BLE MIDI device that connects:

| Component | Log hint |
|---|---|
| BlueZ MIDI plugin (`bluetoothd`) | `journalctl -u bluetooth`: `MIDI I/O: Failed to read initial request` |
| PipeWire / WirePlumber `monitor.bluez-midi` | none (visible only in `sudo btmon`) |

They try to read the Mac's MIDI characteristic. The Mac refuses until the two devices are paired,
so pairing starts. Web Bluetooth never handles pairing, and on a headless Pi nobody confirms the
request, so after the Bluetooth pairing timeout (30 s) the link is dropped. `wifi_ble.py` is not involved.
In `sudo btmon` you can see `Insufficient Authentication`, then `SMP: Security Request` / `Pairing Request`,
and a disconnect 30 s later.

There are two fixes. Pick one:

### Option A: turn Bluetooth MIDI off (installer default)

Use this if the Pi never needs Bluetooth MIDI instruments. Any computer can then connect without pairing.

```bash
sudo ./install.sh
```

It creates two files (`uninstall.sh` or `WIFI_BLE_KEEP_MIDI=1 ./install.sh` removes them):

- `/etc/systemd/system/bluetooth.service.d/wifi-ble-nomidi.conf`: starts `bluetoothd --noplugin=midi`
- `/etc/wireplumber/wireplumber.conf.d/90-wifi-ble-no-bluez-midi.conf`: `monitor.bluez-midi = disabled`

Check: `ps -o args= -C bluetoothd` shows `--noplugin=midi`, and `journalctl -u bluetooth` shows `Excluding (cli) midi`.

USB MIDI is not affected, only Bluetooth MIDI.

### Option B: keep Bluetooth MIDI and pair each Mac once

Use this if the Pi uses Bluetooth MIDI devices.

```bash
sudo WIFI_BLE_KEEP_MIDI=1 ./install.sh
```

Then pair each computer that shows the problem **once**. The pairing is remembered on both sides;
after it, the MIDI read succeeds over an encrypted link and nothing times out.

On the Pi (over SSH or a terminal):

```
$ bluetoothctl
[bluetooth]# agent on
[bluetooth]# default-agent
```

Now connect from the web app on the Mac. Within a few seconds:

- the Pi prints `Confirm passkey 123456 (yes/no):`: type `yes`
- the Mac may show a pairing request with the same number: accept it

Then, still in `bluetoothctl`:

```
[bluetooth]# devices                      # find the Mac's address
[bluetooth]# trust D0:11:E5:XX:XX:XX
[bluetooth]# quit
```

With the Raspberry Pi desktop, you can accept the pairing pop-up on the Pi's screen (or over VNC) instead.

Check: `bluetoothctl info <address>` shows `Paired: yes`, `Bonded: yes` and `Trusted: yes`.
To undo: `bluetoothctl remove <address>` on the Pi, and remove the Pi from the Mac's Bluetooth settings.

If a pairing goes wrong (for example the Mac was paired and then removed on one side only), remove
it on **both** sides and pair again.

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
