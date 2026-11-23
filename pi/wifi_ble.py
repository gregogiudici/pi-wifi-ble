#!/usr/bin/env python3
"""
wifi-ble - check and change a Raspberry Pi's Wi-Fi over Bluetooth Low Energy.

The Pi advertises one GATT service with two characteristics:
  RX (write)  : browser -> Pi, newline-terminated JSON, may arrive in several writes
  TX (notify) : Pi -> browser, newline-terminated JSON, sent in MTU-sized chunks

Protocol
  1. browser -> {"t":"hello","cn":<base64, 16 random bytes>}
     Pi      -> {"t":"hello","v":1,"sn":<base64, 16 random bytes>,"name":<advertised name>}
  2. Both sides derive
        master  = PBKDF2-HMAC-SHA256(secret, "wifi-ble-v1", 100000 iterations, 32 bytes)
        session = HMAC-SHA256(master, "session" || sn || cn)
  3. Every further message is {"t":"enc","iv":<b64>,"ct":<b64>}: AES-256-GCM with the
     session key and AAD "c2s" (browser -> Pi) or "s2c" (Pi -> browser).
       request : {"id":<int, strictly increasing>,"cmd":"status"|"scan"|"saved"|
                  "connect"|"activate"|"forget", ...}
       response: {"id":..,"ok":true,"data":...} | {"id":..,"ok":false,"error":"..."}
     Plain-text errors: {"t":"err","e":"auth"|"no-session"|"bad-request"|"throttled"}

Wi-Fi is managed with NetworkManager (nmcli), the default on Raspberry Pi OS Bookworm.
"""

import argparse
import base64
import hashlib
import hmac
import json
import logging
import re
import secrets
import signal
import socket
import subprocess
import sys
import threading
import time

import dbus
import dbus.exceptions
import dbus.mainloop.glib
import dbus.service
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from gi.repository import GLib

log = logging.getLogger("wifi-ble")

# Must match docs/app.js
SERVICE_UUID = "71251336-797b-4363-b057-e8bb2bf15125"
RX_UUID = "637067ea-b46a-42b3-98d3-296897e972fc"
TX_UUID = "00d343cc-dcc8-4ae2-a308-5c49ee587ccd"

KDF_SALT = b"wifi-ble-v1"
KDF_ITER = 100_000
MAX_MSG = 8192          # bytes buffered from the browser before we give up
MAX_AUTH_FAILS = 5      # wrong-secret attempts allowed ...
AUTH_WINDOW = 60        # ... per this many seconds

BLUEZ = "org.bluez"
ADAPTER_IFACE = "org.bluez.Adapter1"
GATT_MANAGER = "org.bluez.GattManager1"
ADV_MANAGER = "org.bluez.LEAdvertisingManager1"
GATT_SERVICE = "org.bluez.GattService1"
GATT_CHRC = "org.bluez.GattCharacteristic1"
LE_ADV = "org.bluez.LEAdvertisement1"
OBJ_MANAGER = "org.freedesktop.DBus.ObjectManager"
PROPS = "org.freedesktop.DBus.Properties"


# --------------------------------------------------------------------------- crypto

def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(text) -> bytes:
    return base64.b64decode(str(text), validate=True)


def derive_master(secret: str) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", secret.strip().encode("utf-8"), KDF_SALT, KDF_ITER, 32)


class Session:
    """One authenticated conversation with one browser."""

    def __init__(self, master: bytes, client_nonce: bytes, server_nonce: bytes | None = None):
        self.sn = server_nonce or secrets.token_bytes(16)
        key = hmac.new(master, b"session" + self.sn + client_nonce, hashlib.sha256).digest()
        self._aead = AESGCM(key)
        self.last_id = 0

    def seal(self, obj) -> dict:
        iv = secrets.token_bytes(12)
        plain = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        return {"t": "enc", "iv": b64(iv), "ct": b64(self._aead.encrypt(iv, plain, b"s2c"))}

    def open(self, msg: dict):
        """Decrypt a browser message. Raises InvalidTag if the secret is wrong."""
        plain = self._aead.decrypt(unb64(msg["iv"]), unb64(msg["ct"]), b"c2s")
        return json.loads(plain)


# --------------------------------------------------------------------------- Wi-Fi

class CmdError(Exception):
    pass


_SECRET_ARGS = {"password", "wifi-sec.psk"}


def _redact(cmd):
    out, hide = [], False
    for arg in cmd:
        out.append("***" if hide else arg)
        hide = arg in _SECRET_ARGS
    return out


def run(cmd, timeout=30):
    log.debug("exec: %s", " ".join(_redact(cmd)))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise CmdError(f"{cmd[0]} timed out") from None
    if proc.returncode != 0:
        lines = (proc.stderr or proc.stdout).strip().splitlines()
        msg = lines[-1] if lines else f"{cmd[0]} exited with code {proc.returncode}"
        raise CmdError(re.sub(r"^Error:\s*", "", msg))
    return proc.stdout


def run_quiet(cmd):
    try:
        run(cmd)
    except CmdError as exc:
        log.warning("%s: %s", " ".join(_redact(cmd)), exc)


def split_terse(line: str):
    """Split one line of `nmcli -t` output (':' separated, '\\' escapes)."""
    fields, cur, esc = [], [], False
    for ch in line:
        if esc:
            cur.append(ch)
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == ":":
            fields.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    fields.append("".join(cur))
    return fields


def unescape(value: str) -> str:
    return re.sub(r"\\(.)", r"\1", value)


class Wifi:
    def __init__(self, iface: str):
        self.iface = iface
        self.lock = threading.Lock()   # one nmcli change/scan at a time

    # ---- read-only
    def networks(self, rescan="no"):
        out = run(["nmcli", "-t", "-f", "IN-USE,SSID,SIGNAL,SECURITY", "device", "wifi", "list",
                   "ifname", self.iface, "--rescan", rescan], timeout=45)
        nets = {}
        for line in out.splitlines():
            f = split_terse(line)
            if len(f) < 4 or not f[1]:
                continue                           # hidden SSIDs have no name
            ssid, signal_ = f[1], int(f[2]) if f[2].isdigit() else 0
            security = "" if f[3] in ("", "--") else f[3]
            net = nets.setdefault(ssid, {"ssid": ssid, "signal": -1, "security": "", "active": False})
            if signal_ > net["signal"]:
                net["signal"], net["security"] = signal_, security
            net["active"] = net["active"] or f[0] == "*"
        return sorted(nets.values(), key=lambda n: (not n["active"], -n["signal"]))[:40]

    @staticmethod
    def addresses():
        ips = {}
        for itf in json.loads(run(["ip", "-j", "address", "show"]) or "[]"):
            name = itf.get("ifname")
            if not name or name == "lo":
                continue
            addrs = [f'{a["local"]}/{a["prefixlen"]}' for a in itf.get("addr_info", [])
                     if a.get("family") == "inet"
                     or (a.get("family") == "inet6" and a.get("scope") == "global")]
            if addrs:
                ips[name] = addrs
        return ips

    def status(self):
        st = {"host": socket.gethostname(), "iface": self.iface, "state": "unknown",
              "connection": None, "ssid": None, "signal": None, "ips": self.addresses()}
        out = run(["nmcli", "-t", "-f", "GENERAL.STATE,GENERAL.CONNECTION", "device", "show", self.iface])
        for line in out.splitlines():
            key, _, val = line.partition(":")
            if key == "GENERAL.STATE":
                m = re.search(r"\((.*)\)", val)          # "100 (connected)"
                st["state"] = m.group(1) if m else val
            elif key == "GENERAL.CONNECTION":
                st["connection"] = unescape(val) or None
        for net in self.networks("no"):
            if net["active"]:
                st["ssid"], st["signal"] = net["ssid"], net["signal"]
                break
        return st

    def saved(self):
        out = run(["nmcli", "-t", "-f", "NAME,UUID,TYPE,ACTIVE", "connection", "show"])
        profiles = []
        for line in out.splitlines():
            f = split_terse(line)
            if len(f) < 4 or f[2] != "802-11-wireless":
                continue
            ssid = unescape(run(["nmcli", "-g", "802-11-wireless.ssid", "connection", "show",
                                 "uuid", f[1]]).strip())
            profiles.append({"name": f[0], "uuid": f[1], "ssid": ssid or f[0], "active": f[3] == "yes"})
        return profiles

    # ---- changes
    def scan(self):
        with self.lock:
            try:
                return self.networks("yes")
            except CmdError:                        # e.g. "scanning not allowed" right after a scan
                return self.networks("auto")

    def connect(self, ssid, psk="", hidden=False):
        if not isinstance(ssid, str) or not ssid or len(ssid.encode()) > 32:
            raise CmdError("The network name must be 1-32 bytes")
        psk = psk if isinstance(psk, str) else ""
        if psk and not (8 <= len(psk) <= 63 or re.fullmatch(r"[0-9a-fA-F]{64}", psk)):
            raise CmdError("The Wi-Fi password must be 8-63 characters")

        with self.lock:
            security = next((n["security"] for n in self.networks("no") if n["ssid"] == ssid), "")
            tmp_name = "wifi-ble-" + secrets.token_hex(4)
            cmd = ["nmcli", "connection", "add", "type", "wifi", "ifname", self.iface,
                   "con-name", tmp_name, "ssid", ssid, "connection.autoconnect", "yes"]
            if hidden:
                cmd += ["802-11-wireless.hidden", "yes"]
            if psk:
                wpa3_only = "WPA3" in security and "WPA2" not in security and "WPA1" not in security
                cmd += ["wifi-sec.key-mgmt", "sae" if wpa3_only else "wpa-psk", "wifi-sec.psk", psk]
            run(cmd)
            uuid = unescape(run(["nmcli", "-g", "connection.uuid", "connection", "show", "id", tmp_name]).strip())

            # Bring the new profile up first; only if that works do we drop the old ones,
            # so a typo in the password never loses a working configuration.
            try:
                run(["nmcli", "--wait", "45", "connection", "up", "uuid", uuid], timeout=60)
            except CmdError:
                run_quiet(["nmcli", "connection", "delete", "uuid", uuid])
                raise
            for prof in self.saved():
                if prof["ssid"] == ssid and prof["uuid"] != uuid:
                    run_quiet(["nmcli", "connection", "delete", "uuid", prof["uuid"]])
            run_quiet(["nmcli", "connection", "modify", "uuid", uuid, "connection.id", ssid])
        return self.status()

    def _check_profile(self, uuid):
        if not any(p["uuid"] == uuid for p in self.saved()):
            raise CmdError("Unknown saved network")

    def activate(self, uuid):
        with self.lock:
            self._check_profile(uuid)
            run(["nmcli", "--wait", "45", "connection", "up", "uuid", uuid], timeout=60)
        return self.status()

    def forget(self, uuid):
        with self.lock:
            self._check_profile(uuid)
            run(["nmcli", "connection", "delete", "uuid", uuid])
        return self.saved()


# --------------------------------------------------------------------------- BlueZ GATT objects

class InvalidArgs(dbus.exceptions.DBusException):
    _dbus_error_name = "org.freedesktop.DBus.Error.InvalidArgs"


class NotSupported(dbus.exceptions.DBusException):
    _dbus_error_name = "org.bluez.Error.NotSupported"


class Application(dbus.service.Object):
    PATH = "/org/wifible"

    def __init__(self, bus):
        super().__init__(bus, self.PATH)
        self.services = []

    def get_path(self):
        return dbus.ObjectPath(self.PATH)

    @dbus.service.method(OBJ_MANAGER, out_signature="a{oa{sa{sv}}}")
    def GetManagedObjects(self):
        objects = {}
        for svc in self.services:
            objects[svc.get_path()] = svc.get_properties()
            for chrc in svc.characteristics:
                objects[chrc.get_path()] = chrc.get_properties()
        return objects


class Service(dbus.service.Object):
    def __init__(self, bus, index, uuid):
        self.path = f"{Application.PATH}/service{index}"
        self.uuid = uuid
        self.characteristics = []
        super().__init__(bus, self.path)

    def get_path(self):
        return dbus.ObjectPath(self.path)

    def get_properties(self):
        return {GATT_SERVICE: {
            "UUID": self.uuid,
            "Primary": True,
            "Characteristics": dbus.Array([c.get_path() for c in self.characteristics], signature="o"),
        }}

    @dbus.service.method(PROPS, in_signature="s", out_signature="a{sv}")
    def GetAll(self, interface):
        if interface != GATT_SERVICE:
            raise InvalidArgs()
        return self.get_properties()[GATT_SERVICE]


class Characteristic(dbus.service.Object):
    def __init__(self, bus, index, uuid, flags, service):
        self.path = f"{service.path}/char{index}"
        self.uuid, self.flags, self.service = uuid, flags, service
        super().__init__(bus, self.path)
        service.characteristics.append(self)

    def get_path(self):
        return dbus.ObjectPath(self.path)

    def get_properties(self):
        return {GATT_CHRC: {
            "Service": self.service.get_path(),
            "UUID": self.uuid,
            "Flags": self.flags,
            "Descriptors": dbus.Array([], signature="o"),
        }}

    @dbus.service.method(PROPS, in_signature="s", out_signature="a{sv}")
    def GetAll(self, interface):
        if interface != GATT_CHRC:
            raise InvalidArgs()
        return self.get_properties()[GATT_CHRC]

    @dbus.service.method(GATT_CHRC, in_signature="a{sv}", out_signature="ay")
    def ReadValue(self, options):
        raise NotSupported()

    @dbus.service.method(GATT_CHRC, in_signature="aya{sv}")
    def WriteValue(self, value, options):
        raise NotSupported()

    @dbus.service.method(GATT_CHRC)
    def StartNotify(self):
        raise NotSupported()

    @dbus.service.method(GATT_CHRC)
    def StopNotify(self):
        raise NotSupported()

    @dbus.service.signal(PROPS, signature="sa{sv}as")
    def PropertiesChanged(self, interface, changed, invalidated):
        pass


class RxCharacteristic(Characteristic):
    def __init__(self, bus, index, service, server):
        super().__init__(bus, index, RX_UUID, ["write", "write-without-response"], service)
        self.server = server

    def WriteValue(self, value, options):
        if "mtu" in options:
            self.server.mtu = int(options["mtu"])
        self.server.on_bytes(bytes(value))


class TxCharacteristic(Characteristic):
    def __init__(self, bus, index, service, server):
        super().__init__(bus, index, TX_UUID, ["notify"], service)
        self.server = server
        self.notifying = False

    def StartNotify(self):
        self.notifying = True

    def StopNotify(self):          # BlueZ also calls this when the browser disconnects
        self.notifying = False
        self.server.reset()

    def notify(self, chunk: bytes):
        self.PropertiesChanged(GATT_CHRC, {"Value": dbus.Array([dbus.Byte(b) for b in chunk],
                                                               signature="y")}, [])


class Advertisement(dbus.service.Object):
    PATH = "/org/wifible/advertisement0"

    def __init__(self, bus, name):
        super().__init__(bus, self.PATH)
        self.name = name

    def get_path(self):
        return dbus.ObjectPath(self.PATH)

    @dbus.service.method(PROPS, in_signature="s", out_signature="a{sv}")
    def GetAll(self, interface):
        if interface != LE_ADV:
            raise InvalidArgs()
        return {
            "Type": "peripheral",
            "ServiceUUIDs": dbus.Array([SERVICE_UUID], signature="s"),
            "LocalName": dbus.String(self.name),
            "Discoverable": dbus.Boolean(True),
        }

    @dbus.service.method(LE_ADV)
    def Release(self):
        log.info("advertisement released by BlueZ")


# --------------------------------------------------------------------------- server

class WifiBleServer:
    def __init__(self, bus, cfg):
        self.master = derive_master(cfg["secret"])
        self.name = cfg["name"]
        self.wifi = Wifi(cfg["iface"])
        self.session = None
        self.mtu = 23
        self.rxbuf = bytearray()
        self.auth_fails = []

        self.app = Application(bus)
        service = Service(bus, 0, SERVICE_UUID)
        self.rx = RxCharacteristic(bus, 0, service, self)
        self.tx = TxCharacteristic(bus, 1, service, self)
        self.app.services.append(service)
        self.adv = Advertisement(bus, self.name)

    def reset(self):
        if self.session:
            log.info("client disconnected")
        self.session, self.rxbuf, self.mtu = None, bytearray(), 23

    # ---- transport
    def send(self, obj):
        if not self.tx.notifying:
            return
        data = json.dumps(obj, separators=(",", ":")).encode("utf-8") + b"\n"
        size = max(20, min(self.mtu - 3, 509))
        for i in range(0, len(data), size):
            self.tx.notify(data[i:i + size])

    def on_bytes(self, data: bytes):
        self.rxbuf += data
        if len(self.rxbuf) > MAX_MSG:
            self.rxbuf.clear()
            self.send({"t": "err", "e": "bad-request"})
            return
        while b"\n" in self.rxbuf:
            line, _, rest = bytes(self.rxbuf).partition(b"\n")
            self.rxbuf = bytearray(rest)
            if not line.strip():
                continue
            try:
                msg = json.loads(line)
                if not isinstance(msg, dict):
                    raise ValueError
            except ValueError:
                self.send({"t": "err", "e": "bad-request"})
                continue
            self.on_message(msg)

    # ---- protocol
    def _throttled(self):
        now = time.monotonic()
        self.auth_fails = [t for t in self.auth_fails if now - t < AUTH_WINDOW]
        return len(self.auth_fails) >= MAX_AUTH_FAILS

    def on_message(self, msg):
        kind = msg.get("t")
        if kind == "hello":
            if self._throttled():
                self.send({"t": "err", "e": "throttled"})
                return
            try:
                cn = unb64(msg["cn"])
                if len(cn) != 16:
                    raise ValueError
            except (KeyError, ValueError):
                self.send({"t": "err", "e": "bad-request"})
                return
            self.session = Session(self.master, cn)
            log.info("client hello")
            self.send({"t": "hello", "v": 1, "sn": b64(self.session.sn), "name": self.name})
            return

        if kind != "enc":
            self.send({"t": "err", "e": "bad-request"})
            return
        if not self.session:
            self.send({"t": "err", "e": "no-session"})
            return
        try:
            req = self.session.open(msg)
        except (InvalidTag, KeyError, ValueError):
            log.warning("message failed authentication (wrong secret?)")
            self.auth_fails.append(time.monotonic())
            self.session = None
            self.send({"t": "err", "e": "auth"})
            return

        rid = req.get("id") if isinstance(req, dict) else None
        if not isinstance(rid, int) or rid <= self.session.last_id:
            self.send({"t": "err", "e": "bad-request"})
            return
        self.session.last_id = rid
        session = self.session
        log.info("request %d: %s", rid, req.get("cmd"))

        def work():
            try:
                result = {"id": rid, "ok": True, "data": self.dispatch(req)}
            except CmdError as exc:
                result = {"id": rid, "ok": False, "error": str(exc)}
            except Exception as exc:  # noqa: BLE001 - report anything to the browser
                log.exception("command failed")
                result = {"id": rid, "ok": False, "error": f"Internal error: {exc}"}
            GLib.idle_add(self._reply, session, result)

        threading.Thread(target=work, daemon=True).start()

    def _reply(self, session, result):
        if session is self.session:               # drop replies for a closed session
            self.send(session.seal(result))
        return False

    def dispatch(self, req):
        cmd = req.get("cmd")
        if cmd == "status":
            return self.wifi.status()
        if cmd == "scan":
            return self.wifi.scan()
        if cmd == "saved":
            return self.wifi.saved()
        if cmd == "connect":
            return self.wifi.connect(req.get("ssid"), req.get("psk") or "", bool(req.get("hidden")))
        if cmd == "activate":
            return self.wifi.activate(req.get("uuid"))
        if cmd == "forget":
            return self.wifi.forget(req.get("uuid"))
        raise CmdError(f"Unknown command {cmd!r}")


# --------------------------------------------------------------------------- main

def find_adapter(bus, wait=30):
    deadline = time.monotonic() + wait
    while True:
        manager = dbus.Interface(bus.get_object(BLUEZ, "/"), OBJ_MANAGER)
        for path, ifaces in manager.GetManagedObjects().items():
            if GATT_MANAGER in ifaces and ADV_MANAGER in ifaces:
                return path
        if time.monotonic() > deadline:
            raise RuntimeError("No Bluetooth LE adapter found (is bluetooth.service running?)")
        time.sleep(1)


def load_config(path):
    with open(path, encoding="utf-8") as fh:
        cfg = json.load(fh)
    secret = str(cfg.get("secret", "")).strip()
    if len(secret) < 8:
        raise SystemExit(f"{path}: 'secret' must be at least 8 characters")
    return {"secret": secret,
            "name": str(cfg.get("name") or "PiWiFi"),
            "iface": str(cfg.get("iface") or "wlan0")}


def main():
    parser = argparse.ArgumentParser(description="Configure Wi-Fi over Bluetooth LE")
    parser.add_argument("--config", default="/etc/wifi-ble/config.json")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)s %(message)s")

    cfg = load_config(args.config)
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    adapter_path = find_adapter(bus)
    adapter = bus.get_object(BLUEZ, adapter_path)
    dbus.Interface(adapter, PROPS).Set(ADAPTER_IFACE, "Powered", dbus.Boolean(True))

    server = WifiBleServer(bus, cfg)
    loop = GLib.MainLoop()
    exit_code = [0]

    def fail(what):
        def handler(err):
            log.error("%s failed: %s", what, err)
            exit_code[0] = 1
            loop.quit()
        return handler

    dbus.Interface(adapter, GATT_MANAGER).RegisterApplication(
        server.app.get_path(), {},
        reply_handler=lambda: log.info("GATT service registered"),
        error_handler=fail("RegisterApplication"))
    dbus.Interface(adapter, ADV_MANAGER).RegisterAdvertisement(
        server.adv.get_path(), {},
        reply_handler=lambda: log.info("advertising as %r on %s", cfg["name"], adapter_path),
        error_handler=fail("RegisterAdvertisement"))

    seen_owner = [False]

    def on_bluez_owner(owner):
        if owner:
            seen_owner[0] = True
        elif seen_owner[0]:
            log.error("bluetoothd went away; exiting so systemd restarts us")
            exit_code[0] = 1
            loop.quit()

    bus.watch_name_owner(BLUEZ, on_bluez_owner)
    GLib.unix_signal_add(GLib.PRIORITY_DEFAULT, signal.SIGTERM, loop.quit)
    GLib.unix_signal_add(GLib.PRIORITY_DEFAULT, signal.SIGINT, loop.quit)
    loop.run()
    sys.exit(exit_code[0])


if __name__ == "__main__":
    main()
