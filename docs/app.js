'use strict';

// Must match pi/wifi_ble.py
const SERVICE_UUID = '71251336-797b-4363-b057-e8bb2bf15125';
const RX_UUID = '637067ea-b46a-42b3-98d3-296897e972fc';
const TX_UUID = '00d343cc-dcc8-4ae2-a308-5c49ee587ccd';
const KDF_SALT = 'wifi-ble-v1';
const KDF_ITER = 100000;

const te = new TextEncoder();
const td = new TextDecoder();

// ------------------------------------------------------------------ crypto helpers

const b64 = (u8) => btoa(Array.from(u8, (c) => String.fromCharCode(c)).join(''));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

async function deriveMaster(secret) {
  const base = await crypto.subtle.importKey('raw', te.encode(secret.trim()), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: te.encode(KDF_SALT), iterations: KDF_ITER, hash: 'SHA-256' }, base, 256);
  return new Uint8Array(bits);
}

async function deriveSessionKey(master, sn, cn) {
  const hk = await crypto.subtle.importKey('raw', master, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const raw = await crypto.subtle.sign('HMAC', hk, concat(te.encode('session'), sn, cn));
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

const ERRORS = {
  auth: 'Wrong secret. Check /etc/wifi-ble/config.json on the Pi.',
  throttled: 'Too many wrong secrets. Wait a minute and try again.',
  'no-session': 'Session expired. Reconnect.',
  'bad-request': 'The Pi did not understand the request.',
};

// ------------------------------------------------------------------ BLE link

class PiLink extends EventTarget {
  constructor() {
    super();
    this.device = null;
    this._clear();
  }

  _clear() {
    this.rx = this.tx = this.key = null;
    this.buf = new Uint8Array(0);
    this.pending = new Map();
    this.helloWaiter = null;
    this.sendChain = Promise.resolve();
    this.nextId = 1;
    this.chunk = 128;
  }

  get connected() { return !!this.key; }

  async pick() {
    if (!navigator.bluetooth) throw new Error('Web Bluetooth is not available in this browser.');
    this.device = await navigator.bluetooth.requestDevice({ filters: [{ services: [SERVICE_UUID] }] });
    this.device.addEventListener('gattserverdisconnected', () => this._onDisconnect());
  }

  async open(secret) {
    if (!this.device) throw new Error('No device selected');
    const masterP = deriveMaster(secret);
    const server = await this.device.gatt.connect();
    const svc = await server.getPrimaryService(SERVICE_UUID);
    this.rx = await svc.getCharacteristic(RX_UUID);
    this.tx = await svc.getCharacteristic(TX_UUID);
    this.tx.addEventListener('characteristicvaluechanged', (e) => this._onNotify(e.target.value));
    await this.tx.startNotifications();

    const cn = crypto.getRandomValues(new Uint8Array(16));
    const hello = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('No answer from the Pi')), 10000);
      this.helloWaiter = {
        resolve: (m) => { clearTimeout(timer); resolve(m); },
        reject: (e) => { clearTimeout(timer); reject(e); },
      };
      this._writeJson({ t: 'hello', cn: b64(cn) }).catch(this.helloWaiter.reject);
    });
    this.helloWaiter = null;
    this.key = await deriveSessionKey(await masterP, unb64(hello.sn), cn);
    this.nextId = 1;
    this.name = hello.name || this.device.name;
    return this.request('status');            // fails with "auth" if the secret is wrong
  }

  disconnect() {
    if (this.device?.gatt.connected) this.device.gatt.disconnect();
    else this._onDisconnect();
  }

  _onDisconnect() {
    const err = new Error('Disconnected');
    this.helloWaiter?.reject(err);
    for (const p of this.pending.values()) { clearTimeout(p.timer); p.reject(err); }
    this._clear();
    this.dispatchEvent(new Event('disconnected'));
  }

  _onNotify(view) {
    this.buf = concat(this.buf, new Uint8Array(view.buffer, view.byteOffset, view.byteLength));
    let nl;
    while ((nl = this.buf.indexOf(10)) >= 0) {
      const line = this.buf.slice(0, nl);
      this.buf = this.buf.slice(nl + 1);
      let msg;
      try { msg = JSON.parse(td.decode(line)); } catch { continue; }
      this._onMessage(msg).catch((e) => console.error(e));
    }
  }

  async _onMessage(msg) {
    if (msg.t === 'hello') { this.helloWaiter?.resolve(msg); return; }
    if (msg.t === 'err') {
      const err = new Error(ERRORS[msg.e] || msg.e);
      this.helloWaiter?.reject(err);
      for (const p of this.pending.values()) { clearTimeout(p.timer); p.reject(err); }
      this.pending.clear();
      if (msg.e === 'auth') this.key = null;
      return;
    }
    if (msg.t !== 'enc' || !this.key) return;
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: unb64(msg.iv), additionalData: te.encode('s2c') }, this.key, unb64(msg.ct));
    const res = JSON.parse(td.decode(plain));
    const p = this.pending.get(res.id);
    if (!p) return;
    this.pending.delete(res.id);
    clearTimeout(p.timer);
    res.ok ? p.resolve(res.data) : p.reject(new Error(res.error));
  }

  async _writeBytes(bytes) {
    for (let off = 0; off < bytes.length;) {
      const piece = bytes.slice(off, off + this.chunk);
      try {
        await this.rx.writeValueWithResponse(piece);
        off += piece.length;
      } catch (e) {
        if (this.chunk > 20) { this.chunk = 20; continue; }   // tiny MTU: fall back to 20-byte writes
        throw e;
      }
    }
  }

  _writeJson(obj) {
    const run = () => this._writeBytes(te.encode(JSON.stringify(obj) + '\n'));
    this.sendChain = this.sendChain.then(run, run);
    return this.sendChain;
  }

  request(cmd, args = {}, timeoutMs = 30000) {
    if (!this.key) return Promise.reject(new Error('Not connected'));
    return new Promise((resolve, reject) => {
      const send = async () => {
        // id + encryption happen inside the chain so requests reach the Pi in id order
        const id = this.nextId++;
        const timer = setTimeout(() => { this.pending.delete(id); reject(new Error(`"${cmd}" timed out`)); }, timeoutMs);
        this.pending.set(id, { resolve, reject, timer });
        try {
          const iv = crypto.getRandomValues(new Uint8Array(12));
          const ct = new Uint8Array(await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv, additionalData: te.encode('c2s') }, this.key,
            te.encode(JSON.stringify({ id, cmd, ...args }))));
          await this._writeBytes(te.encode(JSON.stringify({ t: 'enc', iv: b64(iv), ct: b64(ct) }) + '\n'));
        } catch (e) {
          clearTimeout(timer); this.pending.delete(id); reject(e);
        }
      };
      this.sendChain = this.sendChain.then(send, send);
    });
  }
}

// ------------------------------------------------------------------ UI

const $ = (sel) => document.querySelector(sel);
const link = new PiLink();
const SECRET_KEY = 'wifi-ble-secret';

function el(tag, props = {}, ...children) {
  const node = Object.assign(document.createElement(tag), props);
  for (const c of children) if (c != null) node.append(c);   // text via append() => never parsed as HTML
  return node;
}

function toast(text, kind = 'info') {
  const t = $('#toast');
  t.textContent = text;
  t.className = `toast show ${kind}`;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { t.className = 'toast'; }, kind === 'error' ? 7000 : 3500);
}

async function busy(button, label, fn) {
  const old = button.textContent;
  button.disabled = true;
  button.textContent = label;
  try { return await fn(); } catch (e) { toast(e.message || String(e), 'error'); }
  finally { button.disabled = false; button.textContent = old; }
}

function bars(signal) {
  const level = signal >= 75 ? 4 : signal >= 50 ? 3 : signal >= 25 ? 2 : 1;
  const b = el('span', { className: 'bars', title: `${signal}%` });
  for (let i = 1; i <= 4; i++) b.append(el('i', { className: i <= level ? 'on' : '' }));
  return b;
}

function setConnected(on) {
  document.body.classList.toggle('connected', on);
  $('#device-name').textContent = on ? link.name || 'Raspberry Pi' : '';
}

function renderStatus(st) {
  const grid = $('#status');
  grid.replaceChildren();
  const row = (k, v) => grid.append(el('dt', {}, k), el('dd', {}, v));
  row('Hostname', st.host);
  row('Wi-Fi', st.ssid ? el('span', {}, st.ssid, ' ', bars(st.signal)) : el('span', { className: 'muted' }, 'Not connected'));
  row('State', st.state);
  const ifaces = Object.entries(st.ips || {});
  if (!ifaces.length) row('IP address', el('span', { className: 'muted' }, 'none'));
  for (const [name, addrs] of ifaces) {
    const box = el('div', { className: 'ips' });
    for (const a of addrs) {
      const ip = a.split('/')[0];
      const copy = el('button', { className: 'link', type: 'button', textContent: 'copy' });
      copy.onclick = () => navigator.clipboard.writeText(ip).then(() => toast(`Copied ${ip}`));
      box.append(el('div', {}, el('code', {}, a), ' ', copy));
    }
    row(`IP (${name})`, box);
  }
}

function renderNetworks(nets) {
  const list = $('#networks');
  list.replaceChildren();
  if (!nets.length) list.append(el('li', { className: 'muted' }, 'No networks found.'));
  for (const n of nets) {
    const li = el('li', { className: 'net' + (n.active ? ' active' : '') },
      el('span', { className: 'ssid' }, n.ssid),
      n.active ? el('span', { className: 'tag' }, 'connected') : null,
      el('span', { className: 'sec' }, n.security ? '🔒' : 'open'),
      bars(n.signal));
    li.tabIndex = 0;
    li.onclick = () => openJoin(n.ssid, !!n.security, false);
    li.onkeydown = (e) => { if (e.key === 'Enter') li.onclick(); };
    list.append(li);
  }
}

function renderSaved(profiles) {
  const list = $('#saved');
  list.replaceChildren();
  if (!profiles.length) list.append(el('li', { className: 'muted' }, 'No saved Wi-Fi networks.'));
  for (const p of profiles) {
    const use = el('button', { type: 'button', textContent: 'Connect', disabled: p.active });
    const del = el('button', { type: 'button', className: 'danger', textContent: 'Forget' });
    use.onclick = () => busy(use, 'Connecting…', async () => {
      renderStatus(await link.request('activate', { uuid: p.uuid }, 75000));
      toast(`Connected to ${p.ssid}`, 'ok');
      await refreshSaved();
    });
    del.onclick = () => {
      const warn = p.active ? '\nThe Pi is using this network right now and will disconnect.' : '';
      if (!confirm(`Forget "${p.ssid}"?${warn}`)) return;
      busy(del, '…', async () => { renderSaved(await link.request('forget', { uuid: p.uuid })); await refreshStatus(); });
    };
    list.append(el('li', { className: 'net' + (p.active ? ' active' : '') },
      el('span', { className: 'ssid' }, p.ssid), p.active ? el('span', { className: 'tag' }, 'in use') : null,
      el('span', { className: 'actions' }, use, del)));
  }
}

const refreshStatus = async () => renderStatus(await link.request('status'));
const refreshSaved = async () => renderSaved(await link.request('saved'));

function openJoin(ssid, secured, hidden) {
  const dlg = $('#join');
  $('#join-ssid').value = ssid;
  $('#join-ssid').readOnly = !hidden;
  $('#join-hidden').checked = hidden;
  $('#join-hidden-row').hidden = !hidden;
  $('#join-psk').value = '';
  $('#join-psk-row').hidden = !secured && !hidden;
  $('#join-title').textContent = hidden ? 'Join a hidden network' : `Join "${ssid}"`;
  dlg.showModal();
  (hidden ? $('#join-ssid') : $('#join-psk')).focus();
}

async function doConnect(newDevice) {
  const secret = $('#secret').value;
  if (secret.trim().length < 8) { toast('Enter the secret shown by install.sh on the Pi.', 'error'); return; }
  const btn = newDevice ? $('#connect') : $('#reconnect');
  await busy(btn, 'Connecting…', async () => {
    if (newDevice || !link.device) await link.pick();
    const st = await link.open(secret);
    if ($('#remember').checked) localStorage.setItem(SECRET_KEY, secret.trim());
    else localStorage.removeItem(SECRET_KEY);
    setConnected(true);
    renderStatus(st);
    toast(`Connected to ${link.name}`, 'ok');
    await refreshSaved();
  });
  if (!link.connected) link.disconnect();
}

function init() {
  if (!navigator.bluetooth) $('#unsupported').hidden = false;
  try {
    const saved = localStorage.getItem(SECRET_KEY);
    if (saved) { $('#secret').value = saved; $('#remember').checked = true; }
  } catch { /* storage unavailable */ }

  $('#connect').onclick = () => doConnect(true);
  $('#reconnect').onclick = () => doConnect(false);
  $('#disconnect').onclick = () => link.disconnect();
  $('#refresh').onclick = (e) => busy(e.target, 'Refreshing…', refreshStatus);
  $('#scan').onclick = (e) => busy(e.target, 'Scanning…', async () => renderNetworks(await link.request('scan', {}, 45000)));
  $('#hidden-btn').onclick = () => openJoin('', true, true);
  $('#join-cancel').onclick = () => $('#join').close();
  $('#join-show').onchange = (e) => { $('#join-psk').type = e.target.checked ? 'text' : 'password'; };

  $('#join-form').onsubmit = (e) => {
    e.preventDefault();
    const ssid = $('#join-ssid').value;
    const psk = $('#join-psk').value;
    const hidden = $('#join-hidden').checked;
    $('#join').close();
    busy($('#scan'), 'Connecting…', async () => {
      toast(`Connecting the Pi to "${ssid}"… this can take up to a minute.`);
      renderStatus(await link.request('connect', { ssid, psk, hidden }, 75000));
      toast(`The Pi joined "${ssid}"`, 'ok');
      await refreshSaved();
    });
  };

  link.addEventListener('disconnected', () => {
    if (document.body.classList.contains('connected')) toast('Bluetooth connection closed');
    setConnected(false);
    $('#reconnect').hidden = !link.device;
  });
}

init();
