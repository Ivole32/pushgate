// Pushgate admin PWA. No dependencies. All server-provided text is inserted with
// textContent; nothing is ever parsed as HTML.

const $ = (id) => document.getElementById(id);
const DEVICE_KEY = 'pushgate.device_id';
let csrf = null;
let oldestEvent = null;
let vapidKey = null;

// ---------- helpers ----------

const b64urlToBytes = (s) => {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4);
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
};
const bytesToB64url = (buf) => {
  let bin = '';
  for (const b of new Uint8Array(buf)) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};
const fmt = (t) => (t ? new Date(t).toLocaleString() : '—');

function flash(message, kind = 'info') {
  const el = $('flash');
  el.textContent = message;
  el.dataset.kind = kind;
  el.hidden = false;
  clearTimeout(flash.timer);
  flash.timer = setTimeout(() => { el.hidden = true; }, 6000);
}

async function api(method, path, body) {
  const headers = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (csrf && method !== 'GET') headers['X-CSRF-Token'] = csrf;
  const res = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), credentials: 'same-origin' });
  const data = await res.json().catch(() => ({}));
  if (res.status === 401 && csrf) {
    csrf = null;
    await boot();
  }
  if (!res.ok) {
    const err = new Error(data?.error?.message || `Request failed (${res.status})`);
    err.status = res.status;
    // Sensitive changes need a recent passkey confirmation. WebAuthn needs a fresh tap on iOS,
    // so ask for one instead of starting the ceremony from here.
    if (data?.error?.code === 'reauth_required') $('reauth').hidden = false;
    throw err;
  }
  return data;
}

function item({ title, meta, actions = [] }) {
  const li = $('tpl-item').content.firstElementChild.cloneNode(true);
  li.querySelector('.item-title').textContent = title;
  li.querySelector('.item-meta').textContent = meta;
  const box = li.querySelector('.item-actions');
  for (const a of actions) {
    if (a.node) {
      box.append(a.node);
      continue;
    }
    const btn = document.createElement('button');
    btn.textContent = a.label;
    btn.className = a.className || 'secondary';
    btn.addEventListener('click', () => guarded(a.onClick)());
    box.append(btn);
  }
  return li;
}

function fill(listId, nodes, empty) {
  const list = $(listId);
  list.replaceChildren(...nodes);
  if (nodes.length === 0) {
    const li = document.createElement('li');
    li.className = 'empty';
    li.textContent = empty;
    list.append(li);
  }
}

const guarded = (fn) => async (...args) => {
  try {
    await fn(...args);
  } catch (err) {
    flash(err.message || 'Something went wrong', 'error');
  }
};

// ---------- WebAuthn (manual JSON conversion; works on iOS 16.4+) ----------

function creationOptions(o) {
  return {
    ...o,
    challenge: b64urlToBytes(o.challenge),
    user: { ...o.user, id: b64urlToBytes(o.user.id) },
    excludeCredentials: (o.excludeCredentials || []).map((c) => ({ ...c, id: b64urlToBytes(c.id) })),
  };
}

function registrationJSON(cred) {
  return {
    id: cred.id,
    rawId: bytesToB64url(cred.rawId),
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment ?? undefined,
    clientExtensionResults: cred.getClientExtensionResults(),
    response: {
      clientDataJSON: bytesToB64url(cred.response.clientDataJSON),
      attestationObject: bytesToB64url(cred.response.attestationObject),
      transports: typeof cred.response.getTransports === 'function' ? cred.response.getTransports() : [],
    },
  };
}

function assertionJSON(cred) {
  return {
    id: cred.id,
    rawId: bytesToB64url(cred.rawId),
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment ?? undefined,
    clientExtensionResults: cred.getClientExtensionResults(),
    response: {
      clientDataJSON: bytesToB64url(cred.response.clientDataJSON),
      authenticatorData: bytesToB64url(cred.response.authenticatorData),
      signature: bytesToB64url(cred.response.signature),
      userHandle: cred.response.userHandle ? bytesToB64url(cred.response.userHandle) : undefined,
    },
  };
}

async function createPasskey(optionsPath, optionsBody) {
  const { challenge_id, options } = await api('POST', optionsPath, optionsBody);
  const cred = await navigator.credentials.create({ publicKey: creationOptions(options) });
  return { challenge_id, response: registrationJSON(cred) };
}

// ---------- push subscription ----------

function pushSupport() {
  if (!window.isSecureContext) return 'This page is not served over HTTPS.';
  if (!('serviceWorker' in navigator)) return 'This browser does not support service workers.';
  if (!('PushManager' in window) || !('Notification' in window)) {
    return isIOS() && !isStandalone()
      ? 'Open Pushgate from the Home Screen icon to enable notifications.'
      : 'This browser does not support Web Push (iOS requires 16.4 or later and a Home Screen web app).';
  }
  return null;
}

const isIOS = () => /iPad|iPhone|iPod/.test(navigator.userAgent) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
const isStandalone = () => window.matchMedia('(display-mode: standalone)').matches || navigator.standalone === true;

async function registration() {
  return navigator.serviceWorker.register('/sw.js', { scope: '/' });
}

async function refreshDeviceState(devices) {
  const problem = pushSupport();
  const known = devices.some((d) => d.id === localStorage.getItem(DEVICE_KEY));
  let sub = null;
  if (!problem) sub = await (await registration()).pushManager.getSubscription();
  const active = Boolean(sub && known);
  $('device-state').textContent = problem
    ? problem
    : active
      ? `Notifications are enabled on this device (permission: ${Notification.permission}).`
      : Notification.permission === 'denied'
        ? 'Notifications are blocked for this app. Re-enable them in iOS Settings → Notifications → Pushgate.'
        : 'Notifications are not enabled on this device.';
  $('subscribe-form').hidden = Boolean(problem) || active || Notification.permission === 'denied';
  $('unsubscribe-btn').hidden = !active;
  $('test-self').hidden = !active;
}

async function subscribe(event) {
  event.preventDefault();
  const form = event.target;
  // Must run directly from the tap: iOS only shows the permission prompt for a user gesture.
  const permission = await Notification.requestPermission();
  if (permission !== 'granted') throw new Error('Notification permission was not granted.');
  const reg = await registration();
  await navigator.serviceWorker.ready;
  let sub = await reg.pushManager.getSubscription();
  if (!sub) sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: b64urlToBytes(vapidKey) });
  const { device } = await api('POST', '/admin/api/devices', {
    name: form.name.value.trim(),
    min_priority: form.min_priority.value,
    subscription: sub.toJSON(),
  });
  localStorage.setItem(DEVICE_KEY, device.id);
  flash('Notifications enabled on this device.');
  await loadAll();
}

async function unsubscribe() {
  const id = localStorage.getItem(DEVICE_KEY);
  const sub = await (await registration()).pushManager.getSubscription();
  if (sub) await sub.unsubscribe();
  if (id) await api('DELETE', `/admin/api/devices/${encodeURIComponent(id)}`).catch(() => {});
  localStorage.removeItem(DEVICE_KEY);
  flash('Notifications disabled on this device.');
  await loadAll();
}

async function testPush(deviceId) {
  const r = await api('POST', '/admin/api/test-push', deviceId ? { device_id: deviceId } : {});
  flash(`Test: ${r.status} (${r.devices.delivered}/${r.devices.targeted} delivered)`, r.status === 'delivered' ? 'info' : 'error');
  await loadAll();
}

// ---------- admin sections ----------

async function loadDevices() {
  const { devices, vapid_public_key } = await api('GET', '/admin/api/devices');
  vapidKey = vapid_public_key;
  const mine = localStorage.getItem(DEVICE_KEY);
  fill('devices', devices.map((d) => {
    const select = document.createElement('select');
    for (const p of ['low', 'normal', 'high']) select.append(new Option(`min: ${p}`, p, false, p === d.min_priority));
    select.addEventListener('change', guarded(async () => {
      await api('PATCH', `/admin/api/devices/${encodeURIComponent(d.id)}`, { min_priority: select.value });
      flash('Device updated.');
    }));
    return item({
      title: d.name + (d.id === mine ? ' (this device)' : ''),
      meta: `${d.push_service} · added ${fmt(d.created_at)} · last success ${fmt(d.last_success_at)}` +
        (d.failure_count ? ` · ${d.failure_count} failure(s), last status ${d.last_status ?? 'network error'}` : ''),
      actions: [
        { node: select },
        { label: 'Test', onClick: () => testPush(d.id) },
        { label: 'Remove', className: 'danger', onClick: async () => {
          if (!confirm(`Remove device "${d.name}"?`)) return;
          await api('DELETE', `/admin/api/devices/${encodeURIComponent(d.id)}`);
          if (d.id === mine) localStorage.removeItem(DEVICE_KEY);
          await loadAll();
        } },
      ],
    });
  }), 'No devices registered.');
  return devices;
}

function showNewKey(key) {
  $('new-key-value').textContent = key;
  $('new-key').hidden = false;
  $('new-key').scrollIntoView({ block: 'center' });
}

async function loadKeys() {
  const { keys } = await api('GET', '/admin/api/keys');
  fill('keys', keys.map((k) => {
    const actions = [];
    if (k.status === 'active' && !k.replaced) {
      actions.push({ label: 'Rotate', onClick: async () => {
        const answer = prompt(`Rotate "${k.name}". Hours the old key keeps working (0–168):`, '0');
        if (answer === null) return;
        const r = await api('POST', `/admin/api/keys/${k.id}/rotate`, { grace_hours: Number.parseInt(answer, 10) || 0 });
        showNewKey(r.key);
        await loadKeys();
      } });
    }
    if (k.status === 'active') {
      actions.push({ label: 'Revoke', className: 'danger', onClick: async () => {
        if (!confirm(`Revoke key for "${k.name}"? Requests using it fail immediately.`)) return;
        await api('POST', `/admin/api/keys/${k.id}/revoke`, {});
        await loadKeys();
      } });
    }
    return item({
      title: `${k.name} — ${k.status}${k.replaced && k.status === 'active' ? ' (replaced, grace period)' : ''}`,
      meta: [
        `id ${k.id}`,
        k.scopes.includes('notifications:send:high') ? 'high priority allowed' : 'low/normal only',
        `created ${fmt(k.created_at)}`,
        k.expires_at ? `expires ${fmt(k.expires_at)}` : null,
        `last used ${fmt(k.last_used_at)}`,
        k.description || null,
      ].filter(Boolean).join(' · '),
      actions,
    });
  }), 'No keys yet.');
}

async function loadOverview() {
  const o = await api('GET', '/admin/api/overview');
  $('paused').checked = o.sending_paused;
  const rows = [
    ['Version', o.version],
    ['Uptime', `${Math.floor(o.uptime_seconds / 3600)} h ${Math.floor((o.uptime_seconds % 3600) / 60)} min`],
    ['Database', o.database],
    ['Sending', !o.notifications_enabled ? 'disabled by configuration' : o.sending_paused ? 'paused' : 'enabled'],
    ['Active keys', String(o.active_keys)],
    ['Devices', String(o.devices)],
    ['Your IP (as seen by server)', o.your_ip + (o.via_proxy ? ' (via proxy)' : '')],
    ['History retention', `${o.history_retention_days} day(s)`],
  ];
  $('health').replaceChildren(...rows.flatMap(([k, v]) => {
    const dt = document.createElement('dt');
    dt.textContent = k;
    const dd = document.createElement('dd');
    dd.textContent = v;
    return [dt, dd];
  }));
  fill('deliveries', o.recent_deliveries.map((d) => item({
    title: `${d.status} · ${d.priority} · ${d.service ?? (d.key_id ? 'deleted key' : 'test')}`,
    meta: `${fmt(d.created_at)} · ${d.delivered}/${d.targeted} delivered${d.removed ? ` · ${d.removed} expired removed` : ''}`,
  })), 'No deliveries recorded.');
}

async function loadPasskeys() {
  const { passkeys } = await api('GET', '/admin/api/passkeys');
  fill('passkeys', passkeys.map((p) => item({
    title: p.name + (p.current ? ' (this session)' : ''),
    meta: `added ${fmt(p.created_at)} · last used ${fmt(p.last_used_at)}`,
    actions: passkeys.length > 1 ? [{ label: 'Remove', className: 'danger', onClick: async () => {
      if (!confirm(`Remove passkey "${p.name}"?`)) return;
      await api('DELETE', `/admin/api/passkeys/${encodeURIComponent(p.id)}`);
      await loadPasskeys();
    } }] : [],
  })), 'No passkeys.');
}

function eventItem(e) {
  const detail = Object.entries(e.detail || {}).map(([k, v]) => `${k}=${typeof v === 'string' ? v : JSON.stringify(v)}`).join(' ');
  return item({ title: e.type, meta: `${fmt(e.ts)} · ${e.actor}${e.ip ? ` · ${e.ip}` : ''}${detail ? ` · ${detail}` : ''}` });
}

async function loadEvents(append = false) {
  const q = append && oldestEvent ? `?before=${oldestEvent}` : '';
  const { events } = await api('GET', `/admin/api/events${q}`);
  if (events.length) oldestEvent = events[events.length - 1].id;
  if (append) $('events').append(...events.map(eventItem));
  else fill('events', events.map(eventItem), 'No events.');
  $('more-events').hidden = events.length < 100;
}

async function loadAll() {
  const devices = await loadDevices();
  await Promise.all([refreshDeviceState(devices), loadKeys(), loadOverview(), loadPasskeys(), loadEvents()]);
}

// ---------- boot ----------

function show(view) {
  $('login').hidden = view !== 'login';
  $('enroll').hidden = view !== 'login';
  $('admin').hidden = view !== 'admin';
  $('logout').hidden = view !== 'admin';
  if (view !== 'admin') $('reauth').hidden = true;
}

async function boot() {
  $('install-hint').hidden = !(isIOS() && !isStandalone());
  const problem = pushSupport();
  $('unsupported').hidden = !problem || (isIOS() && !isStandalone());
  $('unsupported-reason').textContent = problem || '';

  const s = await api('GET', '/admin/api/session');
  if (s.authenticated) {
    csrf = s.csrf_token;
    show('admin');
    await loadAll();
  } else {
    csrf = null;
    show('login');
    $('login').hidden = !s.setup_complete;
  }
}

async function getAssertion(optionsPath) {
  const { challenge_id, options } = await api('POST', optionsPath, {});
  const cred = await navigator.credentials.get({
    publicKey: { ...options, challenge: b64urlToBytes(options.challenge), allowCredentials: [] },
  });
  return { challenge_id, response: assertionJSON(cred) };
}

$('login-btn').addEventListener('click', guarded(async () => {
  const r = await api('POST', '/admin/api/login/verify', await getAssertion('/admin/api/login/options'));
  csrf = r.csrf_token;
  await boot();
}));

$('reauth-btn').addEventListener('click', guarded(async () => {
  await api('POST', '/admin/api/reauth/verify', await getAssertion('/admin/api/reauth/options'));
  $('reauth').hidden = true;
  flash('Confirmed. Repeat the change now.');
}));

$('enroll-form').addEventListener('submit', guarded(async (event) => {
  event.preventDefault();
  const form = event.target;
  const token = form.token.value.trim();
  const reg = await createPasskey('/admin/api/enroll/options', { token });
  await api('POST', '/admin/api/enroll/verify', { token, name: form.name.value.trim(), ...reg });
  form.reset();
  flash('Passkey created. You are signed in.');
  await boot();
}));

$('passkey-form').addEventListener('submit', guarded(async (event) => {
  event.preventDefault();
  const form = event.target;
  const reg = await createPasskey('/admin/api/passkeys/options', {});
  await api('POST', '/admin/api/passkeys/verify', { name: form.name.value.trim(), ...reg });
  form.reset();
  flash('Passkey added.');
  await loadPasskeys();
}));

$('key-form').addEventListener('submit', guarded(async (event) => {
  event.preventDefault();
  const form = event.target;
  const body = { name: form.name.value.trim(), description: form.description.value.trim(), allow_high_priority: form.allow_high.checked };
  if (form.expires.value) body.expires_at = new Date(`${form.expires.value}T23:59:59`).getTime();
  const r = await api('POST', '/admin/api/keys', body);
  form.reset();
  showNewKey(r.key);
  await loadKeys();
}));

$('copy-key').addEventListener('click', guarded(async () => {
  await navigator.clipboard.writeText($('new-key-value').textContent);
  flash('Key copied.');
}));
$('dismiss-key').addEventListener('click', () => {
  $('new-key-value').textContent = '';
  $('new-key').hidden = true;
});
$('subscribe-form').addEventListener('submit', guarded(subscribe));
$('unsubscribe-btn').addEventListener('click', guarded(unsubscribe));
$('test-self').addEventListener('click', guarded(() => testPush(localStorage.getItem(DEVICE_KEY))));
$('test-all').addEventListener('click', guarded(() => testPush(null)));
$('paused').addEventListener('change', guarded(async (event) => {
  await api('PUT', '/admin/api/settings', { sending_paused: event.target.checked });
  flash(event.target.checked ? 'Sending paused.' : 'Sending resumed.');
  await loadOverview();
}));
$('more-events').addEventListener('click', guarded(() => loadEvents(true)));
$('logout').addEventListener('click', guarded(async () => {
  await api('POST', '/admin/api/logout', {});
  csrf = null;
  await boot();
}));

guarded(boot)();
