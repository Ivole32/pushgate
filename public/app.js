// Pushgate admin PWA. No dependencies. All server-provided text is inserted with
// textContent; nothing is ever parsed as HTML. Plugins listed by the server (same origin) can
// add sections through the small API passed to their entry module (see docs/PLUGINS.md).

const $ = (id) => document.getElementById(id);
const DEVICE_KEY = 'pushgate.device_id';
let csrf = null;
let oldestEvent = null;
let vapidKey = null;
let session = null;
let pluginsLoaded = false;
const pluginSections = [];

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

// `approve(options)` may look at the options first and return false to stop (returns null).
async function createPasskey(optionsPath, optionsBody, approve = () => true) {
  const { challenge_id, options } = await api('POST', optionsPath, optionsBody);
  if (!approve(options)) return null;
  const cred = await navigator.credentials.create({ publicKey: creationOptions(options) });
  return { challenge_id, response: registrationJSON(cred) };
}

// Creates the first (or a recovery) passkey of an account with a one-time token and signs in.
// With `confirmAccount` (a token that came in a link, possibly from someone else) the account
// is named and must be confirmed first, so nobody is signed up into a stranger's account.
// Returns false when that was declined.
async function enroll(token, name, { confirmAccount = false } = {}) {
  const ask = (options) => !confirmAccount || session?.accounts !== 'multiple'
    || confirm(`This link creates a passkey for the account "${options.user.name}". Continue only if this is your own account.`);
  const reg = await createPasskey('/admin/api/enroll/options', { token }, ask);
  if (!reg) return false;
  await api('POST', '/admin/api/enroll/verify', { token, name, ...reg });
  await boot();
  return true;
}

// ---------- push subscription ----------

// Push is available when the browser has service workers and the Push API (the
// registration's pushManager, the standard check; the global PushManager is not exposed
// everywhere). The Notification global is optional: without it, subscribing asks for the
// permission itself. Returns null, or a message that says what is missing.
const hasPushApi = () => 'PushManager' in window
  || ('ServiceWorkerRegistration' in window && 'pushManager' in ServiceWorkerRegistration.prototype);

// Every message ends with what the browser reports, so a problem can be reported precisely.
function pushSupport() {
  if (!window.isSecureContext) return `This page is not served over HTTPS. (${pushDetails()})`;
  if (isIOS() && !isStandalone() && !hasPushApi()) return `Open Pushgate from the Home Screen icon to enable notifications. (${pushDetails()})`;
  if ('serviceWorker' in navigator && hasPushApi()) return null;
  if (!isIOS()) return `This browser does not support Web Push. (${pushDetails()})`;
  // Lockdown Mode turns off service workers, and with them push, for websites and Home Screen
  // apps unless the site is excluded.
  if (!('serviceWorker' in navigator)) {
    return 'iOS has turned off service workers for this app, and push notifications need them. This is usually '
      + 'Lockdown Mode: open this address in Safari, tap aA in the address bar → Website Settings, turn off '
      + 'Lockdown Mode for this website, then close the Home Screen app completely and open it again. (Excluded '
      + 'websites are listed under Settings → Privacy & Security → Lockdown Mode → Configure Web Browsing.) '
      + `Safari's "Block All Cookies" setting has the same effect. (${pushDetails()})`;
  }
  return 'iOS does not offer push notifications to this Home Screen app. They need iOS 16.4 or later, and iOS '
    + 'enables them only for apps added to the Home Screen from Safari with their web app manifest: remove the '
    + 'Pushgate icon, open this address in Safari, choose Share → Add to Home Screen, and open it from the new icon. '
    + `If that does not help, check that notifications and the Push API are not turned off under Settings → Apps → Safari → Advanced → Feature Flags. (${pushDetails()})`;
}

// What the browser reports, so a problem can be told apart (and reported) precisely.
function pushDetails() {
  const ios = /OS (\d+)[._](\d+)/.exec(navigator.userAgent);
  const yes = (v) => (v ? 'yes' : 'no');
  return [
    ios ? `iOS ${ios[1]}.${ios[2]}` : null,
    `secure connection: ${yes(window.isSecureContext)}`,
    `Home Screen app: ${yes(isStandalone())}`,
    `service worker: ${yes('serviceWorker' in navigator)}`,
    `Push API: ${yes(hasPushApi())}`,
    `notification permission API: ${yes('Notification' in window)}`,
  ].filter(Boolean).join(', ');
}

const isIOS = () => /iPad|iPhone|iPod/.test(navigator.userAgent) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
const isStandalone = () => window.matchMedia('(display-mode: standalone)').matches || navigator.standalone === true;

// 'granted', 'denied' or 'default', from the Notification API or, without it, the Push API.
async function notificationPermission(reg) {
  if ('Notification' in window) return Notification.permission;
  const state = await reg.pushManager.permissionState({ userVisibleOnly: true });
  return state === 'prompt' ? 'default' : state;
}

async function registration() {
  return navigator.serviceWorker.register('/sw.js', { scope: '/' });
}

async function refreshDeviceState(devices) {
  const problem = pushSupport();
  const known = devices.some((d) => d.id === localStorage.getItem(DEVICE_KEY));
  let sub = null;
  let permission = 'default';
  let failure = null;
  if (!problem) {
    // A service worker that cannot start is shown here instead of leaving "Checking…"; the
    // form stays, so a tap retries and reports the error again.
    try {
      const reg = await registration();
      sub = await reg.pushManager.getSubscription();
      permission = await notificationPermission(reg);
    } catch (err) {
      const reason = String(err.message || err).replace(/\.$/, '');
      failure = `The notification service worker could not be started: ${reason}. (${pushDetails()})`;
    }
  }
  const active = Boolean(sub && known);
  $('device-state').textContent = problem || failure || (active
    ? `Notifications are enabled on this device (permission: ${permission}).`
    : permission === 'denied'
      ? 'Notifications are blocked for this app. Re-enable them in iOS Settings → Notifications → Pushgate.'
      : 'Notifications are not enabled on this device.');
  $('subscribe-form').hidden = Boolean(problem) || active || permission === 'denied';
  $('unsubscribe-btn').hidden = !active;
  $('test-self').hidden = !active;
}

async function subscribe(event) {
  event.preventDefault();
  const form = event.target;
  // Must run directly from the tap: iOS only shows the permission prompt for a user gesture.
  // Without the Notification API, pushManager.subscribe() below asks instead.
  if ('Notification' in window) {
    const permission = await Notification.requestPermission();
    if (permission !== 'granted') throw new Error('Notification permission was not granted.');
  }
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

// ---------- plugins ----------

// What plugin entry modules receive. Their sections are cards shown while signed out or in.
const pluginApi = Object.freeze({
  api,
  flash,
  enroll: (token, name) => enroll(token, name),
  reload: () => boot(),
  session: () => (session ? structuredClone(session) : null),
  addSection({ view, title, onShow }) {
    if (view !== 'signed-out' && view !== 'signed-in') throw new Error('view must be "signed-out" or "signed-in"');
    const el = document.createElement('section');
    el.className = 'card';
    el.hidden = true;
    const h2 = document.createElement('h2');
    h2.textContent = String(title);
    el.append(h2);
    // In the order added: after the core cards of that view and earlier plugin sections.
    const previous = pluginSections.filter((p) => p.view === view).at(-1)?.el;
    (previous ?? (view === 'signed-in' ? $('admin') : $('enroll'))).after(el);
    pluginSections.push({ view, el, onShow });
    return el;
  },
});

async function loadPlugins(entries) {
  if (pluginsLoaded) return;
  pluginsLoaded = true;
  for (const url of entries) {
    try {
      const mod = await import(url);
      if (typeof mod.default === 'function') await mod.default(pluginApi);
    } catch (err) {
      console.error('plugin failed to load', url, err);
      flash('A part of this app could not be loaded.', 'error');
    }
  }
}

// ---------- boot ----------

function show(view) {
  $('login').hidden = view !== 'login';
  $('enroll').hidden = view !== 'login';
  $('admin').hidden = view !== 'admin';
  $('logout').hidden = view !== 'admin';
  if (view !== 'admin') $('reauth').hidden = true;
  const pluginView = view === 'admin' ? 'signed-in' : 'signed-out';
  for (const s of pluginSections) {
    s.el.hidden = s.view !== pluginView;
    if (!s.el.hidden && typeof s.onShow === 'function') guarded(s.onShow)(s.el, pluginApi.session());
  }
}

// A link to this app ending in #enroll=pge_... (e.g. from a sign-up email) fills in
// the token. The fragment never reaches the server; it is removed from the address bar at once.
let linkedToken = null;
function takeEnrollmentLink() {
  const m = /^#enroll=(pge_[A-Za-z0-9_-]{43})$/.exec(location.hash);
  if (!m) return;
  history.replaceState(null, '', location.pathname);
  $('enroll-form').token.value = m[1];
  linkedToken = m[1];
}

async function boot() {
  $('install-hint').hidden = !(isIOS() && !isStandalone());
  const problem = pushSupport();
  $('unsupported').hidden = !problem || (isIOS() && !isStandalone());
  $('unsupported-reason').textContent = problem || '';

  const s = await api('GET', '/admin/api/session');
  const multiple = s.accounts === 'multiple';
  session = { authenticated: s.authenticated, account: s.account ?? null, accounts: s.accounts, features: s.features ?? {} };
  $('enroll-cli').hidden = multiple;
  $('enroll-hosted').hidden = !multiple;
  $('login-hint').textContent = multiple ? 'Sign in with the passkey of your account.' : 'Use the administrator passkey for this server.';
  $('account-name').hidden = !(multiple && s.account);
  $('account-name').textContent = s.account ? s.account.name : '';
  await loadPlugins(s.web ?? []);
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
  if (!await enroll(token, form.name.value.trim(), { confirmAccount: token === linkedToken })) return;
  linkedToken = null;
  form.reset();
  flash('Passkey created. You are signed in.');
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
$('revoke-others').addEventListener('click', guarded(async () => {
  if (!confirm('Sign out every other session of this account? This device stays signed in.')) return;
  const r = await api('POST', '/admin/api/sessions/revoke-others', {});
  flash(`Signed out ${r.revoked} other session(s).`);
  await loadEvents();
}));
$('logout').addEventListener('click', guarded(async () => {
  await api('POST', '/admin/api/logout', {});
  csrf = null;
  await boot();
}));

takeEnrollmentLink();
window.addEventListener('hashchange', takeEnrollmentLink);
guarded(boot)();
