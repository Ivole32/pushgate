import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { ORIGIN, addDevice, adminSession, fakeSubscription, notify, startApp } from './helpers.js';
import { createSoftAuthenticator } from './softauthn.js';

const apps = [];
async function app(opts) {
  const t = await startApp(opts);
  apps.push(t);
  return t;
}
after(() => Promise.all(apps.map((t) => t.close())));

const ROUTES = [
  ['GET', '/admin/api/overview'],
  ['GET', '/admin/api/keys'],
  ['POST', '/admin/api/keys', { name: 'x' }],
  ['POST', '/admin/api/keys/0123456789abcdef/revoke', {}],
  ['POST', '/admin/api/keys/0123456789abcdef/rotate', {}],
  ['GET', '/admin/api/devices'],
  ['POST', '/admin/api/devices', { name: 'x', subscription: fakeSubscription().subscription }],
  ['PATCH', '/admin/api/devices/AAAAAAAAAAAAAAAAAAAAAA', { name: 'y' }],
  ['DELETE', '/admin/api/devices/AAAAAAAAAAAAAAAAAAAAAA'],
  ['POST', '/admin/api/test-push', {}],
  ['GET', '/admin/api/events'],
  ['PUT', '/admin/api/settings', { sending_paused: true }],
  ['GET', '/admin/api/passkeys'],
  ['POST', '/admin/api/passkeys/options', {}],
  ['DELETE', '/admin/api/passkeys/abc'],
  ['POST', '/admin/api/logout', {}],
];

test('administrative endpoints require an authenticated session', async () => {
  const t = await app();
  for (const [method, path, body] of ROUTES) {
    const r = await t.request({ method, path, body, headers: { Origin: ORIGIN } });
    assert.equal(r.status, 401, `${method} ${path}`);
  }
  const s = await t.request({ path: '/admin/api/session' });
  assert.deepEqual(s.json, { authenticated: false, setup_complete: false });
});

test('service API keys cannot manage credentials, devices or settings', async () => {
  const t = await app();
  const { key, record } = t.ctx.keys.create({ name: 'svc' });
  const { record: other } = t.ctx.keys.create({ name: 'other' });
  const bearer = { Authorization: `Bearer ${key}`, Origin: ORIGIN };
  for (const [method, path, body] of [
    ...ROUTES,
    ['POST', `/admin/api/keys/${other.id}/revoke`, {}],
    ['POST', `/admin/api/keys/${other.id}/rotate`, {}],
    ['POST', `/admin/api/keys/${record.id}/rotate`, {}],
  ]) {
    const r = await t.request({ method, path, body, headers: bearer });
    assert.equal(r.status, 401, `${method} ${path}`);
  }
  assert.equal(t.ctx.keys.get(other.id).status, 'active');
  assert.equal(t.ctx.keys.list().length, 2);
});

test('state-changing admin requests require Origin and the CSRF token', async () => {
  const t = await app();
  const s = adminSession(t);
  const body = { name: 'svc' };
  const post = (headers) => t.request({ method: 'POST', path: '/admin/api/keys', body, headers });
  assert.equal((await post({ Cookie: s.headers.Cookie, 'X-CSRF-Token': s.csrf })).status, 403, 'no Origin');
  assert.equal((await post({ ...s.headers, Origin: 'https://evil.example' })).status, 403, 'foreign Origin');
  assert.equal((await post({ ...s.headers, 'Sec-Fetch-Site': 'cross-site' })).status, 403, 'cross-site fetch');
  assert.equal((await post({ Cookie: s.headers.Cookie, Origin: ORIGIN })).status, 403, 'no CSRF token');
  assert.equal((await post({ ...s.headers, 'X-CSRF-Token': 'x'.repeat(43) })).status, 403, 'wrong CSRF token');
  assert.equal(t.ctx.keys.list().length, 0);
  const ok = await post(s.headers);
  assert.equal(ok.status, 201);
  assert.match(ok.json.key, /^pgk_[0-9a-f]{16}_[A-Za-z0-9_-]{43}$/);
});

test('admin key management: create (shown once), list without secrets, rotate, revoke', async () => {
  const t = await app();
  addDevice(t);
  const s = adminSession(t);
  const created = await t.request({ method: 'POST', path: '/admin/api/keys', headers: s.headers, body: { name: 'backup', description: 'nightly', allow_high_priority: true } });
  assert.equal(created.status, 201);
  const { key, record } = created.json;
  assert.deepEqual(record.scopes, ['notifications:send', 'notifications:send:high']);

  const list = await t.request({ path: '/admin/api/keys', headers: s.readHeaders });
  assert.ok(!list.text.includes(key.slice(21)), 'list never includes the secret');
  assert.ok(!list.text.includes('key_hash'));

  const rotated = await t.request({ method: 'POST', path: `/admin/api/keys/${record.id}/rotate`, headers: s.headers, body: { grace_hours: 0 } });
  assert.equal(rotated.status, 201);
  assert.equal(rotated.json.previous.status, 'revoked');
  assert.equal((await notify(t, key)).status, 401);
  assert.equal((await notify(t, rotated.json.key)).status, 200);

  const revoked = await t.request({ method: 'POST', path: `/admin/api/keys/${rotated.json.record.id}/revoke`, headers: s.headers, body: {} });
  assert.equal(revoked.status, 200);
  assert.equal((await notify(t, rotated.json.key)).status, 401);
  assert.equal((await t.request({ method: 'POST', path: `/admin/api/keys/${rotated.json.record.id}/revoke`, headers: s.headers, body: {} })).status, 404);

  const past = await t.request({ method: 'POST', path: '/admin/api/keys', headers: s.headers, body: { name: 'x', expires_at: Date.now() - 1000 } });
  assert.equal(past.status, 400);
  const events = t.ctx.audit.list().map((e) => e.type);
  for (const e of ['api_key.created', 'api_key.rotated', 'api_key.revoked']) assert.ok(events.includes(e));
});

test('unauthorized users cannot register, replace or revoke device subscriptions', async () => {
  const t = await app();
  const existing = addDevice(t, { name: 'real' });
  const attacker = fakeSubscription().subscription;
  const replacement = { ...existing.subscription, keys: fakeSubscription().subscription.keys };
  const tries = [
    ['POST', '/admin/api/devices', { name: 'evil', subscription: attacker }],
    ['POST', '/admin/api/devices', { name: 'evil', subscription: replacement }],
    ['PATCH', `/admin/api/devices/${existing.id}`, { min_priority: 'high' }],
    ['DELETE', `/admin/api/devices/${existing.id}`],
  ];
  for (const [method, path, body] of tries) {
    for (const headers of [{}, { Origin: ORIGIN }, { Origin: ORIGIN, Cookie: '__Host-pushgate_session=' + 'A'.repeat(43) }]) {
      const r = await t.request({ method, path, body, headers });
      // 403 without a same-origin Origin header, 401 without a valid session.
      assert.equal(r.status, headers.Origin ? 401 : 403, `${method} ${path}`);
    }
  }
  const rows = t.db.prepare('SELECT * FROM devices').all();
  assert.equal(rows.length, 1);
  assert.equal(rows[0].p256dh, existing.subscription.keys.p256dh);
  assert.equal(rows[0].min_priority, 'low');
});

test('an admin can register, update, test and remove devices; secrets are never returned', async () => {
  const t = await app({ env: { MAX_DEVICES: '2' } });
  const s = adminSession(t);
  const sub = fakeSubscription().subscription;
  const reg = await t.request({ method: 'POST', path: '/admin/api/devices', headers: s.headers, body: { name: 'iPhone', min_priority: 'normal', subscription: sub } });
  assert.equal(reg.status, 201);
  const id = reg.json.device.id;
  const again = await t.request({ method: 'POST', path: '/admin/api/devices', headers: s.headers, body: { name: 'iPhone 2', subscription: sub } });
  assert.equal(again.status, 200, 'same endpoint updates instead of duplicating');
  const list = await t.request({ path: '/admin/api/devices', headers: s.readHeaders });
  assert.equal(list.json.devices.length, 1);
  assert.equal(list.json.devices[0].push_service, 'web.push.apple.com');
  for (const secret of [sub.endpoint, sub.keys.p256dh, sub.keys.auth]) assert.ok(!list.text.includes(secret));

  const ssrf = await t.request({ method: 'POST', path: '/admin/api/devices', headers: s.headers, body: { name: 'x', subscription: { ...sub, endpoint: 'https://169.254.169.254/latest' } } });
  assert.equal(ssrf.status, 400);
  assert.equal(ssrf.json.error.code, 'invalid_subscription');

  addDevice(t);
  const full = await t.request({ method: 'POST', path: '/admin/api/devices', headers: s.headers, body: { name: 'x', subscription: fakeSubscription().subscription } });
  assert.equal(full.status, 409, 'device limit');

  const upd = await t.request({ method: 'PATCH', path: `/admin/api/devices/${id}`, headers: s.headers, body: { min_priority: 'high' } });
  assert.equal(upd.json.device.min_priority, 'high');
  const tp = await t.request({ method: 'POST', path: '/admin/api/test-push', headers: s.headers, body: { device_id: id } });
  assert.equal(tp.json.status, 'delivered');
  assert.equal(t.push.calls.filter((c) => JSON.parse(c.payload).title === 'Pushgate test').length, 1);
  assert.equal((await t.request({ method: 'DELETE', path: `/admin/api/devices/${id}`, headers: s.headers })).status, 200);
  assert.equal(t.ctx.devices.get(id), null);
});

test('settings, overview and security events are available to the admin without secrets', async () => {
  const t = await app();
  const s = adminSession(t);
  const { key } = t.ctx.keys.create({ name: 'svc' });
  await notify(t, key + 'bad');
  const put = await t.request({ method: 'PUT', path: '/admin/api/settings', headers: s.headers, body: { sending_paused: true } });
  assert.equal(put.status, 200);
  assert.equal((await notify(t, key)).status, 503);
  const o = await t.request({ path: '/admin/api/overview', headers: s.readHeaders });
  assert.equal(o.json.database, 'ok');
  assert.equal(o.json.sending_paused, true);
  assert.equal(o.json.your_ip, '127.0.0.1');
  const ev = await t.request({ path: '/admin/api/events', headers: s.readHeaders });
  const types = ev.json.events.map((e) => e.type);
  assert.ok(types.includes('auth.failed') && types.includes('settings.changed'));
  assert.ok(!ev.text.includes(key.slice(21).slice(0, 20)));
});

test('sessions expire and logout invalidates the session', async () => {
  const t = await app({ env: { SESSION_IDLE_MINUTES: '5' } });
  const s = adminSession(t);
  assert.equal((await t.request({ path: '/admin/api/keys', headers: s.readHeaders })).status, 200);
  const out = await t.request({ method: 'POST', path: '/admin/api/logout', headers: s.headers, body: {} });
  assert.match(out.headers['set-cookie'][0], /Max-Age=0/);
  assert.equal((await t.request({ path: '/admin/api/keys', headers: s.readHeaders })).status, 401);

  const s2 = adminSession(t);
  t.db.prepare('UPDATE sessions SET last_seen_at = ?').run(Date.now() - 6 * 60000);
  assert.equal((await t.request({ path: '/admin/api/keys', headers: s2.readHeaders })).status, 401, 'idle timeout');
});

test('passkey enrollment requires a one-time token; login works with the enrolled passkey', async () => {
  const t = await app();
  const authn = createSoftAuthenticator({ origin: ORIGIN, rpId: 'pushgate.test' });
  const post = (path, body, headers = {}) => t.request({ method: 'POST', path, body, headers: { Origin: ORIGIN, ...headers } });

  // No token / invented token: nothing is issued.
  assert.equal((await post('/admin/api/enroll/options', { token: 'pge_' + 'A'.repeat(43) })).status, 401);
  assert.equal((await post('/admin/api/enroll/options', {}, {})).status, 400);
  assert.equal((await post('/admin/api/enroll/options', { token: 'x' }, { Origin: 'https://evil.example' })).status, 403);

  const { token } = t.ctx.auth.createEnrollmentToken();
  const opts = await post('/admin/api/enroll/options', { token });
  assert.equal(opts.status, 200);
  assert.equal(opts.json.options.rp.id, 'pushgate.test');
  assert.equal(opts.json.options.authenticatorSelection.userVerification, 'required');

  // A response for the wrong origin fails and burns the challenge.
  const wrong = await post('/admin/api/enroll/verify', { token, name: 'phone', challenge_id: opts.json.challenge_id, response: authn.register(opts.json.options, { clientOrigin: 'https://evil.example' }) });
  assert.equal(wrong.status, 401);
  assert.equal(t.ctx.auth.hasAdmin(), false);

  const opts2 = await post('/admin/api/enroll/options', { token });
  const enrolled = await post('/admin/api/enroll/verify', { token, name: 'phone', challenge_id: opts2.json.challenge_id, response: authn.register(opts2.json.options) });
  assert.equal(enrolled.status, 200);
  const cookie = enrolled.headers['set-cookie'][0];
  assert.match(cookie, /^__Host-pushgate_session=[A-Za-z0-9_-]{43}; Path=\/; Secure; HttpOnly; SameSite=Strict; Max-Age=\d+$/);
  assert.equal(t.ctx.auth.hasAdmin(), true);

  // The token is single use.
  assert.equal((await post('/admin/api/enroll/options', { token })).status, 401);

  // Login with the passkey.
  const lo = await post('/admin/api/login/options', {});
  const login = await post('/admin/api/login/verify', { challenge_id: lo.json.challenge_id, response: authn.login(lo.json.options) });
  assert.equal(login.status, 200);
  const sessionCookie = login.headers['set-cookie'][0].split(';')[0];
  const keys = await t.request({ path: '/admin/api/keys', headers: { Cookie: sessionCookie } });
  assert.equal(keys.status, 200);

  // Replaying the same assertion (challenge already used) fails.
  const replay = await post('/admin/api/login/verify', { challenge_id: lo.json.challenge_id, response: authn.login(lo.json.options) });
  assert.equal(replay.status, 400, "used challenge is rejected");
  // An unknown authenticator fails.
  const stranger = createSoftAuthenticator({ origin: ORIGIN, rpId: 'pushgate.test' });
  const lo2 = await post('/admin/api/login/options', {});
  assert.equal((await post('/admin/api/login/verify', { challenge_id: lo2.json.challenge_id, response: stranger.login(lo2.json.options) })).status, 401);

  // The last passkey cannot be removed.
  const s = { Cookie: sessionCookie, 'X-CSRF-Token': login.json.csrf_token, Origin: ORIGIN };
  const del = await t.request({ method: 'DELETE', path: `/admin/api/passkeys/${encodeURIComponent(authn.id)}`, headers: s });
  assert.equal(del.status, 409);
});

test('admin login failures are rate limited per client', async () => {
  const t = await app({ env: { AUTH_FAILURE_LIMIT: '3' } });
  const post = (path, body) => t.request({ method: 'POST', path, body, headers: { Origin: ORIGIN } });
  for (let i = 0; i < 3; i++) {
    assert.equal((await post('/admin/api/enroll/options', { token: 'pge_' + 'B'.repeat(43) })).status, 401);
  }
  assert.equal((await post('/admin/api/login/options', {})).status, 429);
  assert.equal((await post('/admin/api/enroll/options', { token: 'pge_' + 'B'.repeat(43) })).status, 429);
});

test('the PWA and admin API are only served to admin networks', async () => {
  const t = await app({ env: { ADMIN_CIDRS: '10.0.0.0/8' } });
  for (const path of ['/', '/index.html', '/sw.js', '/admin/api/session', '/healthz']) {
    const r = await t.request({ path, headers: path === '/healthz' ? { 'X-Forwarded-For': '10.0.0.1' } : {} });
    // healthz from loopback is always allowed for the container health check
    assert.equal(r.status, path === '/healthz' ? 200 : 403, path);
  }
});

test('static files carry a strict CSP and security headers', async () => {
  const t = await app();
  const r = await t.request({ path: '/' });
  assert.equal(r.status, 200);
  assert.match(r.headers['content-security-policy'], /default-src 'none'/);
  assert.match(r.headers['content-security-policy'], /script-src 'self'(;|$)/);
  assert.doesNotMatch(r.headers['content-security-policy'], /unsafe-inline|unsafe-eval/);
  assert.equal(r.headers['x-content-type-options'], 'nosniff');
  assert.equal(r.headers['x-frame-options'], 'DENY');
  assert.match(r.headers['strict-transport-security'], /max-age=/);
  // Non-canonical paths are refused before routing.
  assert.equal((await t.request({ path: '/../package.json' })).status, 400);
  assert.equal((await t.request({ path: '/%2e%2e/package.json' })).status, 400);
  assert.equal((await t.request({ path: '/manifest.webmanifest' })).headers['content-type'], 'application/manifest+json; charset=utf-8');
});

test('a distributed challenge flood cannot block or lock out the administrator', async () => {
  const t = await app({ env: { ADMIN_PUBLIC: 'true', ADMIN_CIDRS: '', TRUSTED_PROXIES: '127.0.0.1/32', AUTH_FAILURE_LIMIT: '3' } });
  const authn = createSoftAuthenticator({ origin: ORIGIN, rpId: 'pushgate.test' });
  const admin = { Origin: ORIGIN, 'X-Forwarded-For': '203.0.113.9' };
  const post = (path, body, headers = admin) => t.request({ method: 'POST', path, body, headers });
  const { token } = t.ctx.auth.createEnrollmentToken();
  const opts = await post('/admin/api/enroll/options', { token });
  assert.equal((await post('/admin/api/enroll/verify', { token, name: 'p', challenge_id: opts.json.challenge_id, response: authn.register(opts.json.options) })).status, 200);

  // The administrator starts a sign-in; then 1500 other addresses request challenges
  // (more than the old fixed-size challenge table could hold).
  const pending = await post('/admin/api/login/options', {});
  for (let i = 0; i < 1500; i++) {
    const r = await post('/admin/api/login/options', {}, { Origin: ORIGIN, 'X-Forwarded-For': `198.51.${100 + (i >> 8)}.${i & 255}` });
    assert.equal(r.status, 200);
  }

  // Forged, cross-kind and malformed challenges are rejected but not counted as credential failures.
  const [payload] = pending.json.challenge_id.split('.');
  const forged = `${payload}.${'A'.repeat(43)}`;
  // A fresh, validly signed enrollment challenge offered for login: rejected because kinds are bound.
  const crossKind = (await post('/admin/api/enroll/options', { token: t.ctx.auth.createEnrollmentToken().token })).json.challenge_id;
  for (const challenge_id of [forged, crossKind, forged, forged]) {
    const r = await post('/admin/api/login/verify', { challenge_id, response: authn.login(pending.json.options) });
    assert.equal(r.status, 400);
    assert.equal(r.json.error.code, 'challenge_expired');
  }
  const ok = await post('/admin/api/login/verify', { challenge_id: pending.json.challenge_id, response: authn.login(pending.json.options) });
  assert.equal(ok.status, 200, 'the pending sign-in still succeeds and the admin is not blocked');

  // A challenge that completed a sign-in cannot be used again.
  const replay = await post('/admin/api/login/verify', { challenge_id: pending.json.challenge_id, response: authn.login(pending.json.options) });
  assert.equal(replay.status, 400);
});

test('unauthenticated admin endpoints are rate limited per client inside the app', async () => {
  const t = await app({ env: { RATE_LIMIT_ADMIN_ANONYMOUS_PER_MINUTE: '5' } });
  const statuses = [];
  for (let i = 0; i < 7; i++) statuses.push((await t.request({ method: 'POST', path: '/admin/api/login/options', body: {}, headers: { Origin: ORIGIN } })).status);
  assert.deepEqual(statuses, [200, 200, 200, 200, 200, 429, 429]);
});

test('ADMIN_PUBLIC opens only the web app and admin API; sending stays restricted', async () => {
  const t = await app({ env: { ADMIN_PUBLIC: 'true', ADMIN_CIDRS: '', TRUSTED_PROXIES: '127.0.0.1/32', TRUSTED_CIDRS: '10.0.0.0/8' } });
  const { key } = t.ctx.keys.create({ name: 'svc' });
  const internet = { 'X-Forwarded-For': '203.0.113.9' };
  assert.equal((await t.request({ path: '/', headers: internet })).status, 200);
  assert.equal((await t.request({ path: '/admin/api/session', headers: internet })).status, 200);
  assert.equal((await t.request({ path: '/admin/api/keys', headers: internet })).status, 401, 'still needs a passkey session');
  const send = await t.request({ method: 'POST', path: '/api/v1/notifications', headers: { ...internet, Authorization: `Bearer ${key}` }, body: { title: 'a', message: 'b' } });
  assert.equal(send.status, 403, 'sending API keeps its CIDR restriction');
  // The proxy rules still apply: spoofed or missing forwarding headers are refused.
  assert.equal((await t.request({ path: '/', headers: { 'X-Forwarded-For': '203.0.113.9, 10.0.0.1' } })).status, 403);
  assert.equal((await t.request({ path: '/' })).status, 403);
});

test('login challenges do not survive a server restart', async () => {
  const { startApp, tempDir } = await import('./helpers.js');
  const dir = tempDir();
  const first = await startApp({ dir }); // closed below, not by the shared teardown
  const authn = createSoftAuthenticator({ origin: ORIGIN, rpId: 'pushgate.test' });
  const post = (t, path, body) => t.request({ method: 'POST', path, body, headers: { Origin: ORIGIN } });
  const { token } = first.ctx.auth.createEnrollmentToken();
  const eo = await post(first, '/admin/api/enroll/options', { token });
  await post(first, '/admin/api/enroll/verify', { token, name: 'p', challenge_id: eo.json.challenge_id, response: authn.register(eo.json.options) });
  const lo = await post(first, '/admin/api/login/options', {});
  const captured = { challenge_id: lo.json.challenge_id, response: authn.login(lo.json.options) };
  assert.equal((await post(first, '/admin/api/login/verify', captured)).status, 200);
  await first.close();

  // Same data directory and secrets, new process: the captured request must not log in again.
  const second = await app({ dir, secrets: first.secrets });
  const replay = await post(second, '/admin/api/login/verify', captured);
  assert.equal(replay.status, 400);
  assert.equal(replay.json.error.code, 'challenge_expired');
});
