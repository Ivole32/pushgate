import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { SCOPES } from '../src/apikeys.js';
import { addDevice, notify, startApp } from './helpers.js';

const apps = [];
async function app(opts) {
  const t = await startApp(opts);
  apps.push(t);
  return t;
}
after(() => Promise.all(apps.map((t) => t.close())));

test('requests without an API key are rejected', async () => {
  const t = await app();
  const r = await t.request({ method: 'POST', path: '/api/v1/notifications', body: { title: 'a', message: 'b' } });
  assert.equal(r.status, 401);
  assert.equal(r.json.error.code, 'unauthorized');
  assert.equal(t.push.calls.length, 0);
});

test('malformed, unknown, revoked and expired keys are rejected identically', async () => {
  const t = await app({ env: { AUTH_FAILURE_LIMIT: '100' } });
  addDevice(t);
  const { key: good } = t.ctx.keys.create({ name: 'svc' });
  const { key: revoked, record: rr } = t.ctx.keys.create({ name: 'old' });
  t.ctx.keys.revoke(rr.id);
  const { key: expired, record: er } = t.ctx.keys.create({ name: 'exp', expiresAt: Date.now() + 60000 });
  t.db.prepare('UPDATE api_keys SET expires_at = ? WHERE id = ?').run(Date.now() - 1, er.id);
  const tampered = good.slice(0, -1) + (good.endsWith('A') ? 'B' : 'A');
  const unknownId = 'pgk_0123456789abcdef_' + good.slice(21);

  const bad = ['', 'garbage', 'pgk_123', `${good} extra`, tampered, unknownId, revoked, expired, good.toUpperCase()];
  const bodies = new Set();
  for (const k of bad) {
    const r = await t.request({ method: 'POST', path: '/api/v1/notifications', headers: { Authorization: `Bearer ${k}` }, body: { title: 'a', message: 'b' } });
    assert.equal(r.status, 401, `key "${k.slice(0, 30)}"`);
    bodies.add(JSON.stringify({ ...r.json.error, request_id: null }));
  }
  assert.equal(bodies.size, 1, 'all failures look the same to the client');
  for (const scheme of ['Basic', 'bearer', 'Token']) {
    const r = await t.request({ method: 'POST', path: '/api/v1/notifications', headers: { Authorization: `${scheme} ${good}` }, body: { title: 'a', message: 'b' } });
    assert.equal(r.status, 401);
  }
  assert.equal((await notify(t, good)).status, 200);
  assert.equal(t.push.calls.length, 1);
});

test('a valid API key from an untrusted IP is rejected before authentication', async () => {
  const t = await app({ env: { TRUSTED_CIDRS: '10.0.0.0/8' } });
  const { key, record } = t.ctx.keys.create({ name: 'svc' });
  const r = await notify(t, key);
  assert.equal(r.status, 403);
  assert.equal(r.json.error.code, 'forbidden');
  assert.equal(t.ctx.keys.get(record.id).last_used_at, null, 'key was never evaluated');
  assert.ok(t.ctx.audit.list().some((e) => e.type === 'network.rejected' && e.detail.zone === 'api'));
});

test('a trusted IP with an invalid API key is rejected', async () => {
  const t = await app();
  const r = await notify(t, 'pgk_0123456789abcdef_' + 'x'.repeat(43));
  assert.equal(r.status, 401);
});

test('spoofed forwarding headers do not bypass CIDR restrictions', async () => {
  // No trusted proxy: the header is ignored and the real peer (127.0.0.1) is untrusted.
  const t = await app({ env: { TRUSTED_CIDRS: '10.0.0.0/8', ADMIN_CIDRS: '10.0.0.0/8' } });
  const { key } = t.ctx.keys.create({ name: 'svc' });
  for (const h of [{ 'X-Forwarded-For': '10.1.2.3' }, { Forwarded: 'for=10.1.2.3' }, { 'X-Real-IP': '10.1.2.3' }]) {
    assert.equal((await notify(t, key, undefined, h)).status, 403);
    assert.equal((await t.request({ path: '/', headers: h })).status, 403);
  }

  // Loopback configured as the proxy: only a single, trusted forwarded address passes.
  const p = await app({ env: { TRUSTED_CIDRS: '10.0.0.0/8', ADMIN_CIDRS: '10.0.0.0/8', TRUSTED_PROXIES: '127.0.0.1/32' } });
  addDevice(p);
  const { key: k2 } = p.ctx.keys.create({ name: 'svc' });
  assert.equal((await notify(p, k2)).status, 403, 'missing header from proxy');
  assert.equal((await notify(p, k2, undefined, { 'X-Forwarded-For': '192.168.5.5' })).status, 403);
  assert.equal((await notify(p, k2, undefined, { 'X-Forwarded-For': '10.1.2.3, 127.0.0.1' })).status, 403);
  assert.equal((await notify(p, k2, undefined, { 'X-Forwarded-For': '192.168.5.5, 10.1.2.3' })).status, 403);
  assert.equal((await notify(p, k2, undefined, { 'X-Forwarded-For': '10.1.2.3' })).status, 200);
});

test('direct access to the backend is refused when a reverse proxy is configured', async () => {
  const t = await app({ env: { TRUSTED_PROXIES: '172.31.250.2/32' } });
  const { key } = t.ctx.keys.create({ name: 'svc' });
  assert.equal((await notify(t, key)).status, 403);
  assert.equal((await t.request({ path: '/' })).status, 403);
  assert.equal((await t.request({ path: '/healthz' })).status, 200, 'container health check over loopback still works');
});

test('request size and schema limits are enforced', async () => {
  const t = await app();
  addDevice(t);
  const { key } = t.ctx.keys.create({ name: 'svc', scopes: [SCOPES.SEND, SCOPES.SEND_HIGH] });
  const auth = { Authorization: `Bearer ${key}` };
  const post = (opts) => t.request({ method: 'POST', path: '/api/v1/notifications', ...opts, headers: { ...auth, ...opts.headers } });

  const big = await post({ raw: JSON.stringify({ title: 't', message: 'x'.repeat(20000) }), headers: { 'Content-Type': 'application/json' } });
  assert.ok(big.status === 413 || big.reset, 'oversized body rejected');
  assert.equal((await post({ raw: 'title=a', headers: { 'Content-Type': 'application/x-www-form-urlencoded' } })).status, 415);
  assert.equal((await post({ raw: '{not json', headers: { 'Content-Type': 'application/json' } })).status, 400);
  assert.equal((await post({ raw: '[]', headers: { 'Content-Type': 'application/json' } })).status, 400);

  const invalid = [
    {},
    { title: 'a' },
    { title: '', message: 'b' },
    { title: 'a'.repeat(201), message: 'b' },
    { title: 'a', message: 'b'.repeat(2001) },
    { title: 'a', message: 'b', priority: 'urgent' },
    { title: 'a', message: 'b', url: 'https://evil.example' },
    { title: 'a', message: 'b', actions: [{ action: 'x' }] },
    { title: 'a', message: 'b', html: '<b>x</b>' },
    { title: 'a', message: 'b', tag: 'has spaces' },
    { title: 'a', message: 'b', ttl: -1 },
    { title: 'a', message: 'b', ttl: 1.5 },
    { title: 'a\u0000b', message: 'b' },
    { title: 'a\nb', message: 'b' },
    { title: 'a‮b', message: 'b' },
    { title: 5, message: 'b' },
    { title: 'a', message: 'b', __proto__x: 1 },
  ];
  for (const body of invalid) {
    const r = await post({ body });
    assert.equal(r.status, 400, JSON.stringify(body).slice(0, 60));
    assert.equal(r.json.error.code, 'validation_failed');
  }
  // Within field limits but over the Web Push payload limit (multi-byte characters).
  const huge = await post({ body: { title: '€'.repeat(200), message: '€'.repeat(2000) } });
  assert.equal(huge.status, 413);
  assert.equal(t.push.calls.length, 0, 'nothing invalid was delivered');

  const ok = await post({ body: { title: 'Disk', message: 'line 1\nline 2', priority: 'high', tag: 'disk-alert', ttl: 600 } });
  assert.equal(ok.status, 200);
  assert.equal(ok.json.status, 'delivered');
  assert.equal(t.push.calls[0].options.urgency, 'high');
  assert.equal(t.push.calls[0].options.TTL, 600);
  assert.equal(t.push.calls[0].options.topic, 'disk-alert');
});

test('high priority requires the high-priority scope', async () => {
  const t = await app();
  addDevice(t);
  const { key } = t.ctx.keys.create({ name: 'svc' });
  const r = await notify(t, key, { title: 'a', message: 'b', priority: 'high' });
  assert.equal(r.status, 403);
  assert.equal(r.json.error.code, 'insufficient_scope');
  assert.equal((await notify(t, key, { title: 'a', message: 'b', priority: 'normal' })).status, 200);
});

test('rate limits apply per service and globally', async () => {
  const t = await app({ env: { RATE_LIMIT_PER_KEY_PER_MINUTE: '3', RATE_LIMIT_GLOBAL_PER_MINUTE: '5' } });
  addDevice(t);
  const { key: a } = t.ctx.keys.create({ name: 'a' });
  const { key: b } = t.ctx.keys.create({ name: 'b' });
  for (let i = 0; i < 3; i++) assert.equal((await notify(t, a)).status, 200);
  const limited = await notify(t, a);
  assert.equal(limited.status, 429);
  assert.ok(Number(limited.headers['retry-after']) >= 1);
  // Another service is unaffected by service a's limit...
  assert.equal((await notify(t, b)).status, 200);
  assert.equal((await notify(t, b)).status, 200);
  // ...until the global limit (5) is exhausted.
  assert.equal((await notify(t, b)).status, 429);
});

test('repeated authentication failures block the client', async () => {
  const t = await app({ env: { AUTH_FAILURE_LIMIT: '3' } });
  const { key } = t.ctx.keys.create({ name: 'svc' });
  for (let i = 0; i < 3; i++) assert.equal((await notify(t, 'pgk_bad')).status, 401);
  const r = await notify(t, key);
  assert.equal(r.status, 429, 'blocked even with a valid key');
  assert.ok(t.ctx.audit.list().some((e) => e.type === 'auth.blocked'));
});

test('revoking a key takes effect immediately and does not affect other keys', async () => {
  const t = await app();
  addDevice(t);
  const { key: a, record } = t.ctx.keys.create({ name: 'a' });
  const { key: b } = t.ctx.keys.create({ name: 'b' });
  assert.equal((await notify(t, a)).status, 200);
  t.ctx.keys.revoke(record.id);
  assert.equal((await notify(t, a)).status, 401);
  assert.equal((await notify(t, b)).status, 200);
});

test('rotation issues a new key; the old key stops working (or after the grace period)', async () => {
  const t = await app();
  addDevice(t);
  const { key: old, record } = t.ctx.keys.create({ name: 'svc' });
  const rotated = t.ctx.keys.rotate(record.id);
  assert.notEqual(rotated.key, old);
  assert.equal(rotated.record.name, 'svc');
  assert.equal(rotated.record.rotated_from, record.id);
  assert.equal((await notify(t, old)).status, 401);
  assert.equal((await notify(t, rotated.key)).status, 200);

  const graced = t.ctx.keys.rotate(rotated.record.id, { graceSeconds: 3600 });
  assert.equal((await notify(t, rotated.key)).status, 200, 'old key valid during grace');
  assert.equal((await notify(t, graced.key)).status, 200);
  assert.ok(t.ctx.keys.get(rotated.record.id).expires_at <= Date.now() + 3600000);
});

test('only a hash of each key is stored', async () => {
  const t = await app();
  const { key, record } = t.ctx.keys.create({ name: 'svc' });
  const row = t.db.prepare('SELECT * FROM api_keys WHERE id = ?').get(record.id);
  const secret = key.slice(21);
  assert.ok(!JSON.stringify(row).includes(secret));
  assert.match(row.key_hash, /^[0-9a-f]{64}$/);
});

test('sending can be disabled until setup, by configuration and by the pause switch', async () => {
  const t = await app({ env: { REQUIRE_SETUP_BEFORE_SENDING: 'true' } });
  const { key } = t.ctx.keys.create({ name: 'svc' });
  const r = await notify(t, key);
  assert.equal(r.status, 503);
  assert.equal(t.push.calls.length, 0);

  const off = await app({ env: { NOTIFICATIONS_ENABLED: 'false' } });
  const { key: k2 } = off.ctx.keys.create({ name: 'svc' });
  assert.equal((await notify(off, k2)).status, 503);

  const paused = await app();
  const { key: k3 } = paused.ctx.keys.create({ name: 'svc' });
  paused.db.prepare("INSERT INTO settings (key, value) VALUES ('sending_paused', 'true')").run();
  assert.equal((await notify(paused, k3)).status, 503);
});

test('unknown API routes and wrong methods are rejected', async () => {
  const t = await app();
  const { key } = t.ctx.keys.create({ name: 'svc' });
  assert.equal((await t.request({ path: '/api/v1/notifications', headers: { Authorization: `Bearer ${key}` } })).status, 405);
  assert.equal((await t.request({ method: 'POST', path: '/api/v1/keys', headers: { Authorization: `Bearer ${key}` }, body: {} })).status, 404);
});

test('secrets and notification contents never appear in logs, audit events or error responses', async () => {
  const t = await app({ env: { TRUSTED_PROXIES: '127.0.0.1/32', TRUSTED_CIDRS: '10.0.0.0/8', ADMIN_CIDRS: '10.0.0.0/8' } });
  const device = addDevice(t);
  const { key } = t.ctx.keys.create({ name: 'svc' });
  const xff = { 'X-Forwarded-For': '10.0.0.7' };
  const responses = [];
  const title = 'Canary-Title-7f3a';
  const message = 'Canary-Message-91c2';
  responses.push(await notify(t, key, { title, message }, xff));
  responses.push(await notify(t, key + 'x', { title, message }, xff));
  responses.push(await notify(t, key, { title, message }, { 'X-Forwarded-For': '192.168.1.1' }));
  responses.push(await notify(t, key, { title, message, bogus: key }, xff));
  t.push.calls.length = 0;

  const haystack = [
    ...t.logs,
    ...responses.map((r) => r.text + JSON.stringify(r.headers)),
    JSON.stringify(t.ctx.audit.list({ limit: 1000 })),
  ].join('\n');
  const secret = key.slice(21);
  const forbidden = [
    secret,
    t.secrets.pepper,
    t.config.vapid.privateKey,
    device.subscription.endpoint,
    new URL(device.subscription.endpoint).pathname.slice(1),
    device.subscription.keys.p256dh,
    device.subscription.keys.auth,
    title,
    message,
  ];
  forbidden.forEach((f, i) => assert.ok(!haystack.includes(f), `leaked #${i} (len ${f.length}): ${JSON.stringify(f.slice(0, 12))}`));
  assert.equal(responses[0].status, 200);
  assert.ok(!('devices' in responses[0].json && JSON.stringify(responses[0].json).includes('endpoint')));
});

test('a key that was already rotated cannot be rotated again (no early expiry of the new key)', async () => {
  const t = await app();
  const { record } = t.ctx.keys.create({ name: 'svc' });
  const first = t.ctx.keys.rotate(record.id, { graceSeconds: 86400 });
  assert.equal(t.ctx.keys.get(record.id).replaced, true);
  assert.equal(t.ctx.keys.rotate(record.id, { graceSeconds: 86400 }), null);
  assert.equal(first.record.expires_at, null, 'replacement keeps the original (no) expiry');
  assert.ok(t.ctx.keys.rotate(first.record.id));
});

test('a successful request does not reset the failure counter for that client', async () => {
  const t = await app({ env: { AUTH_FAILURE_LIMIT: '3' } });
  addDevice(t);
  const { key } = t.ctx.keys.create({ name: 'svc' });
  assert.equal((await notify(t, 'pgk_bad')).status, 401);
  assert.equal((await notify(t, 'pgk_bad')).status, 401);
  assert.equal((await notify(t, key)).status, 200);
  assert.equal((await notify(t, 'pgk_bad')).status, 401);
  assert.equal((await notify(t, key)).status, 429, 'third failure in the window blocks the client');
});
