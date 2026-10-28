// Regression tests for the findings of the October 2026 security audit.
import assert from 'node:assert/strict';
import path from 'node:path';
import { after, test } from 'node:test';
import { createAudit } from '../src/audit.js';
import { openDatabase } from '../src/db.js';
import { createLogger } from '../src/log.js';
import { createFailureLimiter } from '../src/ratelimit.js';
import { ORIGIN, addDevice, fakeSubscription, notify, startApp, tempDir } from './helpers.js';
import { createSoftAuthenticator } from './softauthn.js';

const apps = [];
async function app(opts) {
  const t = await startApp(opts);
  apps.push(t);
  return t;
}
after(() => Promise.all(apps.map((t) => t.close())));

const soft = (opts) => createSoftAuthenticator({ origin: ORIGIN, rpId: 'pushgate.test', ...opts });
const post = (t, p, body, headers = {}) => t.request({ method: 'POST', path: p, body, headers: { Origin: ORIGIN, ...headers } });

// Enrolls a passkey through the real ceremony; returns headers for the new session.
async function enroll(t, authn, name = 'phone') {
  const { token } = t.ctx.auth.createEnrollmentToken();
  const opts = await post(t, '/admin/api/enroll/options', { token });
  const r = await post(t, '/admin/api/enroll/verify', { token, name, challenge_id: opts.json.challenge_id, response: authn.register(opts.json.options) });
  assert.equal(r.status, 200);
  return { Cookie: r.headers['set-cookie'][0].split(';')[0], 'X-CSRF-Token': r.json.csrf_token, Origin: ORIGIN };
}

async function addPasskey(t, headers, authn, registerOpts) {
  const o = await post(t, '/admin/api/passkeys/options', {}, headers);
  assert.equal(o.status, 200);
  return post(t, '/admin/api/passkeys/verify', { name: 'second', challenge_id: o.json.challenge_id, response: authn.register(o.json.options, registerOpts) }, headers);
}

const alertTitles = (t) => t.push.calls.map((c) => JSON.parse(c.payload)).filter((p) => p.service === 'pushgate' && p.title !== 'Pushgate test').map((p) => p.title);

test('sensitive changes need a recent passkey confirmation, not just a session cookie', async () => {
  const t = await app();
  const authn = soft();
  const h = await enroll(t, authn);
  // A session that has not confirmed presence recently (e.g. a stolen cookie).
  t.db.prepare('UPDATE sessions SET verified_at = ?').run(Date.now() - 6 * 60000);
  for (const [method, p, body] of [
    ['POST', '/admin/api/keys', { name: 'x' }],
    ['POST', '/admin/api/keys/0123456789abcdef/rotate', {}],
    ['POST', '/admin/api/devices', { name: 'x', subscription: fakeSubscription().subscription }],
    ['POST', '/admin/api/passkeys/options', {}],
    ['POST', '/admin/api/passkeys/verify', { name: 'x', challenge_id: `${'A'.repeat(20)}.${'A'.repeat(43)}`, response: {} }],
    ['DELETE', `/admin/api/passkeys/${authn.id}`],
  ]) {
    const r = await t.request({ method, path: p, body, headers: h });
    assert.equal(r.status, 403, `${method} ${p}`);
    assert.equal(r.json.error.code, 'reauth_required');
  }
  assert.equal(t.ctx.keys.list().length, 0);
  // Reading and protective actions do not need it.
  assert.equal((await t.request({ path: '/admin/api/keys', headers: h })).status, 200);
  assert.equal((await t.request({ method: 'PUT', path: '/admin/api/settings', headers: h, body: { sending_paused: false } })).status, 200);

  // A login challenge cannot be used to re-confirm (kinds are bound).
  const lo = await post(t, '/admin/api/login/options', {});
  assert.equal((await post(t, '/admin/api/reauth/verify', { challenge_id: lo.json.challenge_id, response: authn.login(lo.json.options) }, h)).status, 400);
  // An unknown authenticator cannot re-confirm.
  const ro1 = await post(t, '/admin/api/reauth/options', {}, h);
  assert.equal((await post(t, '/admin/api/reauth/verify', { challenge_id: ro1.json.challenge_id, response: soft().login(ro1.json.options) }, h)).status, 400);

  const ro = await post(t, '/admin/api/reauth/options', {}, h);
  const rv = await post(t, '/admin/api/reauth/verify', { challenge_id: ro.json.challenge_id, response: authn.login(ro.json.options) }, h);
  assert.equal(rv.status, 200);
  assert.equal((await t.request({ method: 'POST', path: '/admin/api/keys', headers: h, body: { name: 'x' } })).status, 201);
  assert.ok(t.ctx.audit.list().some((e) => e.type === 'admin.reverified'));
});

test('security-relevant changes are pushed to every device, including the one being removed', async () => {
  const t = await app();
  const phone = addDevice(t, { name: 'phone', minPriority: 'high' });
  const h = await enroll(t, soft());
  assert.equal((await addPasskey(t, h, soft())).status, 201);
  assert.equal((await t.request({ method: 'POST', path: '/admin/api/keys', headers: h, body: { name: 'svc' } })).status, 201);
  assert.equal((await t.request({ method: 'PUT', path: '/admin/api/settings', headers: h, body: { sending_paused: true } })).status, 200);
  const before = t.push.calls.length;
  assert.equal((await t.request({ method: 'DELETE', path: `/admin/api/devices/${phone.id}`, headers: h })).status, 200);
  assert.deepEqual(alertTitles(t), ['Passkey enrolled', 'Passkey added', 'API key created', 'Sending paused', 'Device removed']);
  const last = t.push.calls[before];
  assert.equal(last.subscription.endpoint, phone.subscription.endpoint, 'the removed device is told');
  assert.equal(last.options.urgency, 'high', 'passes every minimum-priority filter');
});

test('a recovery enrollment signs out every existing session', async () => {
  const t = await app();
  const first = await enroll(t, soft());
  assert.equal((await t.request({ path: '/admin/api/keys', headers: first })).status, 200);
  const second = await enroll(t, soft(), 'recovery');
  assert.equal((await t.request({ path: '/admin/api/keys', headers: first })).status, 401);
  assert.equal((await t.request({ path: '/admin/api/keys', headers: second })).status, 200);
});

test('passkeys with unaddressable ids or invalid transports cannot be planted', async () => {
  const t = await app();
  const h = await enroll(t, soft());
  // An 800-character id could never be removed through the API.
  const long = await addPasskey(t, h, soft({ idLength: 600 }));
  assert.equal(long.status, 400);
  assert.equal(t.ctx.auth.listPasskeys().length, 1);

  // Junk transports would make navigator.credentials.create() throw in every browser later.
  const junk = soft();
  assert.equal((await addPasskey(t, h, junk, { transports: ['internal', 'x', 7, { a: 1 }, 'usb', 'usb'] })).status, 201);
  assert.equal(t.db.prepare('SELECT transports FROM passkeys WHERE id = ?').get(junk.id).transports, '["internal","usb"]');

  // Rows stored by older versions are cleaned when echoed to the browser.
  t.db.prepare('UPDATE passkeys SET transports = ?').run('"x"');
  const o = await post(t, '/admin/api/passkeys/options', {}, h);
  assert.equal(o.status, 200);
  for (const c of o.json.options.excludeCredentials) assert.deepEqual(c.transports, []);
});

test('the CLI can remove any passkey, the web app never the last one', async () => {
  const t = await app();
  const authn = soft();
  await enroll(t, authn);
  assert.equal(t.ctx.auth.removePasskey(authn.id), 'last');
  assert.equal(t.ctx.auth.removePasskey(authn.id, { allowLast: true }), 'ok');
  assert.equal(t.ctx.auth.hasAdmin(), false);
});

test('a tag only replaces notifications of the same service, and is not sent in clear', async () => {
  const t = await app();
  addDevice(t);
  const a = t.ctx.keys.create({ name: 'alertmanager' });
  const b = t.ctx.keys.create({ name: 'printer' });
  const topicOf = async (key, tag) => {
    assert.equal((await notify(t, key, { title: 'x', message: 'y', tag })).status, 200);
    return t.push.calls.at(-1).options.topic;
  };
  const real = await topicOf(a.key, 'db-down');
  const spoof = await topicOf(b.key, 'db-down');
  assert.notEqual(real, spoof, 'another service cannot replace or cancel this alert');
  assert.ok(!real.includes('db-down'));
  assert.notEqual(await topicOf(a.key, 'disk'), real);
  // The service keeps its tags across key rotations.
  const rotated = t.ctx.keys.rotate(a.record.id);
  assert.equal(await topicOf(rotated.key, 'db-down'), real);
  assert.equal(await topicOf(t.ctx.keys.rotate(rotated.record.id).key, 'db-down'), real);
});

test('rotating client addresses cannot grow the security event table without bound', async () => {
  const t = await app({ env: { ADMIN_PUBLIC: 'true', ADMIN_CIDRS: '', TRUSTED_PROXIES: '127.0.0.1/32', TRUSTED_CIDRS: '10.0.0.0/8' } });
  const count = () => t.db.prepare('SELECT COUNT(*) AS n FROM audit_events').get().n;
  const hit = (xff) => t.request({ path: '/api/x', headers: { 'X-Forwarded-For': xff } });
  const start = count();
  // Many addresses of one /64 count as one client.
  for (let i = 0; i < 300; i++) assert.equal((await hit(`2001:db8:1:2::${i.toString(16)}`)).status, 403);
  assert.equal(count() - start, 1);
  // Many /64s and IPv4 addresses are bounded by the global budget (60 rows per minute).
  for (let i = 0; i < 200; i++) await hit(`2001:db8:${(i + 16).toString(16)}::1`);
  for (let i = 0; i < 200; i++) await hit(`198.51.100.${i}`);
  assert.ok(count() - start <= 70, `rows written: ${count() - start}`);
});

test('suppressed security events are summarised once the flood subsides', () => {
  const db = openDatabase(path.join(tempDir(), 'data'));
  let now = 1e12;
  const audit = createAudit(db, createLogger({ sink: () => {} }), { now: () => now });
  for (let i = 0; i < 200; i++) audit.recordThrottled('network.rejected', { ip: `203.0.113.${i}` });
  assert.equal(audit.list().length, 60);
  now += 60000;
  audit.recordThrottled('network.rejected', { ip: '192.0.2.1' });
  const [latest, summary] = audit.list();
  assert.equal(latest.ip, '192.0.2.1');
  assert.deepEqual([summary.type, summary.detail], ['audit.suppressed', { count: 140 }]);
  db.close();
});

test('non-canonical request paths are refused before routing', async () => {
  const t = await app({ env: { RATE_LIMIT_ADMIN_ANONYMOUS_PER_MINUTE: '1000' } });
  for (const p of ['/admin\\api\\session', '/api\\v1\\notifications', '/x/%2e%2e/admin/api/session', '/admin/api/./session',
    '/admin//api/session/..', 'http://localhost/admin/api/session']) {
    assert.equal((await t.request({ path: p })).status, 400, p);
  }
  assert.equal((await t.request({ path: '/admin/api/session?x=1' })).status, 200);
  assert.equal((await t.request({ path: '/healthz' })).status, 200);
});

test('the failure counter stays bounded even when every entry is an active block', () => {
  const now = 1e12;
  const limiter = createFailureLimiter({ limit: 1, windowMs: 1e9, blockMs: 1e9, now: () => now });
  for (let i = 0; i < 25000; i++) limiter.fail(`c${i}`);
  assert.equal(limiter.blockedFor('c0'), 0, 'the oldest blocks give way past twice the normal size');
  assert.ok(limiter.blockedFor('c24999') > 0);
});
