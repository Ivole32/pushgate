import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { after, test } from 'node:test';
import { DEFAULT_ACCOUNT, checkAccountId } from '../src/accounts.js';
import { MIGRATIONS, openDatabase } from '../src/db.js';
import { ORIGIN, addDevice, adminSession, fakeSubscription, notify, startApp, tempDir } from './helpers.js';
import { createSoftAuthenticator } from './softauthn.js';

const apps = [];
async function app(opts) {
  const t = await startApp(opts);
  apps.push(t);
  return t;
}
after(() => Promise.all(apps.map((t) => t.close())));

const soft = () => createSoftAuthenticator({ origin: ORIGIN, rpId: 'pushgate.test' });
const post = (t, p, body, headers = {}) => t.request({ method: 'POST', path: p, body, headers: { Origin: ORIGIN, ...headers } });

async function enroll(t, accountId, authn, name = 'phone') {
  const { token } = t.ctx.auth.createEnrollmentToken(accountId);
  const opts = await post(t, '/admin/api/enroll/options', { token });
  const r = await post(t, '/admin/api/enroll/verify', { token, name, challenge_id: opts.json.challenge_id, response: authn.register(opts.json.options) });
  assert.equal(r.status, 200);
  return { Cookie: r.headers['set-cookie'][0].split(';')[0], 'X-CSRF-Token': r.json.csrf_token, Origin: ORIGIN };
}

// Two accounts with a key, a device and an admin session each.
async function twoAccounts(opts = {}) {
  const t = await app({ multiAccount: true, ...opts });
  const b = t.ctx.accounts.create({ name: 'bob' }).id;
  const side = (accountId) => ({
    id: accountId,
    key: t.ctx.keys.create(accountId, { name: `svc-${accountId}` }),
    device: addDevice(t, { name: `phone-${accountId}`, accountId }),
    session: adminSession(t, accountId),
  });
  return { t, a: side(DEFAULT_ACCOUNT), b: side(b) };
}

test('existing data moves into the default account when upgrading', () => {
  const dir = tempDir();
  const dataDir = path.join(dir, 'data');
  fs.mkdirSync(dataDir);
  const old = new DatabaseSync(path.join(dataDir, 'pushgate.db'));
  old.exec('CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)');
  for (const [i, sql] of MIGRATIONS.slice(0, 2).entries()) {
    old.exec(sql);
    old.prepare('INSERT INTO schema_migrations VALUES (?, ?)').run(i + 1, 0);
  }
  old.exec(`
    INSERT INTO settings VALUES ('sending_paused', 'true'), ('webauthn_user_id', 'handle123');
    INSERT INTO api_keys (id, name, key_hash, scopes, created_at) VALUES ('0123456789abcdef', 'svc', 'x', '[]', 1);
    INSERT INTO passkeys (id, public_key, name, created_at) VALUES ('pk1', x'00', 'phone', 1);
    INSERT INTO devices (id, name, endpoint, p256dh, auth, created_at) VALUES ('d1', 'phone', 'https://web.push.apple.com/x', 'p', 'a', 1);
    INSERT INTO audit_events (ts, type, actor) VALUES (1, 'network.rejected', 'anonymous');
  `);
  old.close();

  const db = openDatabase(dataDir);
  try {
    assert.deepEqual({ ...db.prepare('SELECT id, webauthn_user_id, sending_paused FROM accounts').get() },
      { id: 'default', webauthn_user_id: 'handle123', sending_paused: 1 });
    for (const table of ['api_keys', 'passkeys', 'devices', 'audit_events']) {
      assert.equal(db.prepare(`SELECT account_id FROM ${table}`).get().account_id, 'default', table);
    }
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM settings').get().n, 0, 'moved settings are removed');
  } finally {
    db.close();
  }
});

test('data functions refuse to run without a valid account', async () => {
  const t = await app();
  for (const bad of [undefined, null, '', 'acc_x', 'DEFAULT', "default' OR 1=1"]) {
    assert.throws(() => checkAccountId(bad), TypeError);
    assert.throws(() => t.ctx.keys.list(bad), TypeError);
    assert.throws(() => t.ctx.devices.list(bad), TypeError);
    assert.throws(() => t.ctx.auth.listPasskeys(bad), TypeError);
  }
  assert.throws(() => t.ctx.keys.create({ name: 'x' }), TypeError, 'the old signature cannot silently pick an account');
  await assert.rejects(() => t.ctx.pusher.deliver({ title: 'x', message: 'y', service: 's' }), TypeError);
  assert.throws(() => t.ctx.auth.createEnrollmentToken('acc_0000000000000000'), /unknown account/);
});

test('an administrator never sees or changes another account\'s keys, devices, passkeys or events', async () => {
  const { t, a, b } = await twoAccounts();
  const as = (s) => (method, p, body) => t.request({ method, path: p, body, headers: method === 'GET' ? s.readHeaders : s.headers });
  const bob = as(b.session);

  assert.deepEqual((await bob('GET', '/admin/api/keys')).json.keys.map((k) => k.id), [b.key.record.id]);
  assert.deepEqual((await bob('GET', '/admin/api/devices')).json.devices.map((d) => d.id), [b.device.id]);
  assert.deepEqual((await bob('GET', '/admin/api/passkeys')).json.passkeys.map((p) => p.id), [b.session.passkeyId]);

  const foreign = [
    ['POST', `/admin/api/keys/${a.key.record.id}/revoke`, {}],
    ['POST', `/admin/api/keys/${a.key.record.id}/rotate`, {}],
    ['PATCH', `/admin/api/devices/${a.device.id}`, { min_priority: 'high' }],
    ['DELETE', `/admin/api/devices/${a.device.id}`],
    ['POST', '/admin/api/test-push', { device_id: a.device.id }],
    ['DELETE', `/admin/api/passkeys/${a.session.passkeyId}`],
  ];
  for (const [method, p, body] of foreign) {
    const r = await bob(method, p, body);
    assert.equal(r.status, 404, `${method} ${p}`);
  }
  assert.equal(t.ctx.keys.get(DEFAULT_ACCOUNT, a.key.record.id).status, 'active');
  assert.equal(t.ctx.devices.get(DEFAULT_ACCOUNT, a.device.id).min_priority, 'low');
  assert.equal(t.ctx.auth.listPasskeys(DEFAULT_ACCOUNT).length, 1);

  // Bob's own changes stay in Bob's account, including pausing.
  assert.equal((await bob('PUT', '/admin/api/settings', { sending_paused: true })).status, 200);
  const overview = (await bob('GET', '/admin/api/overview')).json;
  assert.equal(overview.sending_paused, true);
  assert.equal(overview.active_keys, 1);
  assert.equal(overview.devices, 1);
  assert.equal(t.ctx.accounts.isPaused(DEFAULT_ACCOUNT), false);
  const events = (await bob('GET', '/admin/api/events')).json.events;
  assert.ok(events.length > 0 && events.every((e) => ['settings.changed'].includes(e.type)), JSON.stringify(events.map((e) => e.type)));
});

test('a key sends only to its own account\'s devices and obeys its own pause switch', async () => {
  const { t, a, b } = await twoAccounts();
  const r = await notify(t, b.key.key);
  assert.equal(r.status, 200);
  assert.deepEqual(t.push.calls.map((c) => c.subscription.endpoint), [b.device.subscription.endpoint]);
  const alerts = t.push.calls.length;

  t.ctx.accounts.setPaused(b.id, true);
  assert.equal((await notify(t, b.key.key)).status, 503);
  assert.equal((await notify(t, a.key.key)).status, 200, 'other accounts keep sending');
  assert.equal(t.push.calls.at(-1).subscription.endpoint, a.device.subscription.endpoint);
  assert.equal(t.push.calls.length, alerts + 1);

  const rows = t.db.prepare('SELECT account_id FROM deliveries ORDER BY created_at').all().map((x) => x.account_id);
  assert.deepEqual(rows, [b.id, DEFAULT_ACCOUNT]);
});

test('security alerts go only to the devices of the account that changed', async () => {
  const { t, a, b } = await twoAccounts();
  const r = await t.request({ method: 'POST', path: `/admin/api/keys/${b.key.record.id}/revoke`, body: {}, headers: b.session.headers });
  assert.equal(r.status, 200);
  await new Promise((resolve) => setImmediate(resolve));
  const endpoints = t.push.calls.map((c) => c.subscription.endpoint);
  assert.ok(endpoints.includes(b.device.subscription.endpoint));
  assert.ok(!endpoints.includes(a.device.subscription.endpoint));
  const alert = JSON.parse(t.push.calls[0].payload);
  assert.ok(!alert.body.includes('cli.js'), 'hosted administrators are not told to use the server CLI');
});

test('enrollment tokens enroll into their own account; recovery signs out only that account', async () => {
  const t = await app({ multiAccount: true });
  const bob = t.ctx.accounts.create({ name: 'bob' }).id;
  const alice = await enroll(t, DEFAULT_ACCOUNT, soft());
  const bobAuthn = soft();
  const bobSession = await enroll(t, bob, bobAuthn);
  assert.equal(t.ctx.auth.listPasskeys(bob)[0].id, bobAuthn.id);
  assert.equal(t.ctx.auth.listPasskeys(DEFAULT_ACCOUNT).length, 1);

  const s = await t.request({ path: '/admin/api/session', headers: { Cookie: bobSession.Cookie } });
  assert.deepEqual(s.json.account, { id: bob, name: 'bob' });
  assert.equal(s.json.accounts, 'multiple');

  // Recovery for Bob: Bob's old session ends, Alice's stays.
  await enroll(t, bob, soft(), 'recovery');
  assert.equal((await t.request({ path: '/admin/api/keys', headers: { Cookie: bobSession.Cookie } })).status, 401);
  assert.equal((await t.request({ path: '/admin/api/keys', headers: { Cookie: alice.Cookie } })).status, 200);
});

test('registration options for one account cannot complete in another', async () => {
  const t = await app({ multiAccount: true });
  const bob = t.ctx.accounts.create({ name: 'bob' }).id;
  const tokenA = t.ctx.auth.createEnrollmentToken(DEFAULT_ACCOUNT).token;
  const tokenB = t.ctx.auth.createEnrollmentToken(bob).token;
  const optsA = await post(t, '/admin/api/enroll/options', { token: tokenA });
  const authn = soft();
  const r = await post(t, '/admin/api/enroll/verify', { token: tokenB, name: 'x', challenge_id: optsA.json.challenge_id, response: authn.register(optsA.json.options) });
  assert.equal(r.status, 400);
  assert.equal(r.json.error.code, 'challenge_expired');
  assert.equal(t.ctx.auth.listPasskeys(bob).length, 0);
  assert.ok(t.ctx.auth.enrollmentTokenAccount(tokenB), 'the token is not spent');
});

test('a passkey of another account cannot confirm sensitive changes', async () => {
  const t = await app({ multiAccount: true });
  const bob = t.ctx.accounts.create({ name: 'bob' }).id;
  const alice = await enroll(t, DEFAULT_ACCOUNT, soft());
  const bobAuthn = soft();
  await enroll(t, bob, bobAuthn);
  t.db.prepare('UPDATE sessions SET verified_at = 0').run();
  const o = await post(t, '/admin/api/reauth/options', {}, alice);
  const r = await post(t, '/admin/api/reauth/verify', { challenge_id: o.json.challenge_id, response: bobAuthn.login(o.json.options) }, alice);
  assert.equal(r.status, 400);
  assert.equal((await t.request({ method: 'POST', path: '/admin/api/keys', body: { name: 'x' }, headers: alice })).json.error.code, 'reauth_required');
});

test('signing in picks the account from the passkey', async () => {
  const t = await app({ multiAccount: true });
  const bob = t.ctx.accounts.create({ name: 'bob' }).id;
  const bobAuthn = soft();
  await enroll(t, bob, bobAuthn);
  const o = await post(t, '/admin/api/login/options', {});
  const r = await post(t, '/admin/api/login/verify', { challenge_id: o.json.challenge_id, response: bobAuthn.login(o.json.options) });
  assert.equal(r.status, 200);
  const s = await t.request({ path: '/admin/api/session', headers: { Cookie: r.headers['set-cookie'][0].split(';')[0] } });
  assert.equal(s.json.account.id, bob);
  assert.ok(t.ctx.audit.list(bob).some((e) => e.type === 'admin.login'));
  assert.ok(!t.ctx.audit.list(DEFAULT_ACCOUNT).some((e) => e.type === 'admin.login'));
});

test('a browser subscription in one account cannot be taken over by another', async () => {
  const { t, a, b } = await twoAccounts();
  const r = await t.request({
    method: 'POST', path: '/admin/api/devices', headers: b.session.headers,
    body: { name: 'stolen', subscription: a.device.subscription },
  });
  assert.equal(r.status, 409);
  assert.equal(r.json.error.code, 'device_in_other_account');
  assert.equal(t.ctx.devices.list(b.id).length, 1);
  assert.equal(t.ctx.devices.get(DEFAULT_ACCOUNT, a.device.id).name, `phone-${DEFAULT_ACCOUNT}`);
  // A fresh subscription is fine.
  const ok = await t.request({ method: 'POST', path: '/admin/api/devices', headers: b.session.headers, body: { name: 'new', subscription: fakeSubscription().subscription } });
  assert.equal(ok.status, 201);
});

test('server-wide events are shown only with a single account', async () => {
  for (const multiAccount of [false, true]) {
    const t = await app({ multiAccount, env: { TRUSTED_PROXIES: '127.0.0.1/32', TRUSTED_CIDRS: '10.0.0.0/8', ADMIN_CIDRS: '10.0.0.0/8' } });
    const s = adminSession(t);
    assert.equal((await t.request({ method: 'POST', path: '/api/v1/notifications', headers: { 'X-Forwarded-For': '192.0.2.1' }, body: {} })).status, 403);
    const events = (await t.request({ path: '/admin/api/events', headers: { ...s.readHeaders, 'X-Forwarded-For': '10.0.0.1' } })).json.events;
    assert.equal(events.some((e) => e.type === 'network.rejected'), !multiAccount, `multiAccount=${multiAccount}`);
  }
});

test('the session endpoint tells the web app which mode it runs in', async () => {
  const single = await app();
  assert.equal((await single.request({ path: '/admin/api/session' })).json.setup_complete, false);
  const multi = await app({ multiAccount: true });
  const s = (await multi.request({ path: '/admin/api/session' })).json;
  assert.equal(s.accounts, 'multiple');
  assert.equal(s.setup_complete, true, 'sign-in is always offered');
});

test('removing an account deletes all its data; the default account stays', async () => {
  const { t, a, b } = await twoAccounts();
  assert.equal(t.ctx.accounts.remove(DEFAULT_ACCOUNT), 'default');
  assert.equal(t.ctx.accounts.remove(b.id), 'ok');
  assert.equal(t.ctx.accounts.remove(b.id), 'missing');
  for (const table of ['api_keys', 'passkeys', 'devices', 'enrollment_tokens', 'deliveries', 'audit_events']) {
    assert.equal(t.db.prepare(`SELECT COUNT(*) AS n FROM ${table} WHERE account_id = ?`).get(b.id).n, 0, table);
  }
  assert.equal(t.db.prepare('SELECT COUNT(*) AS n FROM sessions').get().n, 1, 'only the other account\'s session remains');
  assert.equal((await t.request({ path: '/admin/api/keys', headers: b.session.readHeaders })).status, 401);
  assert.equal((await notify(t, b.key.key)).status, 401);
  assert.equal((await notify(t, a.key.key)).status, 200);
});

test('enrollment token lifetimes are bounded', async () => {
  const t = await app();
  const { expiresAt } = t.ctx.auth.createEnrollmentToken(DEFAULT_ACCOUNT, { ttlMs: 24 * 3600 * 1000 });
  assert.ok(expiresAt > Date.now() + 23 * 3600 * 1000);
  for (const ttlMs of [0, 1000, 25 * 3600 * 1000, 1.5, '60000']) {
    assert.throws(() => t.ctx.auth.createEnrollmentToken(DEFAULT_ACCOUNT, { ttlMs }), /lifetime/);
  }
});
