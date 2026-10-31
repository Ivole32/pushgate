import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { createApp } from '../src/app.js';
import { ConfigError, loadConfig } from '../src/config.js';
import { openDatabase } from '../src/db.js';
import { HttpError } from '../src/http.js';
import { createLogger } from '../src/log.js';
import { PLUGIN_API_VERSION, resolvePlugins } from '../src/plugins.js';
import { ORIGIN, addDevice, adminSession, baseEnv, notify, startApp, tempDir, writeSecrets } from './helpers.js';

const apps = [];
async function app(opts) {
  const t = await startApp(opts);
  apps.push(t);
  return t;
}
after(() => Promise.all(apps.map((t) => t.close())));

const plugin = (extra = {}) => ({ name: 'test', apiVersion: PLUGIN_API_VERSION, ...extra });
const route = (extra = {}) => ({ method: 'GET', path: '/ext', handler: () => ({}), ...extra });
const noop = () => {};

test('invalid plugins are refused with a clear message', () => {
  const cases = [
    [[{ apiVersion: PLUGIN_API_VERSION }], /needs a name/],
    [[plugin({ name: 'Not Valid' })], /needs a name/],
    [[plugin({ apiVersion: PLUGIN_API_VERSION + 1 })], /provides version 1/],
    [[plugin({ servics: {} })], /unknown option "servics"/],
    [[plugin(), plugin()], /is given twice/],
    [[plugin({ services: { database: noop } })], /unknown service "database"/],
    [[plugin({ services: { transport: 'x' } })], /must be a function/],
    [[plugin({ name: 'a', services: { transport: noop } }), plugin({ name: 'b', services: { transport: noop } })], /already replaced by plugin "a"/],
    [[plugin({ hooks: { beforeLogin: noop } })], /unknown hook "beforeLogin"/],
    [[plugin({ routes: [route({ path: '/api/v2/send' })] })], /reserved/],
    [[plugin({ routes: [route({ path: '/admin/api/billing' })] })], /reserved/],
    [[plugin({ routes: [route({ path: '/healthz' })] })], /reserved/],
    [[plugin({ routes: [route({ path: '/x/../admin' })] })], /exact canonical path/],
    [[plugin({ routes: [route({ path: '/x//y' })] })], /exact canonical path/],
    [[plugin({ routes: [route({ path: '/x?y=1' })] })], /exact canonical path/],
    [[plugin({ routes: [route({ path: 'relative' })] })], /exact canonical path/],
    [[plugin({ routes: [route({ method: 'HEAD' })] })], /route method/],
    [[plugin({ routes: [route({ zone: 'internet' })] })], /zone must be/],
    [[plugin({ routes: [route({ auth: 'apikey' })] })], /auth must be/],
    [[plugin({ routes: [route({ crossOrigin: true })] })], /only allowed with auth "none"/],
    [[plugin({ routes: [route({ regex: /x/ })] })], /unknown option "regex"/],
    [[plugin({ name: 'a', routes: [route()] }), plugin({ name: 'b', routes: [route()] })], /already defined by plugin "a"/],
    [[plugin({ name: 'a', features: { x: 1 } }), plugin({ name: 'b', features: { x: 2 } })], /already set by plugin "a"/],
    [[plugin({ migrations: 'CREATE TABLE x (a)' })], /array of SQL strings/],
  ];
  for (const [plugins, message] of cases) {
    assert.throws(() => resolvePlugins(plugins), (err) => err instanceof ConfigError && message.test(err.message), String(message));
  }
  assert.deepEqual(resolvePlugins([]).names, []);
});

test('plugin routes cannot hide web app files or mix zones on one path', () => {
  const dir = tempDir();
  const config = loadConfig(baseEnv(dir, writeSecrets(dir)));
  const db = openDatabase(config.dataDir);
  const log = createLogger({ sink: noop });
  try {
    for (const [routes, message] of [
      [[route({ path: '/index.html' })], /is a web app file/],
      [[route({ path: '/sw.js' })], /is a web app file/],
      [[route({ zone: 'public' }), route({ method: 'POST', zone: 'app' })], /need the same zone/],
    ]) {
      assert.throws(() => createApp({ config, db, log, plugins: [plugin({ routes })] }), message);
    }
  } finally {
    db.close();
  }
});

test('beforeSend hooks can refuse a notification; nothing is sent and content stays hidden', async () => {
  const seen = [];
  const second = [];
  const t = await app({
    plugins: [
      plugin({ name: 'quota', hooks: { beforeSend: (x) => { seen.push(x); throw new HttpError(429, 'quota_exceeded', 'Monthly quota reached'); } } }),
      plugin({ name: 'later', hooks: { beforeSend: (x) => second.push(x) } }),
    ],
  });
  addDevice(t);
  const { key, record } = t.ctx.keys.create({ name: 'svc' });
  const r = await notify(t, key, { title: 'secret title', message: 'secret body', priority: 'low' });
  assert.equal(r.status, 429);
  assert.equal(r.json.error.code, 'quota_exceeded');
  assert.equal(t.push.calls.length, 0);
  assert.equal(second.length, 0, 'later hooks do not run once one refused');
  assert.equal(seen[0].key.id, record.id);
  assert.deepEqual(seen[0].notification, { priority: 'low', ttl: 86400 });
  assert.ok(!JSON.stringify(seen[0]).includes('secret'), 'hooks never see title or message');

  // Requests that fail earlier checks never reach the hooks.
  assert.equal((await notify(t, 'pgk_wrong')).status, 401);
  assert.equal((await notify(t, key, { title: '' })).status, 400);
  assert.equal(seen.length, 1);
});

test('a beforeSend hook that crashes blocks the notification with a 500', async () => {
  const t = await app({ plugins: [plugin({ hooks: { beforeSend: async () => { throw new Error('quota database down'); } } })] });
  addDevice(t);
  const { key } = t.ctx.keys.create({ name: 'svc' });
  const r = await notify(t, key);
  assert.equal(r.status, 500);
  assert.equal(r.json.error.code, 'internal_error');
  assert.equal(t.push.calls.length, 0);
});

test('afterDelivery hooks see the outcome; a failing one is logged and does not change the response', async () => {
  const metered = [];
  const t = await app({
    plugins: [
      plugin({ name: 'meter', hooks: { afterDelivery: ({ key, outcome }) => metered.push([key.id, outcome.devices.delivered]) } }),
      plugin({ name: 'broken', hooks: { afterDelivery: () => { throw new Error('metering down'); } } }),
    ],
  });
  addDevice(t);
  const { key, record } = t.ctx.keys.create({ name: 'svc' });
  const r = await notify(t, key);
  assert.equal(r.status, 200);
  assert.deepEqual(metered, [[record.id, 1]]);
  assert.ok(t.logs.some((l) => l.includes('afterDelivery hook failed') && l.includes('"plugin":"broken"')));
});

test('services can be replaced: rate limiters and the push transport', async () => {
  const limits = [];
  const pushed = [];
  const t = await app({
    plugins: [plugin({
      services: {
        rateLimiter: (perMinute) => {
          limits.push(perMinute);
          return { take: () => (perMinute === 30 ? 0 : 7) };
        },
        transport: async (subscription) => {
          pushed.push(subscription.endpoint);
          return { statusCode: 201 };
        },
      },
    })],
  });
  assert.deepEqual(limits, [30, 120, 30], 'per key, global and anonymous admin limits are built with the plugin');
  addDevice(t);
  const { key } = t.ctx.keys.create({ name: 'svc' });
  const r = await notify(t, key);
  assert.equal(r.status, 429, 'the replaced global limiter refuses');
  assert.equal(r.headers['retry-after'], '7');

  const t2 = await app({ plugins: [plugin({ services: { transport: async (s) => { pushed.push(s.endpoint); return { statusCode: 201 }; } } })] });
  const device = addDevice(t2);
  const { key: key2 } = t2.ctx.keys.create({ name: 'svc' });
  assert.equal((await notify(t2, key2)).status, 200);
  assert.deepEqual(pushed, [device.subscription.endpoint]);
  assert.equal(t2.push.calls.length, 0, 'the built-in transport was not used');
});

test('a plugin can replace the sending API network check, only an explicit true allows', async () => {
  const env = { TRUSTED_PROXIES: '127.0.0.1/32', TRUSTED_CIDRS: '10.0.0.0/8' };
  const t = await app({
    env,
    plugins: [plugin({ services: { apiAccess: (client, { fallback }) => (client.ip === '203.0.113.9' ? true : client.ip === '198.51.100.7' ? 'yes' : fallback(client)) } })],
  });
  const { key } = t.ctx.keys.create({ name: 'svc' });
  const from = (ip) => notify(t, key, undefined, { 'X-Forwarded-For': ip });
  assert.equal((await from('203.0.113.9')).status, 200);
  assert.equal((await from('10.1.2.3')).status, 200, 'the default check is available as fallback');
  assert.equal((await from('198.51.100.7')).status, 403, 'truthy is not enough');
  assert.equal((await from('192.0.2.1')).status, 403);
  assert.ok(t.logs.some((l) => l.includes('sending API network check replaced by a plugin')));
});

test('plugin routes get the same network, origin, session and passkey checks as the admin API', async () => {
  const t = await app({
    env: { TRUSTED_PROXIES: '127.0.0.1/32', ADMIN_CIDRS: '10.0.0.0/8' },
    plugins: [plugin({
      routes: [
        { method: 'POST', path: '/signup', auth: 'none', handler: () => ({ status: 201, body: { ok: true } }) },
        { method: 'GET', path: '/account/usage', handler: ({ session }) => ({ used: 3, session: Boolean(session) }) },
        { method: 'POST', path: '/account/delete', auth: 'fresh', handler: () => ({ ok: true }) },
        { method: 'POST', path: '/billing/webhook', zone: 'public', auth: 'none', crossOrigin: true, handler: ({ res }) => { res.writeHead(204); res.end(); } },
      ],
    })],
  });
  const home = { 'X-Forwarded-For': '10.0.0.5' };
  const internet = { 'X-Forwarded-For': '203.0.113.9' };
  const s = adminSession(t);

  assert.equal((await t.request({ method: 'POST', path: '/signup', headers: { ...home, Origin: ORIGIN }, body: {} })).status, 201);
  assert.equal((await t.request({ method: 'POST', path: '/signup', headers: home, body: {} })).status, 403, 'needs a same-origin request');
  assert.equal((await t.request({ method: 'POST', path: '/signup', headers: { ...internet, Origin: ORIGIN }, body: {} })).status, 403, 'app zone follows ADMIN_CIDRS');
  assert.equal((await t.request({ path: '/signup', headers: home })).status, 405);

  assert.equal((await t.request({ path: '/account/usage', headers: home })).status, 401, 'session is the default');
  const usage = await t.request({ path: '/account/usage', headers: { ...home, ...s.readHeaders } });
  assert.deepEqual(usage.json, { used: 3, session: true });

  const del = (headers) => t.request({ method: 'POST', path: '/account/delete', headers: { ...home, ...headers }, body: {} });
  assert.equal((await del({ ...s.headers, 'X-CSRF-Token': 'wrong' })).status, 403, 'CSRF token required');
  assert.equal((await del(s.headers)).status, 200);
  t.db.prepare('UPDATE sessions SET verified_at = 0').run();
  const stale = await del(s.headers);
  assert.equal(stale.status, 403);
  assert.equal(stale.json.error.code, 'reauth_required');

  const hook = await t.request({ method: 'POST', path: '/billing/webhook', headers: internet, body: {} });
  assert.equal(hook.status, 204, 'public cross-origin route reachable from any network without Origin');
  assert.equal((await t.request({ method: 'POST', path: '/billing/webhook', headers: { 'X-Forwarded-For': '203.0.113.9, 10.0.0.1' }, body: {} })).status, 403, 'proxy rules still apply');
});

test('feature flags reach the web app through the session endpoint', async () => {
  const t = await app({ plugins: [plugin({ features: { billing: true, plans: ['free', 'pro'] } })] });
  const r = await t.request({ path: '/admin/api/session' });
  assert.deepEqual(r.json.features, { billing: true, plans: ['free', 'pro'] });
});

test('plugin migrations run once, in order, and new steps are applied on the next start', async () => {
  const first = ['CREATE TABLE test_usage (account TEXT PRIMARY KEY, sent INTEGER NOT NULL DEFAULT 0)'];
  const t1 = await startApp({ plugins: [plugin({ migrations: first })] });
  t1.db.prepare("INSERT INTO test_usage (account, sent) VALUES ('a', 5)").run();
  await t1.close();

  const t2 = await app({ dir: t1.dir, secrets: t1.secrets, plugins: [plugin({ migrations: [...first, 'ALTER TABLE test_usage ADD COLUMN plan TEXT'] })] });
  assert.deepEqual({ ...t2.db.prepare('SELECT account, sent, plan FROM test_usage').get() }, { account: 'a', sent: 5, plan: null });
  assert.deepEqual(t2.db.prepare('SELECT plugin, version FROM plugin_migrations ORDER BY version').all().map((r) => ({ ...r })),
    [{ plugin: 'test', version: 1 }, { plugin: 'test', version: 2 }]);
});
