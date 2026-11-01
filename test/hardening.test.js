// Regression tests for the findings of the independent security review: push endpoint checks
// and the bounded transport, removed accounts, per-account limits, sign-in blocks, recovery,
// plugin contract checks and request host checks.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { after, test } from 'node:test';
import { DEFAULT_ACCOUNT, UnknownAccountError } from '../src/accounts.js';
import { checkEndpoint } from '../src/devices.js';
import { PLUGIN_API_VERSION, resolvePlugins } from '../src/plugins.js';
import { createTransport } from '../src/push.js';
import { createRateLimiter } from '../src/ratelimit.js';
import { loadStatic } from '../src/static.js';
import { ORIGIN, addDevice, adminSession, baseEnv, fakeSubscription, notify, startApp, tempDir, writeSecrets } from './helpers.js';
import { createSoftAuthenticator } from './softauthn.js';

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const apps = [];
async function app(opts) {
  const t = await startApp(opts);
  apps.push(t);
  return t;
}
after(() => Promise.all(apps.map((t) => t.close())));

const soft = () => createSoftAuthenticator({ origin: ORIGIN, rpId: 'pushgate.test' });
const post = (t, p, body, headers = {}) => t.request({ method: 'POST', path: p, body, headers: { Origin: ORIGIN, ...headers } });
const plugin = (extra = {}) => ({ name: 'test', apiVersion: PLUGIN_API_VERSION, ...extra });

async function enroll(t, accountId, authn, { token } = {}) {
  const tok = token ?? t.ctx.auth.createEnrollmentToken(accountId).token;
  const opts = await post(t, '/admin/api/enroll/options', { token: tok });
  if (opts.status !== 200) return opts;
  const r = await post(t, '/admin/api/enroll/verify', { token: tok, name: 'phone', challenge_id: opts.json.challenge_id, response: authn.register(opts.json.options) });
  return r.status === 200 ? { Cookie: r.headers['set-cookie'][0].split(';')[0], 'X-CSRF-Token': r.json.csrf_token, Origin: ORIGIN } : r;
}

async function login(t, authn) {
  const opts = await post(t, '/admin/api/login/options', {});
  return post(t, '/admin/api/login/verify', { challenge_id: opts.json.challenge_id, response: authn.login(opts.json.options) });
}

// ---- push endpoints and transport ----------------------------------------------------------

test('push endpoints must be plain DNS names of a push service, with one spelling', () => {
  const hosts = ['push.apple.com', 'fcm.googleapis.com', 'notify.windows.com'];
  for (const ok of ['https://web.push.apple.com/abc', 'https://fcm.googleapis.com/fcm/send/x:y-z', 'https://db5p.notify.windows.com/w/?token=AbC%2b']) {
    assert.ok(checkEndpoint(ok, hosts), ok);
  }
  for (const bad of [
    // Hosts that Node's legacy URL parser splits differently (connects to the part before ";").
    'https://127.0.0.2;.push.apple.com/x', 'https://evil.example{.push.apple.com/x', "https://a'.push.apple.com/x",
    'https://a".push.apple.com/x', 'https://a`.push.apple.com/x', 'https://a}.push.apple.com/x',
    // One subscription under several spellings.
    'https://web.push.apple.com/abc#1', 'https://web.push.apple.com/abc#', 'https://web.push.apple.com/abc?',
  ]) {
    assert.throws(() => checkEndpoint(bad, hosts), Error, bad);
  }
});

test('a stored endpoint that is no longer allowed is not contacted', async () => {
  const t = await app();
  const device = addDevice(t);
  t.db.prepare('UPDATE devices SET endpoint = ? WHERE id = ?').run('https://127.0.0.2;.push.apple.com/x', device.id);
  const { key } = t.ctx.keys.create(DEFAULT_ACCOUNT, { name: 'svc' });
  const r = await notify(t, key);
  assert.equal(r.status, 502);
  assert.equal(r.json.devices.failed, 1);
  assert.equal(t.push.calls.length, 0);
});

// A fake push service on plain HTTP; the transport's request function is pointed at it.
async function pushService(handler) {
  const server = http.createServer(handler);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  const seen = [];
  const request = (opts, cb) => {
    seen.push(opts);
    return http.request({ ...opts, host: '127.0.0.1', hostname: '127.0.0.1', port }, cb);
  };
  return { request, seen, close: () => new Promise((r) => { server.closeAllConnections(); server.close(r); }) };
}

test('the built-in transport bounds the response size and the whole attempt', async () => {
  const { subscription } = fakeSubscription('web.push.apple.com');
  const options = { vapidDetails: { subject: 'mailto:a@example.invalid', ...(await import('web-push')).default.generateVAPIDKeys() }, TTL: 60, urgency: 'normal' };

  const ok = await pushService((req, res) => req.resume().on('end', () => { res.writeHead(201); res.end('created'); }));
  try {
    const r = await createTransport({ request: ok.request })(subscription, 'hi', { ...options, timeout: 2000 });
    assert.equal(r.statusCode, 201);
    assert.equal(ok.seen[0].hostname, 'web.push.apple.com', 'connects to the checked host');
    assert.equal(ok.seen[0].port, 443);
  } finally {
    await ok.close();
  }

  const gone = await pushService((req, res) => req.resume().on('end', () => { res.writeHead(410); res.end('gone'); }));
  try {
    await assert.rejects(createTransport({ request: gone.request })(subscription, 'hi', { ...options, timeout: 2000 }), (err) => err.statusCode === 410 && err.body === 'gone');
  } finally {
    await gone.close();
  }

  const huge = await pushService((req, res) => req.resume().on('end', () => {
    res.writeHead(201);
    const chunk = Buffer.alloc(16384, 'x');
    const write = () => { while (res.write(chunk)); };
    res.on('drain', write);
    write();
  }));
  try {
    await assert.rejects(createTransport({ request: huge.request, maxResponseBytes: 65536 })(subscription, 'hi', { ...options, timeout: 5000 }), /too large/);
  } finally {
    await huge.close();
  }

  // A response that trickles in forever: idle timeouts never fire, the deadline does.
  const slow = await pushService((req, res) => req.resume().on('end', () => {
    res.writeHead(201);
    const timer = setInterval(() => res.write('x'), 50);
    res.on('close', () => clearInterval(timer));
  }));
  try {
    const started = Date.now();
    await assert.rejects(createTransport({ request: slow.request })(subscription, 'hi', { ...options, timeout: 400 }), /timed out/);
    assert.ok(Date.now() - started < 3000);
  } finally {
    await slow.close();
  }
});

// ---- removed accounts ----------------------------------------------------------------------

test('a request still uploading when its account is removed cannot recreate data for it', async () => {
  const t = await app({ multiAccount: true });
  const bob = t.ctx.accounts.create({ name: 'bob' }).id;
  const s = adminSession(t, bob);
  const body = JSON.stringify({ name: 'late key' });
  const res = await new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1', port: t.port, method: 'POST', path: '/admin/api/keys',
      headers: { ...s.headers, Host: 'pushgate.test', 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
    }, (r) => {
      r.resume();
      r.on('end', () => resolve(r.statusCode));
    });
    req.on('error', reject);
    req.write(body.slice(0, 5));
    setTimeout(() => {
      assert.equal(t.ctx.accounts.remove(bob), 'ok');
      req.end(body.slice(5));
    }, 100);
  });
  assert.equal(res, 401);
  assert.equal(t.db.prepare('SELECT COUNT(*) AS n FROM api_keys WHERE account_id = ?').get(bob).n, 0);
  assert.throws(() => t.ctx.keys.create(bob, { name: 'x' }), UnknownAccountError);
  assert.throws(() => addDevice(t, { accountId: bob }), UnknownAccountError);
});

test('passkeys and sessions of a missing account cannot sign in', async () => {
  const t = await app({ multiAccount: true });
  const bob = t.ctx.accounts.create({ name: 'bob' }).id;
  const authn = soft();
  const h = await enroll(t, bob, authn);
  // Simulate rows left behind by an earlier version (no account row any more).
  t.db.exec('PRAGMA foreign_keys = OFF');
  t.db.prepare('DELETE FROM accounts WHERE id = ?').run(bob);
  t.db.exec('PRAGMA foreign_keys = ON');
  const s = await t.request({ path: '/admin/api/session', headers: { Cookie: h.Cookie } });
  assert.equal(s.status, 200);
  assert.equal(s.json.authenticated, false);
  assert.equal((await login(t, authn)).status, 401);
});

// ---- limits --------------------------------------------------------------------------------

test('signed-in admin requests and key and passkey counts are limited per account', async () => {
  const t = await app({ multiAccount: true, env: { RATE_LIMIT_ADMIN_PER_ACCOUNT_PER_MINUTE: '3', MAX_API_KEYS: '2', MAX_PASSKEYS: '1' } });
  const bob = t.ctx.accounts.create({ name: 'bob' }).id;
  const a = adminSession(t, DEFAULT_ACCOUNT);
  const b = adminSession(t, bob);
  assert.equal((await t.request({ method: 'POST', path: '/admin/api/keys', headers: a.headers, body: { name: 'one' } })).status, 201);
  assert.equal((await t.request({ method: 'POST', path: '/admin/api/keys', headers: a.headers, body: { name: 'two' } })).status, 201);
  const third = await t.request({ method: 'POST', path: '/admin/api/keys', headers: a.headers, body: { name: 'three' } });
  assert.equal(third.status, 409);
  assert.equal(third.json.error.code, 'key_limit');
  const more = await post(t, '/admin/api/passkeys/options', {}, a.headers);
  assert.equal(more.status, 429, 'the fourth request of the minute is refused');
  // The other account is not affected.
  assert.equal((await t.request({ path: '/admin/api/overview', headers: b.readHeaders })).status, 200);
  const pk = await post(t, '/admin/api/passkeys/options', {}, b.headers);
  assert.equal(pk.status, 409, 'bob already has the maximum of one passkey');
  assert.equal(pk.json.error.code, 'passkey_limit');
});

test('one account cannot use up the sending budget of the others', async () => {
  const t = await app({ multiAccount: true, env: { RATE_LIMIT_PER_ACCOUNT_PER_MINUTE: '2', RATE_LIMIT_GLOBAL_PER_MINUTE: '4', RATE_LIMIT_PER_KEY_PER_MINUTE: '100' } });
  const bob = t.ctx.accounts.create({ name: 'bob' }).id;
  addDevice(t);
  addDevice(t, { accountId: bob });
  const ka = t.ctx.keys.create(DEFAULT_ACCOUNT, { name: 'a' }).key;
  const kb = t.ctx.keys.create(bob, { name: 'b' }).key;
  // Paused accounts and invalid requests take nothing from the shared budget.
  t.ctx.accounts.setPaused(DEFAULT_ACCOUNT, true);
  for (let i = 0; i < 5; i++) assert.equal((await notify(t, ka)).status, 503);
  t.ctx.accounts.setPaused(DEFAULT_ACCOUNT, false);
  for (let i = 0; i < 5; i++) assert.equal((await notify(t, ka, { title: 'x' })).status, 400);
  // Each account gets its own share.
  assert.equal((await notify(t, ka)).status, 200);
  assert.equal((await notify(t, ka)).status, 200);
  const third = await notify(t, ka);
  assert.equal(third.status, 429);
  assert.equal((await notify(t, kb)).status, 200);
  assert.equal((await notify(t, kb)).status, 200);
  // Test notifications from the web app count too.
  const s = adminSession(t, bob);
  assert.equal((await t.request({ method: 'POST', path: '/admin/api/test-push', headers: s.headers, body: {} })).status, 429);
});

test('a client that is blocked after failed sign-ins can still sign in with a valid passkey', async () => {
  const t = await app({ env: { AUTH_FAILURE_LIMIT: '3' } });
  const authn = soft();
  await enroll(t, DEFAULT_ACCOUNT, authn);
  const bogus = { id: 'unknown', rawId: 'unknown', type: 'public-key', response: { clientDataJSON: 'e30', authenticatorData: 'AA', signature: 'AA' }, clientExtensionResults: {} };
  const statuses = [];
  for (let i = 0; i < 5; i++) {
    const o = await post(t, '/admin/api/login/options', {});
    statuses.push((await post(t, '/admin/api/login/verify', { challenge_id: o.json.challenge_id, response: bogus })).status);
  }
  assert.deepEqual(statuses, [401, 401, 401, 429, 429]);
  assert.equal((await login(t, authn)).status, 200);
});

test('rate limiters ignore a clock that goes backwards', () => {
  let now = 1_000_000;
  const limiter = createRateLimiter(60, { now: () => now });
  assert.equal(limiter.take('x'), 0);
  now -= 3_600_000;
  assert.ok(limiter.take('x') <= 1, 'a backward step does not drain the bucket');
});

// ---- audit -----------------------------------------------------------------------------------

test('use of a revoked key is shown to its account, and event budgets are per account', async () => {
  const t = await app({ multiAccount: true });
  const bob = t.ctx.accounts.create({ name: 'bob' }).id;
  const { key, record } = t.ctx.keys.create(bob, { name: 'old' });
  t.ctx.keys.revoke(bob, record.id);
  assert.equal((await notify(t, key)).status, 401);
  const failed = t.ctx.audit.list(bob).find((e) => e.type === 'auth.failed');
  assert.equal(failed?.detail.reason, 'revoked');
  // A flood of unattributed events does not hide an account's events.
  for (let i = 0; i < 100; i++) t.ctx.audit.recordThrottled('network.rejected', { ip: `198.51.100.${i}` });
  t.ctx.audit.recordThrottled('admin.csrf_rejected', { accountId: bob, ip: '203.0.113.1' });
  assert.ok(t.ctx.audit.list(bob).some((e) => e.type === 'admin.csrf_rejected'));
  assert.ok(!t.ctx.audit.list(DEFAULT_ACCOUNT).some((e) => e.type === 'audit.suppressed'), 'unattributed summaries are not shown to accounts');
});

test('without multiple accounts, only the default account sees server-wide events', async () => {
  const t = await app();
  const other = t.ctx.accounts.create({ name: 'other' }).id;
  t.ctx.audit.recordThrottled('network.rejected', { ip: '198.51.100.1' });
  const own = adminSession(t, DEFAULT_ACCOUNT);
  const foreign = adminSession(t, other);
  const events = async (s) => (await t.request({ path: '/admin/api/events', headers: s.readHeaders })).json.events.map((e) => e.type);
  assert.ok((await events(own)).includes('network.rejected'));
  assert.ok(!(await events(foreign)).includes('network.rejected'));
});

// ---- sessions, enrollment, recovery --------------------------------------------------------

test('enrolling spends the account\'s other tokens; a replacing token removes the other passkeys', async () => {
  const t = await app({ multiAccount: true });
  const bob = t.ctx.accounts.create({ name: 'bob' }).id;
  const older = t.ctx.auth.createEnrollmentToken(bob).token;
  const first = soft();
  await enroll(t, bob, first);
  const r = await enroll(t, bob, soft(), { token: older });
  assert.equal(r.status, 401, 'an older sign-up or recovery link no longer works');

  const intruder = soft();
  const recovery = t.ctx.auth.createEnrollmentToken(bob).token;
  await enroll(t, bob, intruder, { token: recovery });
  assert.equal(t.ctx.auth.listPasskeys(bob).length, 2);
  const replacing = t.ctx.auth.createEnrollmentToken(bob, { replacePasskeys: true }).token;
  const owner = soft();
  await enroll(t, bob, owner, { token: replacing });
  assert.deepEqual(t.ctx.auth.listPasskeys(bob).map((p) => p.id), [owner.id]);
  assert.equal((await login(t, intruder)).status, 401);
  assert.throws(() => t.ctx.auth.createEnrollmentToken(bob, { replacePasskeys: 'yes' }), TypeError);
});

test('"sign out other sessions" ends every other session of the account only', async () => {
  const t = await app({ multiAccount: true });
  const bob = t.ctx.accounts.create({ name: 'bob' }).id;
  const mine = adminSession(t, bob);
  const stolen = adminSession(t, bob);
  const alice = adminSession(t, DEFAULT_ACCOUNT);
  const r = await post(t, '/admin/api/sessions/revoke-others', {}, mine.headers);
  assert.equal(r.status, 200);
  assert.equal(r.json.revoked, 1);
  const check = async (s) => (await t.request({ path: '/admin/api/session', headers: s.readHeaders })).json.authenticated;
  assert.equal(await check(mine), true);
  assert.equal(await check(stolen), false);
  assert.equal(await check(alice), true);
});

test('a passkey confirmation counts only for the session that asked for it', async () => {
  const t = await app();
  const authn = soft();
  const h = await enroll(t, DEFAULT_ACCOUNT, authn);
  const other = adminSession(t, DEFAULT_ACCOUNT);
  t.db.prepare('UPDATE sessions SET verified_at = 0').run();
  const ro = await post(t, '/admin/api/reauth/options', {}, h);
  const assertion = authn.login(ro.json.options);
  assert.equal((await post(t, '/admin/api/reauth/verify', { challenge_id: ro.json.challenge_id, response: assertion }, other.headers)).status, 400);
  assert.equal((await post(t, '/admin/api/reauth/verify', { challenge_id: ro.json.challenge_id, response: assertion }, h)).status, 200);
});

test('account names are one line of visible text, and the CLI never prints control characters', () => {
  const dir = tempDir();
  const secrets = writeSecrets(dir);
  const env = { ...process.env, ...baseEnv(dir, secrets) };
  // Through the core API: refused.
  return (async () => {
    const t = await app({ dir, secrets });
    for (const bad of ['eve\x1b]0;PWNED\x07', 'a‮b', 'line\nbreak', '', 'x'.repeat(65)]) {
      assert.throws(() => t.ctx.accounts.create({ name: bad }), TypeError, JSON.stringify(bad));
    }
    const id = t.ctx.accounts.create({ name: 'fine' }).id;
    assert.throws(() => t.ctx.accounts.rename(id, 'bad\x1b[2K'), TypeError);
    // A name stored by an older version is printed escaped.
    t.db.prepare('UPDATE accounts SET name = ? WHERE id = ?').run('eve\x1b[2Kfake‮', id);
    const out = spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', path.join(ROOT, 'src', 'cli.js'), 'accounts', 'list'], { env, encoding: 'utf8' });
    assert.equal(out.status, 0, out.stderr);
    assert.ok(!/[\x1b‮]/.test(out.stdout), 'no raw control characters');
    assert.match(out.stdout, /eve\\u\{1b\}\[2Kfake\\u\{202e\}/);
  })();
});

// ---- plugins ---------------------------------------------------------------------------------

test('plugin contract: public routes take no session, flags may have any name', () => {
  const route = { method: 'GET', path: '/x', zone: 'public', auth: 'session', handler: () => ({}) };
  assert.throws(() => resolvePlugins([plugin({ routes: [route] })]), /only allowed with auth "none"/);
  assert.throws(() => resolvePlugins([plugin({ routes: [{ ...route, auth: 'fresh' }] })]), /only allowed with auth "none"/);
  const r = resolvePlugins([plugin({ features: { constructor: true, toString: 1 } })]);
  assert.equal(r.features.constructor, true);
  assert.equal(JSON.stringify(r.features), '{"constructor":true,"toString":1}');
});

test('anonymous plugin routes have their own rate limit bucket', async () => {
  const t = await app({
    env: { RATE_LIMIT_PLUGIN_ANONYMOUS_PER_MINUTE: '2' },
    plugins: [plugin({ routes: [{ method: 'POST', path: '/hook', zone: 'public', auth: 'none', crossOrigin: true, handler: () => ({ ok: true }) }] })],
  });
  const hook = () => t.request({ method: 'POST', path: '/hook', body: {} });
  assert.deepEqual([(await hook()).status, (await hook()).status, (await hook()).status], [200, 200, 429]);
  assert.equal((await t.request({ path: '/admin/api/session' })).status, 200, 'the sign-in budget is untouched');
});

test('limiters from plugins must answer with a number; anything else refuses', async () => {
  for (const take of [async () => 0, () => undefined, () => Number.NaN]) {
    const t = await app({ plugins: [plugin({ services: { rateLimiter: () => ({ take }) } })] });
    const r = await t.request({ path: '/admin/api/session' });
    assert.equal(r.status, 429, String(take));
    assert.equal(r.headers['retry-after'], '60');
    assert.ok(t.logs.some((l) => l.includes('plugin service returned an invalid value')));
  }
});

test('route results: only an exact { status, body } is an envelope', async () => {
  const t = await app({
    plugins: [plugin({ routes: [
      { method: 'GET', path: '/row', auth: 'none', handler: () => ({ id: 7, status: 404, body: 'note' }) },
      { method: 'GET', path: '/empty', auth: 'none', handler: () => ({ status: 204 }) },
      { method: 'GET', path: '/created', auth: 'none', handler: () => ({ status: 201, body: { ok: true } }) },
    ] })],
  });
  const row = await t.request({ path: '/row' });
  assert.equal(row.status, 200);
  assert.deepEqual(row.json, { id: 7, status: 404, body: 'note' });
  const empty = await t.request({ path: '/empty' });
  assert.equal(empty.status, 204);
  assert.equal(empty.text, '');
  assert.equal((await t.request({ path: '/created' })).status, 201);
});

test('plugin web directories never publish hidden files, node_modules or links', () => {
  const dir = tempDir();
  fs.writeFileSync(path.join(dir, 'main.js'), 'export default () => {};');
  fs.writeFileSync(path.join(dir, '.secret.js'), 'secret');
  fs.mkdirSync(path.join(dir, '.git'));
  fs.writeFileSync(path.join(dir, '.git', 'hook.js'), 'secret');
  fs.mkdirSync(path.join(dir, 'node_modules', 'dep'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'node_modules', 'dep', 'index.js'), 'secret');
  fs.writeFileSync(path.join(dir, 'index.html'), '<!doctype html>');
  const outside = path.join(tempDir(), 'server.js');
  fs.writeFileSync(outside, 'secret');
  let linked = true;
  try {
    fs.symlinkSync(outside, path.join(dir, 'link.js'), 'file');
  } catch {
    linked = false; // creating symbolic links needs extra rights on some Windows setups
  }
  const files = [...loadStatic(dir).keys()].sort();
  assert.deepEqual(files, ['/', '/index.html', '/main.js']);
  if (!linked) assert.ok(true, 'symlink case not exercised');
});

// ---- HTTP ------------------------------------------------------------------------------------

test('requests for another host name are refused; the health check is exempt', async () => {
  const t = await app();
  const r = await t.request({ path: '/', headers: { Host: 'rebind.attacker.example' } });
  assert.equal(r.status, 421);
  assert.equal((await t.request({ path: '/', headers: { Host: 'pushgate.test:8443' } })).status, 200, 'the port may differ behind a proxy');
  assert.equal((await t.request({ path: '/', headers: { Host: 'PUSHGATE.test' } })).status, 200);
  assert.equal((await t.request({ path: '/healthz', headers: { Host: '127.0.0.1:8080' } })).status, 200);
});

test('the web app uses no HTML sinks and registers its service worker without Trusted Types', async () => {
  const t = await app();
  const csp = (await t.request({ path: '/' })).headers['content-security-policy'];
  // Trusted Types enforcement is new in Safari; it must not stand between iOS and Web Push.
  assert.doesNotMatch(csp, /trusted-types/);
  const js = fs.readFileSync(path.join(ROOT, 'public', 'app.js'), 'utf8');
  assert.match(js, /serviceWorker\.register\('\/sw\.js'/);
  assert.doesNotMatch(js, /innerHTML|insertAdjacentHTML|document\.write/);
});
