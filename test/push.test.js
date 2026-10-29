import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { after, test } from 'node:test';
import ece from 'http_ece';
import webpush from 'web-push';
import { checkSubscription } from '../src/devices.js';
import { addDevice, fakeSubscription, notify, startApp } from './helpers.js';

const apps = [];
async function app(opts) {
  const t = await startApp(opts);
  apps.push(t);
  return t;
}
after(() => Promise.all(apps.map((t) => t.close())));

const noSleep = { RATE_LIMIT_PER_KEY_PER_MINUTE: '100' };

test('expired subscriptions (404/410) are removed without retry', async () => {
  const t = await app({ env: noSleep, script: () => ({ statusCode: 410 }) });
  const d = addDevice(t);
  const { key } = t.ctx.keys.create({ name: 'svc' });
  const r = await notify(t, key);
  assert.equal(r.status, 502);
  assert.equal(r.json.status, 'failed');
  assert.equal(r.json.devices.removed, 1);
  assert.equal(t.push.calls.length, 1);
  assert.equal(t.ctx.devices.get(d.id), null);
  assert.ok(t.ctx.audit.list().some((e) => e.type === 'device.expired'));
});

test('transient errors are retried a bounded number of times', async () => {
  const t = await app({ env: noSleep, script: () => ({ statusCode: 503, headers: { 'retry-after': '0' } }) });
  const d = addDevice(t);
  const { key } = t.ctx.keys.create({ name: 'svc' });
  const r = await notify(t, key);
  assert.equal(r.json.status, 'failed');
  assert.equal(t.push.calls.length, 3, 'one attempt plus two retries');
  const dev = t.ctx.devices.get(d.id);
  assert.equal(dev.failure_count, 1);
  assert.equal(dev.last_status, 503);
});

test('a transient error followed by success is delivered', async () => {
  const t = await app({ env: noSleep, script: (_s, n) => (n === 1 ? new Error('ECONNRESET') : { statusCode: 201 }) });
  addDevice(t);
  const { key } = t.ctx.keys.create({ name: 'svc' });
  const r = await notify(t, key);
  assert.equal(r.status, 200);
  assert.equal(r.json.status, 'delivered');
  assert.equal(t.push.calls.length, 2);
});

test('permanent errors are not retried and do not leak endpoint details', async () => {
  const t = await app({ env: noSleep, script: () => ({ statusCode: 403, body: 'BadJwtToken' }) });
  const d = addDevice(t);
  const { key } = t.ctx.keys.create({ name: 'svc' });
  const r = await notify(t, key);
  assert.equal(t.push.calls.length, 1);
  assert.equal(r.json.status, 'failed');
  assert.ok(t.ctx.devices.get(d.id), 'device kept: 403 is a server/VAPID problem, not an expired subscription');
  const all = t.logs.join('\n') + r.text;
  assert.ok(!all.includes(d.subscription.endpoint));
  assert.ok(!all.includes(new URL(d.subscription.endpoint).pathname.slice(1)));
});

test('multiple devices are served by one key; partial failures and priority filters are reported', async () => {
  const t = await app({ env: noSleep, script: (s) => (s.endpoint.includes('fcm.googleapis.com') ? { statusCode: 400 } : { statusCode: 201 }) });
  addDevice(t, { name: 'iphone' });
  addDevice(t, { name: 'android', host: 'fcm.googleapis.com' });
  addDevice(t, { name: 'quiet', minPriority: 'high' });
  const { key } = t.ctx.keys.create({ name: 'svc' });
  const r = await notify(t, key, { title: 'a', message: 'b', priority: 'normal' });
  assert.equal(r.status, 200);
  assert.equal(r.json.status, 'partial');
  assert.deepEqual(r.json.devices, { targeted: 2, delivered: 1, failed: 1, removed: 0, filtered: 1 });
  const row = t.db.prepare('SELECT * FROM deliveries WHERE id = ?').get(r.json.id);
  assert.equal(row.status, 'partial');
  assert.ok(!JSON.stringify(row).includes('"a"'), 'no content stored');
  assert.deepEqual(Object.keys(row).sort(), ['created_at', 'delivered', 'failed', 'id', 'key_id', 'priority', 'removed', 'status', 'targeted']);
});

test('with no devices the request succeeds with status no_devices', async () => {
  const t = await app();
  const { key } = t.ctx.keys.create({ name: 'svc' });
  const r = await notify(t, key);
  assert.equal(r.status, 200);
  assert.equal(r.json.status, 'no_devices');
});

test('invalid subscriptions are rejected safely', () => {
  const hosts = ['push.apple.com', 'fcm.googleapis.com'];
  const good = fakeSubscription().subscription;
  assert.ok(checkSubscription(good, hosts));
  const mutate = (fn) => {
    const s = structuredClone(good);
    fn(s);
    return s;
  };
  const bad = [
    mutate((s) => { s.endpoint = 'http://web.push.apple.com/x'; }),
    mutate((s) => { s.endpoint = 'https://evil.example/x'; }),
    mutate((s) => { s.endpoint = 'https://push.apple.com.evil.example/x'; }),
    mutate((s) => { s.endpoint = 'https://127.0.0.1/x'; }),
    mutate((s) => { s.endpoint = 'https://web.push.apple.com:8443/x'; }),
    mutate((s) => { s.endpoint = 'https://user:pw@web.push.apple.com/x'; }),
    mutate((s) => { s.endpoint = 'not a url'; }),
    mutate((s) => { s.keys.p256dh = Buffer.alloc(65).toString('base64url'); }),
    mutate((s) => { s.keys.p256dh = s.keys.p256dh.slice(0, 80); }),
    mutate((s) => { s.keys.auth = Buffer.alloc(8).toString('base64url'); }),
  ];
  for (const s of bad) assert.throws(() => checkSubscription(s, hosts), Error, s.endpoint);
});

test('Web Push payloads are encrypted for the subscription and decrypt to the exact text', async () => {
  const { subscription, ecdh, auth } = fakeSubscription();
  const { publicKey, privateKey } = webpush.generateVAPIDKeys();
  const tricky = { title: '<script>alert(1)</script> & "quotes"', body: '<img src=x onerror=alert(1)>\nzweite Zeile ✓' };
  const payload = JSON.stringify(tricky);
  const details = webpush.generateRequestDetails(subscription, payload, {
    vapidDetails: { subject: 'mailto:a@example.invalid', publicKey, privateKey },
    TTL: 60,
  });
  assert.equal(details.headers['Content-Encoding'], 'aes128gcm');
  assert.ok(!details.body.includes(Buffer.from(tricky.title)), 'ciphertext does not contain the plaintext');
  const plain = ece.decrypt(details.body, { version: 'aes128gcm', privateKey: ecdh, authSecret: auth.toString('base64url') });
  assert.deepEqual(JSON.parse(plain.toString('utf8')), tricky);
  assert.match(details.headers.Authorization, /^vapid t=.+, k=/);
});

test('the service worker shows content as plain text and never takes URLs from the payload', async () => {
  const listeners = {};
  const shown = [];
  const opened = [];
  const sandbox = {
    self: {
      addEventListener: (type, fn) => { listeners[type] = fn; },
      registration: { showNotification: (title, options) => { shown.push({ title, options }); return Promise.resolve(); } },
      clients: { matchAll: async () => [], openWindow: async (u) => opened.push(u), claim: async () => {} },
      location: { origin: 'https://pushgate.test' },
      skipWaiting: () => {},
    },
    URL,
  };
  vm.runInNewContext(fs.readFileSync(new URL('../public/sw.js', import.meta.url), 'utf8'), sandbox);
  const push = (data) => new Promise((resolve) => {
    listeners.push({ data: { json: () => (data instanceof Error ? (() => { throw data; })() : data) }, waitUntil: (p) => p.then(resolve) });
  });

  await push({ title: '<b>Alert</b>', body: '<a href="javascript:x">click</a>', service: 'svc', tag: 'disk', url: 'https://evil.example', actions: [{ action: 'x' }] });
  assert.equal(shown[0].title, 'svc: <b>Alert</b>', 'title passed through verbatim as text, led by the sender');
  assert.equal(shown[0].options.body, '<a href="javascript:x">click</a>');
  assert.equal(shown[0].options.tag, 'disk');
  assert.ok(!('actions' in shown[0].options));
  assert.ok(!JSON.stringify(shown[0].options).includes('evil.example'));

  await push(new Error('not json'));
  assert.equal(shown[1].title, 'Notification', 'malformed payload still shows a notification (iOS requirement)');
  await push({ title: 42, tag: 'bad tag!' });
  assert.equal(shown[2].title, 'Notification');
  assert.ok(!('tag' in shown[2].options));

  await new Promise((resolve) => {
    listeners.notificationclick({ notification: { close() {} }, waitUntil: (p) => p.then(resolve) });
  });
  assert.deepEqual(opened, ['/']);
});

test('the admin UI never renders server data as HTML and loads no external resources', () => {
  const js = fs.readFileSync(new URL('../public/app.js', import.meta.url), 'utf8');
  const sw = fs.readFileSync(new URL('../public/sw.js', import.meta.url), 'utf8');
  const html = fs.readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
  for (const src of [js, sw]) {
    assert.doesNotMatch(src, /innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function|setAttribute\(\s*['"]on/);
  }
  assert.doesNotMatch(html, /<script(?![^>]*src="\/app\.js")/, 'no inline scripts');
  assert.doesNotMatch(html, /\son[a-z]+=/i, 'no inline event handlers');
  assert.doesNotMatch(html + js + sw, /https?:\/\/(?!localhost)/, 'no external URLs');
});
