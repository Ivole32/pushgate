import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { createApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { openDatabase } from '../src/db.js';
import { createLogger } from '../src/log.js';
import { createServer } from '../src/server.js';

export const ORIGIN = 'https://pushgate.test';

export function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'pushgate-test-'));
}

export function writeSecrets(dir) {
  const pepper = crypto.randomBytes(32).toString('base64');
  const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const pem = privateKey.export({ format: 'pem', type: 'pkcs8' });
  fs.writeFileSync(path.join(dir, 'pepper'), pepper);
  fs.writeFileSync(path.join(dir, 'vapid.pem'), pem);
  return { pepper, pem, pepperFile: path.join(dir, 'pepper'), vapidFile: path.join(dir, 'vapid.pem') };
}

export function baseEnv(dir, secrets, overrides = {}) {
  return {
    PUBLIC_ORIGIN: ORIGIN,
    DATA_DIR: path.join(dir, 'data'),
    API_KEY_PEPPER_FILE: secrets.pepperFile,
    VAPID_PRIVATE_KEY_FILE: secrets.vapidFile,
    VAPID_SUBJECT: 'mailto:admin@example.invalid',
    TRUSTED_CIDRS: '127.0.0.1/32',
    ADMIN_CIDRS: '127.0.0.1/32',
    REQUIRE_SETUP_BEFORE_SENDING: 'false',
    ...overrides,
  };
}

// A fake push transport: records calls, answers with scripted results.
export function fakeSend(script = () => ({ statusCode: 201 })) {
  const calls = [];
  const send = async (subscription, payload, options) => {
    calls.push({ subscription, payload, options });
    const r = await script(subscription, calls.length);
    if (r instanceof Error) throw r;
    if (r.statusCode >= 400) {
      const err = new Error(`push failed ${r.statusCode} ${subscription.endpoint}`);
      err.name = 'WebPushError';
      err.statusCode = r.statusCode;
      err.headers = r.headers ?? {};
      err.body = r.body ?? '';
      err.endpoint = subscription.endpoint;
      throw err;
    }
    return { statusCode: r.statusCode, headers: {}, body: '' };
  };
  return { send, calls };
}

export async function startApp({ env = {}, script, dir = tempDir(), secrets, plugins } = {}) {
  const s = secrets ?? writeSecrets(dir);
  const config = loadConfig(baseEnv(dir, s, env));
  const logs = [];
  const log = createLogger({ level: 'debug', sink: (l) => logs.push(l) });
  const db = openDatabase(config.dataDir);
  const push = fakeSend(script);
  const app = createApp({ config, db, log, send: push.send, plugins });
  const server = createServer(app);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  return {
    dir,
    secrets: s,
    config,
    db,
    app,
    ctx: app.ctx,
    logs,
    push,
    port,
    request: (opts) => request(port, opts),
    async close() {
      server.closeAllConnections();
      await new Promise((r) => server.close(r));
      db.close();
    },
  };
}

export function request(port, { method = 'GET', path: p = '/', headers = {}, body, raw } = {}) {
  return new Promise((resolve, reject) => {
    const data = raw !== undefined ? raw : body !== undefined ? JSON.stringify(body) : undefined;
    const h = { ...headers };
    if (body !== undefined && !Object.keys(h).some((k) => k.toLowerCase() === 'content-type')) h['Content-Type'] = 'application/json';
    const req = http.request({ host: '127.0.0.1', port, method, path: p, headers: h }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json;
        try {
          json = JSON.parse(text);
        } catch {
          json = null;
        }
        resolve({ status: res.statusCode, headers: res.headers, text, json });
      });
    });
    req.on('error', (err) => {
      // The server may close the connection right after rejecting an oversized upload.
      if (err.code === 'ECONNRESET' || err.code === 'EPIPE') resolve({ status: 0, headers: {}, text: '', json: null, reset: true });
      else reject(err);
    });
    if (data !== undefined) req.write(data);
    req.end();
  });
}

// Creates a passkey row and a session directly in the database (for tests that are not
// about the WebAuthn ceremony itself). Returns headers for authenticated admin requests.
export function adminSession(t) {
  const id = crypto.randomBytes(16).toString('base64url');
  t.db.prepare('INSERT INTO passkeys (id, public_key, counter, transports, name, created_at) VALUES (?, ?, 0, ?, ?, ?)')
    .run(id, Buffer.alloc(77), '[]', 'test', Date.now());
  const s = t.ctx.auth.createSession(id);
  return {
    passkeyId: id,
    token: s.token,
    csrf: s.csrf,
    headers: { Cookie: `__Host-pushgate_session=${s.token}`, 'X-CSRF-Token': s.csrf, Origin: ORIGIN },
    readHeaders: { Cookie: `__Host-pushgate_session=${s.token}` },
  };
}

// A syntactically valid browser push subscription (real P-256 key and auth secret), plus the
// private material needed to decrypt payloads sent to it.
export function fakeSubscription(host = 'web.push.apple.com') {
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.generateKeys();
  const auth = crypto.randomBytes(16);
  return {
    subscription: {
      endpoint: `https://${host}/${crypto.randomBytes(24).toString('base64url')}`,
      expirationTime: null,
      keys: { p256dh: ecdh.getPublicKey().toString('base64url'), auth: auth.toString('base64url') },
    },
    ecdh,
    auth,
  };
}

export function addDevice(t, { name = 'phone', minPriority = 'low', host } = {}) {
  const { subscription } = fakeSubscription(host);
  const r = t.ctx.devices.upsert({ name, minPriority, endpoint: subscription.endpoint, p256dh: subscription.keys.p256dh, auth: subscription.keys.auth }, 100);
  return { ...r.device, subscription };
}

export const notify = (t, key, body = { title: 'Hello', message: 'World' }, headers = {}) =>
  t.request({ method: 'POST', path: '/api/v1/notifications', headers: { Authorization: `Bearer ${key}`, ...headers }, body });
