// Web Push delivery (RFC 8030 / 8291 / 8292). The `web-push` library encrypts the payload for
// each subscription (aes128gcm) and signs a VAPID JWT; the request itself is made here.
import crypto from 'node:crypto';
import https from 'node:https';
import webpush from 'web-push';
import { checkEndpoint } from './devices.js';
import { priorityRank } from './validate.js';
import { safeError } from './log.js';

// Apple and other push services accept 4 KiB of encrypted payload; encryption adds overhead,
// so the plaintext JSON is capped well below that.
export const MAX_PAYLOAD_BYTES = 3072;
export const DEFAULT_TTL = 86400;
const MAX_ATTEMPTS = 3;
const MAX_RETRY_WAIT_MS = 5000;
const REQUEST_TIMEOUT_MS = 10000;
const RETRYABLE = new Set([429, 500, 502, 503, 504]);
// Push services answer with a few bytes; anything beyond this is not read.
export const MAX_RESPONSE_BYTES = 65536;

export function buildPayload({ id, title, message, priority, tag, service, ts }) {
  // Content is transported as JSON strings and rendered by the service worker as plain text.
  return JSON.stringify({ v: 1, id, title, body: message, priority, tag: tag ?? null, service, ts });
}

// The default transport, with the interface of web-push's sendNotification. Unlike that, it
// bounds the whole attempt by `options.timeout` (not only idle time), reads at most
// MAX_RESPONSE_BYTES of the answer, and connects to the host of the WHATWG-parsed endpoint,
// the same parser that checked it. Resolves { statusCode, headers, body } for 2xx, otherwise
// rejects with an error carrying `statusCode`, `headers` and `body` (like WebPushError).
export function createTransport({ request = https.request, maxResponseBytes = MAX_RESPONSE_BYTES } = {}) {
  return function send(subscription, payload, options = {}) {
    const { timeout = REQUEST_TIMEOUT_MS, ...rest } = options;
    let details;
    try {
      details = webpush.generateRequestDetails(subscription, payload, rest);
    } catch (err) {
      return Promise.reject(err);
    }
    const url = new URL(details.endpoint);
    return new Promise((resolve, reject) => {
      let settled = false;
      const finish = (fn, value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        fn(value);
      };
      const req = request({
        hostname: url.hostname,
        port: 443,
        path: url.pathname + url.search,
        method: details.method,
        headers: details.headers,
      }, (res) => {
        const chunks = [];
        let size = 0;
        res.on('data', (chunk) => {
          size += chunk.length;
          if (size > maxResponseBytes) {
            req.destroy();
            finish(reject, new Error('push service response too large'));
            return;
          }
          chunks.push(chunk);
        });
        res.on('error', (err) => finish(reject, err));
        res.on('end', () => {
          const body = Buffer.concat(chunks).toString('utf8');
          if (res.statusCode >= 200 && res.statusCode <= 299) return finish(resolve, { statusCode: res.statusCode, headers: res.headers, body });
          const err = new Error('Received unexpected response code');
          Object.assign(err, { name: 'WebPushError', statusCode: res.statusCode, headers: res.headers, body });
          finish(reject, err);
        });
      });
      const timer = setTimeout(() => {
        req.destroy();
        finish(reject, new Error('push request timed out'));
      }, timeout);
      req.on('error', (err) => finish(reject, err));
      req.end(details.body);
    });
  };
}

function retryDelay(err, attempt) {
  const header = err?.headers?.['retry-after'];
  if (header && /^\d+$/.test(header)) return Math.min(Number(header) * 1000, MAX_RETRY_WAIT_MS);
  return Math.min(500 * 3 ** (attempt - 1), MAX_RETRY_WAIT_MS);
}

export function createPusher({ config, db, devices, audit, log, send = createTransport(), sleep = (ms) => new Promise((r) => setTimeout(r, ms)), now = () => Date.now() }) {
  const vapidDetails = { subject: config.vapidSubject, publicKey: config.vapid.publicKey, privateKey: config.vapid.privateKey };

  // A tag replaces earlier notifications with the same tag, on the device and (as the Web Push
  // Topic header) in the push service's queue. Tags are therefore scoped to the sending service,
  // so one service cannot replace or cancel another's alerts, and keyed with the pepper, so the
  // push service does not see the tag text. 32 base64url characters, the Topic header maximum.
  const scopedTag = (scope, tag) =>
    crypto.createHmac('sha256', config.pepper).update(`tag\0${scope}\0${tag}`).digest('base64url').slice(0, 32);

  // Checked again at every delivery: the allowed hosts may have changed since registration, and
  // rows stored by older versions were checked less strictly.
  function endpointAllowed(device) {
    try {
      checkEndpoint(device.endpoint, config.pushHosts);
      return true;
    } catch {
      log.warn('device endpoint not allowed, not sending', { device: device.id });
      return false;
    }
  }

  async function sendOne(device, payload, { ttl, priority, tag }) {
    const subscription = { endpoint: device.endpoint, keys: { p256dh: device.p256dh, auth: device.auth } };
    const options = { vapidDetails, TTL: ttl, urgency: priority, timeout: REQUEST_TIMEOUT_MS };
    if (tag) options.topic = tag;
    for (let attempt = 1; ; attempt++) {
      try {
        const res = await send(subscription, payload, options);
        return { outcome: 'delivered', status: res?.statusCode ?? 201, attempts: attempt };
      } catch (err) {
        const status = Number.isInteger(err?.statusCode) ? err.statusCode : null;
        if (status === 404 || status === 410) return { outcome: 'gone', status, attempts: attempt };
        const retryable = status === null || RETRYABLE.has(status);
        if (!retryable || attempt >= MAX_ATTEMPTS) {
          log.warn('push delivery failed', { device: device.id, attempts: attempt, ...safeError(err) });
          return { outcome: 'failed', status, attempts: attempt };
        }
        await sleep(retryDelay(err, attempt));
      }
    }
  }

  // Delivers one notification to all devices of an account (or one of its devices for tests).
  // Never throws for delivery problems; returns a summary safe to show to the caller.
  // `tagScope` identifies the sending service across key rotations (see apikeys.lineage).
  async function deliver({ accountId, keyId = null, title, message, priority = 'normal', tag = null, tagScope = keyId, ttl = DEFAULT_TTL, service, deviceId = null }) {
    const id = crypto.randomUUID();
    const scoped = tag ? scopedTag(tagScope ?? service, tag) : null;
    const payload = buildPayload({ id, title, message, priority, tag: scoped, service, ts: now() });
    if (Buffer.byteLength(payload) > MAX_PAYLOAD_BYTES) return { error: 'payload_too_large' };

    const all = devices.targets(accountId, deviceId);
    const eligible = all.filter((d) => priorityRank(priority) >= priorityRank(d.min_priority));
    const results = await Promise.all(eligible.map(async (d) => {
      const r = endpointAllowed(d) ? await sendOne(d, payload, { ttl, priority, tag: scoped }) : { outcome: 'failed', status: null, attempts: 0 };
      if (r.outcome === 'gone') {
        // Not recorded when the device was removed meanwhile (e.g. it unsubscribed itself and
        // the admin removal sent it an alert).
        if (devices.remove(accountId, d.id)) audit.record('device.expired', { accountId, detail: { device: d.id, name: d.name, status: r.status } });
      } else {
        devices.recordResult(d.id, r.outcome === 'delivered', r.status);
      }
      return r;
    }));

    const count = (o) => results.filter((r) => r.outcome === o).length;
    const summary = {
      targeted: eligible.length,
      delivered: count('delivered'),
      failed: count('failed'),
      removed: count('gone'),
      filtered: all.length - eligible.length,
    };
    let status;
    if (all.length === 0) status = 'no_devices';
    else if (eligible.length === 0) status = 'filtered';
    else if (summary.delivered === eligible.length) status = 'delivered';
    else if (summary.delivered > 0) status = 'partial';
    else status = 'failed';

    if (config.historyRetentionDays > 0) {
      // Not recorded for an account removed while the notification was on its way.
      db.prepare(`INSERT INTO deliveries (id, account_id, key_id, priority, created_at, status, targeted, delivered, failed, removed)
                  SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM accounts WHERE id = ?)`)
        .run(id, accountId, keyId, priority, now(), status, summary.targeted, summary.delivered, summary.failed, summary.removed, accountId);
    }
    return { id, status, devices: summary };
  }

  return { deliver };
}
