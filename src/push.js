// Web Push delivery (RFC 8030 / 8291 / 8292) via the `web-push` library.
// The library encrypts the payload for each subscription (aes128gcm) and signs a VAPID JWT.
import crypto from 'node:crypto';
import webpush from 'web-push';
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

export function buildPayload({ id, title, message, priority, tag, service, ts }) {
  // Content is transported as JSON strings and rendered by the service worker as plain text.
  return JSON.stringify({ v: 1, id, title, body: message, priority, tag: tag ?? null, service, ts });
}

function retryDelay(err, attempt) {
  const header = err?.headers?.['retry-after'];
  if (header && /^\d+$/.test(header)) return Math.min(Number(header) * 1000, MAX_RETRY_WAIT_MS);
  return Math.min(500 * 3 ** (attempt - 1), MAX_RETRY_WAIT_MS);
}

export function createPusher({ config, db, devices, audit, log, send = webpush.sendNotification, sleep = (ms) => new Promise((r) => setTimeout(r, ms)), now = () => Date.now() }) {
  const vapidDetails = { subject: config.vapidSubject, publicKey: config.vapid.publicKey, privateKey: config.vapid.privateKey };

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

  // Delivers one notification to all registered devices (or one device for tests).
  // Never throws for delivery problems; returns a summary safe to show to the caller.
  async function deliver({ keyId = null, title, message, priority = 'normal', tag = null, ttl = DEFAULT_TTL, service, deviceId = null }) {
    const id = crypto.randomUUID();
    const payload = buildPayload({ id, title, message, priority, tag, service, ts: now() });
    if (Buffer.byteLength(payload) > MAX_PAYLOAD_BYTES) return { error: 'payload_too_large' };

    const all = devices.targets(deviceId);
    const eligible = all.filter((d) => priorityRank(priority) >= priorityRank(d.min_priority));
    const results = await Promise.all(eligible.map(async (d) => {
      const r = await sendOne(d, payload, { ttl, priority, tag });
      if (r.outcome === 'gone') {
        devices.remove(d.id);
        audit.record('device.expired', { detail: { device: d.id, name: d.name, status: r.status } });
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
      db.prepare(`INSERT INTO deliveries (id, key_id, priority, created_at, status, targeted, delivered, failed, removed)
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
        .run(id, keyId, priority, now(), status, summary.targeted, summary.delivered, summary.failed, summary.removed);
    }
    return { id, status, devices: summary };
  }

  return { deliver };
}
