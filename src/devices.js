// Push subscriptions ("devices"). Endpoint URLs and keys are secrets: they are only read by
// the delivery code and never returned by any API.
import crypto from 'node:crypto';

export function hostAllowed(hostname, allowed) {
  const h = hostname.toLowerCase();
  return allowed.some((a) => h === a || h.endsWith('.' + a));
}

// Returns { endpoint, p256dh, auth } or throws Error with a client-safe message.
export function checkSubscription(sub, allowedHosts) {
  let url;
  try {
    url = new URL(sub.endpoint);
  } catch {
    throw new Error('subscription endpoint is not a URL');
  }
  if (url.protocol !== 'https:' || url.username || url.password || (url.port && url.port !== '443')) {
    throw new Error('subscription endpoint must be a plain https URL');
  }
  if (!hostAllowed(url.hostname, allowedHosts)) {
    throw new Error('subscription endpoint is not a known push service');
  }
  const p256dh = Buffer.from(sub.keys.p256dh, 'base64url');
  if (p256dh.length !== 65 || p256dh[0] !== 4) throw new Error('subscription p256dh key is invalid');
  const auth = Buffer.from(sub.keys.auth, 'base64url');
  if (auth.length !== 16) throw new Error('subscription auth secret is invalid');
  return { endpoint: url.href, p256dh: p256dh.toString('base64url'), auth: auth.toString('base64url') };
}

export function createDevices(db, { now = () => Date.now() } = {}) {
  const publicView = (row) => ({
    id: row.id,
    name: row.name,
    push_service: new URL(row.endpoint).hostname,
    min_priority: row.min_priority,
    created_at: row.created_at,
    last_success_at: row.last_success_at,
    last_failure_at: row.last_failure_at,
    last_status: row.last_status,
    failure_count: row.failure_count,
  });

  function count() {
    return db.prepare('SELECT COUNT(*) AS n FROM devices').get().n;
  }

  // Registers a subscription, or refreshes it if the same endpoint is already known.
  // Returns { device, created } or null when the device limit is reached.
  function upsert({ name, minPriority = 'low', endpoint, p256dh, auth }, maxDevices) {
    const existing = db.prepare('SELECT id FROM devices WHERE endpoint = ?').get(endpoint);
    if (existing) {
      db.prepare('UPDATE devices SET name = ?, min_priority = ?, p256dh = ?, auth = ?, failure_count = 0 WHERE id = ?')
        .run(name, minPriority, p256dh, auth, existing.id);
      return { device: get(existing.id), created: false };
    }
    if (count() >= maxDevices) return null;
    const id = crypto.randomBytes(16).toString('base64url');
    db.prepare(`INSERT INTO devices (id, name, endpoint, p256dh, auth, min_priority, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)`).run(id, name, endpoint, p256dh, auth, minPriority, now());
    return { device: get(id), created: true };
  }

  function get(id) {
    const row = db.prepare('SELECT * FROM devices WHERE id = ?').get(id);
    return row ? publicView(row) : null;
  }

  function list() {
    return db.prepare('SELECT * FROM devices ORDER BY created_at').all().map(publicView);
  }

  function update(id, { name, minPriority }) {
    const res = db.prepare('UPDATE devices SET name = COALESCE(?, name), min_priority = COALESCE(?, min_priority) WHERE id = ?')
      .run(name ?? null, minPriority ?? null, id);
    return res.changes === 1;
  }

  function remove(id) {
    return db.prepare('DELETE FROM devices WHERE id = ?').run(id).changes === 1;
  }

  // Internal: full rows including subscription secrets, for delivery only.
  function targets(deviceId = null) {
    return deviceId
      ? db.prepare('SELECT * FROM devices WHERE id = ?').all(deviceId)
      : db.prepare('SELECT * FROM devices ORDER BY created_at').all();
  }

  function recordResult(id, ok, status) {
    if (ok) {
      db.prepare('UPDATE devices SET last_success_at = ?, last_status = ?, failure_count = 0 WHERE id = ?').run(now(), status, id);
    } else {
      db.prepare('UPDATE devices SET last_failure_at = ?, last_status = ?, failure_count = failure_count + 1 WHERE id = ?')
        .run(now(), status, id);
    }
  }

  return { count, upsert, get, list, update, remove, targets, recordResult };
}
