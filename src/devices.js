// Push subscriptions ("devices"). Endpoint URLs and keys are secrets: they are only read by
// the delivery code and never returned by any API. Every device belongs to one account; all
// functions take the account first.
import crypto from 'node:crypto';
import { checkAccountId } from './accounts.js';

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

  function count(accountId) {
    return db.prepare('SELECT COUNT(*) AS n FROM devices WHERE account_id = ?').get(checkAccountId(accountId)).n;
  }

  // Registers a subscription, or refreshes it if the same endpoint is already known in this
  // account. Returns { device, created }, null when the device limit is reached, or
  // { conflict: true } when the endpoint belongs to another account (a browser has one
  // subscription per site; it must be removed there first, it is never moved silently).
  function upsert(accountId, { name, minPriority = 'low', endpoint, p256dh, auth }, maxDevices) {
    checkAccountId(accountId);
    const existing = db.prepare('SELECT id, account_id FROM devices WHERE endpoint = ?').get(endpoint);
    if (existing && existing.account_id !== accountId) return { conflict: true };
    if (existing) {
      db.prepare('UPDATE devices SET name = ?, min_priority = ?, p256dh = ?, auth = ?, failure_count = 0 WHERE id = ?')
        .run(name, minPriority, p256dh, auth, existing.id);
      return { device: get(accountId, existing.id), created: false };
    }
    if (count(accountId) >= maxDevices) return null;
    const id = crypto.randomBytes(16).toString('base64url');
    db.prepare(`INSERT INTO devices (id, account_id, name, endpoint, p256dh, auth, min_priority, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).run(id, accountId, name, endpoint, p256dh, auth, minPriority, now());
    return { device: get(accountId, id), created: true };
  }

  function get(accountId, id) {
    const row = db.prepare('SELECT * FROM devices WHERE id = ? AND account_id = ?').get(id, checkAccountId(accountId));
    return row ? publicView(row) : null;
  }

  function list(accountId) {
    return db.prepare('SELECT * FROM devices WHERE account_id = ? ORDER BY created_at').all(checkAccountId(accountId)).map(publicView);
  }

  function update(accountId, id, { name, minPriority }) {
    const res = db.prepare('UPDATE devices SET name = COALESCE(?, name), min_priority = COALESCE(?, min_priority) WHERE id = ? AND account_id = ?')
      .run(name ?? null, minPriority ?? null, id, checkAccountId(accountId));
    return res.changes === 1;
  }

  function remove(accountId, id) {
    return db.prepare('DELETE FROM devices WHERE id = ? AND account_id = ?').run(id, checkAccountId(accountId)).changes === 1;
  }

  // Internal: full rows including subscription secrets, for delivery only.
  function targets(accountId, deviceId = null) {
    checkAccountId(accountId);
    return deviceId
      ? db.prepare('SELECT * FROM devices WHERE id = ? AND account_id = ?').all(deviceId, accountId)
      : db.prepare('SELECT * FROM devices WHERE account_id = ? ORDER BY created_at').all(accountId);
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
