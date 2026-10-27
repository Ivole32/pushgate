// Per-service API keys.
//
// Format:  pgk_<key id: 16 hex>_<secret: 32 random bytes, base64url (43 chars)>
// Storage: HMAC-SHA-256(pepper, full key) as hex. The pepper is a secret file outside the
//          database. See docs/ARCHITECTURE.md for why a keyed hash is used instead of a
//          password hash.
import crypto from 'node:crypto';
import { transaction } from './db.js';

export const SCOPES = Object.freeze({
  SEND: 'notifications:send',
  SEND_HIGH: 'notifications:send:high',
});
const ALL_SCOPES = new Set(Object.values(SCOPES));
const KEY_PATTERN = /^pgk_([0-9a-f]{16})_([A-Za-z0-9_-]{43})$/;
const ID_PATTERN = /^[0-9a-f]{16}$/;

export function isValidKeyId(id) {
  return typeof id === 'string' && ID_PATTERN.test(id);
}

export function createApiKeys(db, pepper, { now = () => Date.now() } = {}) {
  const hash = (key) => crypto.createHmac('sha256', pepper).update(key, 'utf8').digest();
  const dummyHash = hash('pgk_0000000000000000_' + 'A'.repeat(43));

  const publicView = (row) => ({
    id: row.id,
    name: row.name,
    description: row.description,
    scopes: JSON.parse(row.scopes),
    created_at: row.created_at,
    expires_at: row.expires_at,
    revoked_at: row.revoked_at,
    last_used_at: row.last_used_at,
    rotated_from: row.rotated_from,
    // True when a newer key was issued by rotation (this one is revoked or in its grace period).
    replaced: Boolean(db.prepare('SELECT 1 FROM api_keys WHERE rotated_from = ?').get(row.id)),
    status: row.revoked_at ? 'revoked' : row.expires_at !== null && row.expires_at <= now() ? 'expired' : 'active',
  });

  function create({ name, description = '', expiresAt = null, scopes = [SCOPES.SEND], rotatedFrom = null }) {
    for (const s of scopes) if (!ALL_SCOPES.has(s)) throw new Error('unknown scope');
    if (expiresAt !== null && expiresAt <= now()) throw new Error('expiry must be in the future');
    const id = crypto.randomBytes(8).toString('hex');
    const key = `pgk_${id}_${crypto.randomBytes(32).toString('base64url')}`;
    db.prepare(`INSERT INTO api_keys (id, name, description, key_hash, scopes, created_at, expires_at, rotated_from)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(id, name, description, hash(key).toString('hex'), JSON.stringify([...new Set(scopes)]), now(), expiresAt, rotatedFrom);
    return { key, record: get(id) };
  }

  function get(id) {
    const row = db.prepare('SELECT * FROM api_keys WHERE id = ?').get(id);
    return row ? publicView(row) : null;
  }

  function list() {
    return db.prepare('SELECT * FROM api_keys ORDER BY created_at DESC').all().map(publicView);
  }

  // Returns { ok: true, key } or { ok: false, reason, keyId }. Callers must not reveal the
  // reason to the client; it is for audit logging only.
  function verify(presented) {
    if (typeof presented !== 'string' || presented.length > 100) return { ok: false, reason: 'malformed', keyId: null };
    const m = KEY_PATTERN.exec(presented);
    if (!m) return { ok: false, reason: 'malformed', keyId: null };
    const keyId = m[1];
    const row = db.prepare('SELECT * FROM api_keys WHERE id = ?').get(keyId);
    const actual = hash(presented);
    // Always perform one constant-time comparison so that unknown ids cost the same.
    const expected = row ? Buffer.from(row.key_hash, 'hex') : dummyHash;
    const match = crypto.timingSafeEqual(actual, expected);
    if (!row || !match) return { ok: false, reason: row ? 'mismatch' : 'unknown', keyId };
    if (row.revoked_at) return { ok: false, reason: 'revoked', keyId };
    if (row.expires_at !== null && row.expires_at <= now()) return { ok: false, reason: 'expired', keyId };
    db.prepare('UPDATE api_keys SET last_used_at = ? WHERE id = ?').run(now(), keyId);
    return { ok: true, key: publicView(row) };
  }

  function revoke(id) {
    const res = db.prepare('UPDATE api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL').run(now(), id);
    return res.changes === 1;
  }

  // Issues a new key with the same name, description and scopes. The old key is revoked
  // immediately, or keeps working for `graceSeconds` so the service can be reconfigured.
  function rotate(id, { graceSeconds = 0 } = {}) {
    return transaction(db, () => {
      const row = db.prepare('SELECT * FROM api_keys WHERE id = ?').get(id);
      if (!row || row.revoked_at) return null;
      const t = now();
      if (row.expires_at !== null && row.expires_at <= t) return null;
      // A key in its rotation grace period already has a successor; rotate that one instead.
      // (Its expires_at is the grace deadline, which must not be copied to a new key.)
      if (db.prepare('SELECT 1 FROM api_keys WHERE rotated_from = ?').get(id)) return null;
      const created = create({
        name: row.name,
        description: row.description,
        scopes: JSON.parse(row.scopes),
        expiresAt: row.expires_at,
        rotatedFrom: row.id,
      });
      if (graceSeconds > 0) {
        const until = t + graceSeconds * 1000;
        db.prepare('UPDATE api_keys SET expires_at = ? WHERE id = ?')
          .run(row.expires_at === null ? until : Math.min(row.expires_at, until), id);
      } else {
        db.prepare('UPDATE api_keys SET revoked_at = ? WHERE id = ?').run(t, id);
      }
      return created;
    });
  }

  return { create, get, list, verify, revoke, rotate };
}
