// Accounts. Every API key, passkey, device, delivery and enrollment token belongs to exactly one
// account, and every query is limited to it. A self-hosted installation uses only the account
// "default" (created by the database migration); with several accounts (`multiAccount`), each
// one is a separate administrator with its own keys and devices.
import crypto from 'node:crypto';
import { transaction } from './db.js';
import { validate } from './validate.js';

export const DEFAULT_ACCOUNT = 'default';
export const ACCOUNT_ID = /^(default|acc_[0-9a-f]{16})$/;

// Guards every scoped data function: a missing account id is a programming error and must
// never fall back to "all accounts" or to the default account.
export function checkAccountId(id) {
  if (typeof id !== 'string' || !ACCOUNT_ID.test(id)) throw new TypeError('a valid account id is required');
  return id;
}

// Thrown when data would be added to an account that no longer exists: a request that passed
// its session check before the account was removed must not recreate rows for it. Answered
// with 401, like a missing session.
export class UnknownAccountError extends Error {
  constructor() {
    super('unknown account');
  }
}

// Called synchronously right before an insert (node:sqlite is synchronous, so nothing can
// remove the account in between).
export function requireAccount(db, id) {
  if (!db.prepare('SELECT 1 FROM accounts WHERE id = ?').get(checkAccountId(id))) throw new UnknownAccountError();
}

// Names come from sign-up forms (via plugins) and are printed by the CLI and shown in the web
// app: one line of visible text, the same rules as other names.
const NAME_FIELDS = { name: { type: 'string', required: true, minLength: 1, maxLength: 64 } };
function checkName(name) {
  if (validate({ name }, NAME_FIELDS).length) throw new TypeError('account name must be 1-64 characters without control characters');
}

export function createAccounts(db, { now = () => Date.now() } = {}) {
  const publicView = (row) => ({ id: row.id, name: row.name, sending_paused: row.sending_paused === 1, created_at: row.created_at });

  function create({ name }) {
    checkName(name);
    const id = `acc_${crypto.randomBytes(8).toString('hex')}`;
    db.prepare('INSERT INTO accounts (id, name, created_at) VALUES (?, ?, ?)').run(id, name, now());
    return get(id);
  }

  function get(id) {
    if (typeof id !== 'string' || !ACCOUNT_ID.test(id)) return null;
    const row = db.prepare('SELECT * FROM accounts WHERE id = ?').get(id);
    return row ? publicView(row) : null;
  }

  function list() {
    return db.prepare('SELECT * FROM accounts ORDER BY created_at, id').all().map(publicView);
  }

  function rename(id, name) {
    checkName(name);
    return db.prepare('UPDATE accounts SET name = ? WHERE id = ?').run(name, checkAccountId(id)).changes === 1;
  }

  function isPaused(id) {
    return db.prepare('SELECT sending_paused FROM accounts WHERE id = ?').get(checkAccountId(id))?.sending_paused === 1;
  }

  function setPaused(id, paused) {
    db.prepare('UPDATE accounts SET sending_paused = ? WHERE id = ?').run(paused ? 1 : 0, checkAccountId(id));
  }

  // Random WebAuthn user handle per account, created on first use. Passkeys of different
  // accounts therefore never share a user handle on the device.
  function webauthnUserId(id) {
    checkAccountId(id);
    let value = db.prepare('SELECT webauthn_user_id FROM accounts WHERE id = ?').get(id)?.webauthn_user_id;
    if (!value) {
      value = crypto.randomBytes(32).toString('base64url');
      db.prepare('UPDATE accounts SET webauthn_user_id = ? WHERE id = ? AND webauthn_user_id IS NULL').run(value, id);
      value = db.prepare('SELECT webauthn_user_id FROM accounts WHERE id = ?').get(id).webauthn_user_id;
    }
    return value;
  }

  // Deletes an account and everything that belongs to it. The default account cannot be
  // removed: it is the one a self-hosted installation and the CLI use.
  function remove(id) {
    checkAccountId(id);
    if (id === DEFAULT_ACCOUNT) return 'default';
    return transaction(db, () => {
      if (!db.prepare('SELECT 1 FROM accounts WHERE id = ?').get(id)) return 'missing';
      // Sessions go with their passkeys (foreign key ON DELETE CASCADE).
      for (const table of ['passkeys', 'enrollment_tokens', 'api_keys', 'devices', 'deliveries', 'audit_events']) {
        db.prepare(`DELETE FROM ${table} WHERE account_id = ?`).run(id);
      }
      db.prepare('DELETE FROM accounts WHERE id = ?').run(id);
      return 'ok';
    });
  }

  return { create, get, list, rename, isPaused, setPaused, webauthnUserId, remove };
}
