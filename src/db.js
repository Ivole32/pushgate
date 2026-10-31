// SQLite storage: connection setup, schema migrations, retention purge and online backup.
import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';

export const MIGRATIONS = [
  `
  CREATE TABLE api_keys (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    key_hash      TEXT NOT NULL,
    scopes        TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER,
    revoked_at    INTEGER,
    last_used_at  INTEGER,
    rotated_from  TEXT
  );
  CREATE TABLE passkeys (
    id            TEXT PRIMARY KEY,
    public_key    BLOB NOT NULL,
    counter       INTEGER NOT NULL DEFAULT 0,
    transports    TEXT NOT NULL DEFAULT '[]',
    name          TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    last_used_at  INTEGER
  );
  CREATE TABLE enrollment_tokens (
    token_hash    TEXT PRIMARY KEY,
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL,
    used_at       INTEGER
  );
  CREATE TABLE sessions (
    token_hash    TEXT PRIMARY KEY,
    csrf_token    TEXT NOT NULL,
    passkey_id    TEXT NOT NULL REFERENCES passkeys(id) ON DELETE CASCADE,
    created_at    INTEGER NOT NULL,
    last_seen_at  INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL
  );
  CREATE TABLE devices (
    id               TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    endpoint         TEXT NOT NULL UNIQUE,
    p256dh           TEXT NOT NULL,
    auth             TEXT NOT NULL,
    min_priority     TEXT NOT NULL DEFAULT 'low',
    created_at       INTEGER NOT NULL,
    last_success_at  INTEGER,
    last_failure_at  INTEGER,
    last_status      INTEGER,
    failure_count    INTEGER NOT NULL DEFAULT 0
  );
  CREATE TABLE deliveries (
    id          TEXT PRIMARY KEY,
    key_id      TEXT,
    priority    TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    status      TEXT NOT NULL,
    targeted    INTEGER NOT NULL,
    delivered   INTEGER NOT NULL,
    failed      INTEGER NOT NULL,
    removed     INTEGER NOT NULL
  );
  CREATE INDEX deliveries_created ON deliveries(created_at);
  CREATE TABLE audit_events (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      INTEGER NOT NULL,
    type    TEXT NOT NULL,
    actor   TEXT NOT NULL,
    ip      TEXT,
    detail  TEXT NOT NULL DEFAULT '{}'
  );
  CREATE INDEX audit_events_ts ON audit_events(ts);
  CREATE TABLE settings (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
  );
  `,
  // When the session holder last proved presence with a passkey (sign-in or re-confirmation).
  // Sensitive changes require this to be recent. Existing sessions count as not verified.
  `
  ALTER TABLE sessions ADD COLUMN verified_at INTEGER NOT NULL DEFAULT 0;
  `,
  // Accounts. Everything that existed before belongs to the account "default", which also takes
  // over the former global pause switch and WebAuthn user handle. New rows always name their
  // account explicitly; the column defaults only fill existing rows. (SQLite cannot add a
  // foreign key column with a non-NULL default, so account removal deletes rows in code.)
  `
  CREATE TABLE accounts (
    id                TEXT PRIMARY KEY,
    name              TEXT NOT NULL,
    webauthn_user_id  TEXT,
    sending_paused    INTEGER NOT NULL DEFAULT 0,
    created_at        INTEGER NOT NULL
  );
  INSERT INTO accounts (id, name, webauthn_user_id, sending_paused, created_at) VALUES (
    'default', 'default',
    (SELECT value FROM settings WHERE key = 'webauthn_user_id'),
    COALESCE((SELECT value = 'true' FROM settings WHERE key = 'sending_paused'), 0),
    CAST(strftime('%s', 'now') AS INTEGER) * 1000
  );
  DELETE FROM settings WHERE key IN ('webauthn_user_id', 'sending_paused');
  ALTER TABLE api_keys ADD COLUMN account_id TEXT NOT NULL DEFAULT 'default';
  ALTER TABLE passkeys ADD COLUMN account_id TEXT NOT NULL DEFAULT 'default';
  ALTER TABLE enrollment_tokens ADD COLUMN account_id TEXT NOT NULL DEFAULT 'default';
  ALTER TABLE devices ADD COLUMN account_id TEXT NOT NULL DEFAULT 'default';
  ALTER TABLE deliveries ADD COLUMN account_id TEXT NOT NULL DEFAULT 'default';
  ALTER TABLE audit_events ADD COLUMN account_id TEXT;
  UPDATE audit_events SET account_id = 'default';
  CREATE INDEX api_keys_account ON api_keys(account_id);
  CREATE INDEX passkeys_account ON passkeys(account_id);
  CREATE INDEX devices_account ON devices(account_id);
  CREATE INDEX deliveries_account ON deliveries(account_id, created_at);
  CREATE INDEX audit_events_account ON audit_events(account_id, id);
  `,
];

export function openDatabase(dataDir) {
  fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  const file = path.join(dataDir, 'pushgate.db');
  const db = new DatabaseSync(file);
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = NORMAL;
    PRAGMA foreign_keys = ON;
    PRAGMA busy_timeout = 5000;
    PRAGMA temp_store = MEMORY;
    PRAGMA secure_delete = ON;
  `);
  try {
    fs.chmodSync(file, 0o600);
  } catch {
    // Not supported on every filesystem (e.g. some Windows mounts); permissions of the volume apply.
  }
  migrate(db);
  return db;
}

function migrate(db) {
  db.exec('CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)');
  const current = db.prepare('SELECT COALESCE(MAX(version), 0) AS v FROM schema_migrations').get().v;
  for (let i = current; i < MIGRATIONS.length; i++) {
    transaction(db, () => {
      db.exec(MIGRATIONS[i]);
      db.prepare('INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)').run(i + 1, Date.now());
    });
  }
}

// Plugin tables are migrated after the core schema, tracked per plugin, each step in its own
// transaction. Steps are append-only, exactly like MIGRATIONS above.
export function migratePlugins(db, pluginMigrations) {
  if (!pluginMigrations.length) return;
  db.exec(`CREATE TABLE IF NOT EXISTS plugin_migrations (
    plugin TEXT NOT NULL, version INTEGER NOT NULL, applied_at INTEGER NOT NULL, PRIMARY KEY (plugin, version))`);
  for (const { plugin, steps } of pluginMigrations) {
    const current = db.prepare('SELECT COALESCE(MAX(version), 0) AS v FROM plugin_migrations WHERE plugin = ?').get(plugin).v;
    for (let i = current; i < steps.length; i++) {
      transaction(db, () => {
        db.exec(steps[i]);
        db.prepare('INSERT INTO plugin_migrations (plugin, version, applied_at) VALUES (?, ?, ?)').run(plugin, i + 1, Date.now());
      });
    }
  }
}

export function transaction(db, fn) {
  db.exec('BEGIN IMMEDIATE');
  try {
    const result = fn();
    db.exec('COMMIT');
    return result;
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

export function getSetting(db, key, def = null) {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
  return row ? row.value : def;
}

export function setSetting(db, key, value) {
  db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value')
    .run(key, String(value));
}

// Removes data past its retention period. Safe to call repeatedly.
export function purgeExpired(db, config, now = Date.now()) {
  const day = 86400000;
  db.prepare('DELETE FROM deliveries WHERE created_at < ?').run(now - config.historyRetentionDays * day);
  db.prepare('DELETE FROM audit_events WHERE ts < ?').run(now - config.auditRetentionDays * day);
  db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(now);
  db.prepare('DELETE FROM enrollment_tokens WHERE expires_at < ?').run(now - day);
}

// Consistent online backup via VACUUM INTO. The target must not exist.
export function backupDatabase(db, target) {
  if (fs.existsSync(target)) throw new Error('backup target already exists');
  db.prepare('VACUUM INTO ?').run(target);
  try {
    fs.chmodSync(target, 0o600);
  } catch {
    // see openDatabase
  }
}
