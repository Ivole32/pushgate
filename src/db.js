// SQLite storage: connection setup, schema migrations, retention purge and online backup.
import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';

const MIGRATIONS = [
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
