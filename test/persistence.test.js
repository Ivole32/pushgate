import assert from 'node:assert/strict';
import path from 'node:path';
import { test } from 'node:test';
import { backupDatabase, openDatabase, purgeExpired } from '../src/db.js';
import { addDevice, notify, startApp, tempDir } from './helpers.js';

test('keys, devices, revocations and settings survive a restart', async () => {
  const dir = tempDir();
  const first = await startApp({ dir });
  addDevice(first);
  const { key } = first.ctx.keys.create('default', { name: 'svc' });
  const { key: revokedKey, record } = first.ctx.keys.create('default', { name: 'gone' });
  first.ctx.keys.revoke('default', record.id);
  assert.equal((await notify(first, key)).status, 200);
  await first.close();

  const second = await startApp({ dir, secrets: first.secrets });
  assert.equal((await notify(second, key)).status, 200);
  assert.equal((await notify(second, revokedKey)).status, 401);
  assert.equal(second.ctx.devices.list('default').length, 1);
  assert.equal(second.push.calls.length, 1);
  await second.close();
});

test('a different pepper invalidates every stored key (pepper is required to verify)', async () => {
  const dir = tempDir();
  const first = await startApp({ dir });
  const { key } = first.ctx.keys.create('default', { name: 'svc' });
  await first.close();
  const other = await startApp({ dir: dir }); // writes fresh secrets into the same dir
  assert.equal((await notify(other, key)).status, 401);
  await other.close();
});

test('online backup produces a usable copy; retention purges old metadata', async () => {
  const t = await startApp();
  const { record } = t.ctx.keys.create('default', { name: 'svc' });
  t.db.prepare("INSERT INTO deliveries (id, key_id, priority, created_at, status, targeted, delivered, failed, removed) VALUES ('old', NULL, 'low', 0, 'delivered', 1, 1, 0, 0)").run();
  t.db.prepare("INSERT INTO audit_events (ts, type, actor) VALUES (0, 'ancient', 'x')").run();
  purgeExpired(t.db, t.config);
  assert.equal(t.db.prepare("SELECT COUNT(*) AS n FROM deliveries WHERE id = 'old'").get().n, 0);
  assert.equal(t.db.prepare("SELECT COUNT(*) AS n FROM audit_events WHERE type = 'ancient'").get().n, 0);

  const target = path.join(tempDir(), 'backup.db');
  backupDatabase(t.db, target);
  assert.throws(() => backupDatabase(t.db, target), /exists/);
  await t.close();

  const restoredDir = path.dirname(target);
  const fs = await import('node:fs');
  fs.renameSync(target, path.join(restoredDir, 'pushgate.db'));
  const db = openDatabase(restoredDir);
  assert.equal(db.prepare('SELECT name FROM api_keys WHERE id = ?').get(record.id).name, 'svc');
  db.close();
});
