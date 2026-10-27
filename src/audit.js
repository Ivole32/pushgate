// Minimal security audit trail. Details must never contain secrets or notification content.

export function createAudit(db, log, { now = () => Date.now() } = {}) {
  const insert = db.prepare('INSERT INTO audit_events (ts, type, actor, ip, detail) VALUES (?, ?, ?, ?, ?)');
  // Rejections can be triggered by anyone on the network, so persisting them is throttled
  // per (type, ip) to keep a flood from growing the database. Every rejection is still logged.
  const lastWrite = new Map();

  function record(type, { actor = 'system', ip = null, detail = {} } = {}) {
    insert.run(now(), type, actor, ip, JSON.stringify(detail));
    log.info('audit', { event: type, actor, ip, ...detail });
  }

  function recordThrottled(type, { actor = 'anonymous', ip = null, detail = {} } = {}) {
    const key = `${type}|${ip}`;
    const t = now();
    if ((lastWrite.get(key) ?? 0) > t - 60000) {
      log.info('audit', { event: type, actor, ip, persisted: false, ...detail });
      return;
    }
    if (lastWrite.size > 10000) lastWrite.clear();
    lastWrite.set(key, t);
    record(type, { actor, ip, detail });
  }

  function list({ limit = 100, before = null } = {}) {
    const rows = before
      ? db.prepare('SELECT * FROM audit_events WHERE id < ? ORDER BY id DESC LIMIT ?').all(before, limit)
      : db.prepare('SELECT * FROM audit_events ORDER BY id DESC LIMIT ?').all(limit);
    return rows.map((r) => ({ id: r.id, ts: r.ts, type: r.type, actor: r.actor, ip: r.ip, detail: JSON.parse(r.detail) }));
  }

  return { record, recordThrottled, list };
}
