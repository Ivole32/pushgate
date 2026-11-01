// Minimal security audit trail. Details must never contain secrets or notification content.
// Events belong to an account, or to none when they happen before anyone is identified
// (rejected networks, unknown keys, failed sign-ins); those are shown only in single-account mode.
import { checkAccountId } from './accounts.js';
import { clientKey } from './netacl.js';
import { createRateLimiter } from './ratelimit.js';

const MAX_TRACKED = 10000;
// Rows per minute that throttled events may add, per account and once more for the
// unattributed ones. Per-client throttling alone does not bound the table: one IPv6 allocation
// holds many /64s, and a botnet many IPv4 addresses. Separate budgets keep a flood of anonymous
// rejections, or one account's events, from hiding another account's.
const ANONYMOUS_ROWS_PER_MINUTE = 60;

export function createAudit(db, log, { now = () => Date.now() } = {}) {
  // Events of an account removed meanwhile (a request still in flight) are only logged.
  const insert = db.prepare(`INSERT INTO audit_events (ts, type, account_id, actor, ip, detail)
                             SELECT ?, ?, ?3, ?, ?, ? WHERE ?3 IS NULL OR EXISTS (SELECT 1 FROM accounts WHERE id = ?3)`);
  // Rejections can be triggered by anyone on the network, so persisting them is throttled
  // per (type, client) and in total, to keep a flood from growing the database. Every
  // rejection is still logged, and the number of unpersisted ones is recorded once the flood
  // subsides.
  const lastWrite = new Map();
  const budget = createRateLimiter(ANONYMOUS_ROWS_PER_MINUTE, { now });
  // Unpersisted events per account ('' for unattributed ones).
  const suppressed = new Map();

  function record(type, { accountId = null, actor = 'system', ip = null, detail = {} } = {}) {
    insert.run(now(), type, accountId, actor, ip, JSON.stringify(detail));
    log.info('audit', { event: type, account: accountId, actor, ip, ...detail });
  }

  function recordThrottled(type, { accountId = null, actor = 'anonymous', ip = null, detail = {} } = {}) {
    const scope = accountId ?? '';
    const key = `${scope}|${type}|${ip === null ? '' : clientKey(ip)}`;
    const t = now();
    if ((lastWrite.get(key) ?? 0) > t - 60000 || budget.take(scope)) {
      suppressed.set(scope, (suppressed.get(scope) ?? 0) + 1);
      log.info('audit', { event: type, account: accountId, actor, ip, persisted: false, ...detail });
      return;
    }
    // Bounded, oldest first (re-inserting moves a key to the end of the Map's order).
    if (lastWrite.size >= MAX_TRACKED) {
      let n = MAX_TRACKED / 10;
      for (const k of lastWrite.keys()) {
        lastWrite.delete(k);
        if (--n === 0) break;
      }
    }
    lastWrite.delete(key);
    lastWrite.set(key, t);
    const count = suppressed.get(scope);
    if (count) {
      record('audit.suppressed', { accountId, detail: { count } });
      suppressed.delete(scope);
    }
    record(type, { accountId, actor, ip, detail });
  }

  // Events of one account, plus the unattributed ones if `includeUnattributed`.
  function list(accountId, { limit = 100, before = null, includeUnattributed = false } = {}) {
    checkAccountId(accountId);
    const scope = includeUnattributed ? '(account_id = ? OR account_id IS NULL)' : 'account_id = ?';
    const rows = before
      ? db.prepare(`SELECT * FROM audit_events WHERE ${scope} AND id < ? ORDER BY id DESC LIMIT ?`).all(accountId, before, limit)
      : db.prepare(`SELECT * FROM audit_events WHERE ${scope} ORDER BY id DESC LIMIT ?`).all(accountId, limit);
    return rows.map((r) => ({ id: r.id, ts: r.ts, type: r.type, actor: r.actor, ip: r.ip, detail: JSON.parse(r.detail) }));
  }

  return { record, recordThrottled, list };
}
