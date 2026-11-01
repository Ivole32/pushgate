// POST /api/v1/notifications — the only endpoint that accepts service API keys. The key's
// account decides which devices receive the notification.
import { SCOPES } from './apikeys.js';
import { HttpError, errors, readJson, sendJson } from './http.js';
import { safeError } from './log.js';
import { clientKey } from './netacl.js';
import { DEFAULT_TTL } from './push.js';
import { schemas, validate } from './validate.js';

export const NOTIFICATION_BODY_LIMIT = 8192;

export function createNotifyHandler({ config, log, accounts, keys, auth, pusher, audit, limits, hooks }) {
  return async function handleNotify(req, res, client) {
    const ip = client.ip;
    const who = clientKey(ip);

    // 1. API key. All failure reasons produce the same response.
    const header = req.headers.authorization;
    const match = typeof header === 'string' ? /^Bearer ([^\s]{1,200})$/.exec(header) : null;
    const result = match ? keys.verify(match[1]) : { ok: false, reason: 'missing', keyId: null };
    if (!result.ok) {
      // 2. Clients that failed too often get 429 for further failures, which are not counted.
      // The block applies only to failures: senders behind the same NAT, /64 or host would
      // otherwise lose their alerts to one neighbour's bad requests. Guessing stays hopeless
      // (256-bit keys), and the block still marks the client in the security events.
      const blocked = limits.apiFailures.blockedFor(who);
      if (blocked) {
        audit.recordThrottled('auth.blocked', { ip, detail: { zone: 'api', key_id: result.keyId } });
        throw errors.rateLimited(blocked);
      }
      const nowBlocked = limits.apiFailures.fail(who);
      // A revoked or expired key (the full secret matched) is shown to its account: someone
      // still uses it.
      audit.recordThrottled('auth.failed', {
        accountId: result.accountId ?? null,
        ...(result.accountId ? { actor: `key:${result.keyId}` } : {}),
        ip,
        detail: { reason: result.reason, key_id: result.keyId, blocked: nowBlocked },
      });
      throw errors.unauthorized();
    }
    const key = result.key;
    const accountId = key.account_id;
    if (limits.apiFailures.blockedFor(who)) {
      audit.recordThrottled('auth.valid_key_while_blocked', { accountId, actor: `key:${key.id}`, ip });
    }
    if (!key.scopes.includes(SCOPES.SEND)) {
      audit.recordThrottled('auth.forbidden_scope', { accountId, actor: `key:${key.id}`, ip, detail: { scope: SCOPES.SEND } });
      throw new HttpError(403, 'insufficient_scope', 'This key may not send notifications');
    }
    // Failures are deliberately not reset on success: holding one valid key must not allow
    // unlimited guessing of other keys from the same host.

    // 3. Per-key rate limit.
    const waitKey = limits.perKey.take(key.id);
    if (waitKey) {
      audit.recordThrottled('rate_limited', { accountId, actor: `key:${key.id}`, ip, detail: { limit: 'key' } });
      throw errors.rateLimited(waitKey);
    }

    // 4. Kill switches.
    if (!config.notificationsEnabled) throw errors.unavailable('Notification sending is disabled');
    if (config.requireSetupBeforeSending && !auth.hasAdmin(accountId)) throw errors.unavailable('Initial setup is not complete');
    if (accounts.isPaused(accountId)) throw errors.unavailable('Notification sending is paused');

    // 5. Only now read and validate the body.
    const body = await readJson(req, NOTIFICATION_BODY_LIMIT);
    const problems = validate(body, schemas.notification);
    if (problems.length) throw errors.badRequest('validation_failed', 'Request body is invalid', { details: problems });
    const priority = body.priority ?? 'normal';
    if (priority === 'high' && !key.scopes.includes(SCOPES.SEND_HIGH)) {
      throw new HttpError(403, 'insufficient_scope', 'This key may not send high priority notifications');
    }
    const ttl = body.ttl ?? DEFAULT_TTL;
    // The account may have been removed while the body was read.
    const account = accounts.get(accountId);
    if (!account) throw errors.unauthorized();

    // 6. Account and global rate limits, taken only for notifications that will be sent: paused
    // accounts and invalid requests do not use up the budget shared with other accounts.
    for (const [limit, bucket, id] of [['account', limits.perAccount, accountId], ['global', limits.global, 'global']]) {
      const wait = bucket.take(id);
      if (wait) {
        audit.recordThrottled('rate_limited', { accountId, actor: `key:${key.id}`, ip, detail: { limit } });
        throw errors.rateLimited(wait);
      }
    }

    // 7. Plugin checks (e.g. quotas). They may only refuse: an HttpError is the response, any
    // other error a 500. Either way nothing is sent. Hooks never see title or message.
    for (const { fn } of hooks.beforeSend) await fn({ account, key, client, notification: { priority, ttl } });

    const outcome = await pusher.deliver({
      accountId,
      keyId: key.id,
      title: body.title,
      message: body.message,
      priority,
      tag: body.tag ?? null,
      tagScope: keys.lineage(key.id),
      ttl,
      service: key.name,
    });
    if (outcome.error === 'payload_too_large') {
      throw new HttpError(413, 'payload_too_large', 'Notification exceeds the Web Push payload limit; shorten title or message');
    }
    // 8. Plugin follow-ups (e.g. metering). The notification is out already, so a failing hook
    // is logged and does not change the response (an error would make the sender send again).
    for (const { plugin, fn } of hooks.afterDelivery) {
      try {
        await fn({ account, key, client, outcome });
      } catch (err) {
        log.error('plugin afterDelivery hook failed', { plugin, ...safeError(err) });
      }
    }
    sendJson(res, outcome.status === 'failed' ? 502 : 200, outcome);
  };
}
