// Admin JSON API used by the PWA. Every route except session bootstrap and login/enrollment
// requires a passkey session; every state-changing route requires a same-origin request
// and the per-session CSRF token. Routes marked `fresh` additionally need a recent passkey
// confirmation, and security-relevant changes are pushed to every registered device.
// Every route acts only on the account of the session's passkey.
import crypto from 'node:crypto';
import { SCOPES, isValidKeyId } from '../apikeys.js';
import { DEFAULT_ACCOUNT } from '../accounts.js';
import { checkSubscription } from '../devices.js';
import { safeError } from '../log.js';
import { clientKey } from '../netacl.js';
import { HttpError, errors, readJson, sendResult } from '../http.js';
import { schemas, validate } from '../validate.js';
import { PASSKEY_ID, SESSION_COOKIE, readCookie, sessionCookie } from './auth.js';

const ADMIN_BODY_LIMIT = 16384;
const DEVICE_ID = /^[A-Za-z0-9_-]{22}$/;
// The database integrity check reads the whole file; its result is reused for this long.
const HEALTH_CHECK_INTERVAL_MS = 10 * 60 * 1000;

function safeEqual(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

async function body(req, schema) {
  const data = await readJson(req, ADMIN_BODY_LIMIT);
  const problems = validate(data, schema);
  if (problems.length) throw errors.badRequest('validation_failed', 'Request body is invalid', { details: problems });
  return data;
}

export function createAdminRoutes({ config, db, log, accounts, keys, devices, pusher, auth, audit, limits, features, web, multiAccount, version, startedAt }) {
  const sessionMaxAge = config.sessionMaxHours * 3600;

  // Administrators of hosted accounts have no shell on the server.
  const notYou = multiAccount
    ? 'Not you? Sign in, choose "Sign out other sessions", remove passkeys you do not recognise and review Security events.'
    : 'Not you? Sign in and choose "Sign out other sessions" (or on the server run "cli.js sessions revoke-all"), then review Security events.';

  // Out-of-band alert to every device of the account, so a change made with a stolen session
  // does not go unnoticed. High priority passes every device filter and the pause switch does
  // not apply. Not awaited: the admin request must not wait for push services.
  function securityAlert(accountId, title, message, client) {
    pusher.deliver({
      accountId,
      title,
      message: `${message}\nFrom ${client.ip}. ${notYou}`,
      priority: 'high',
      service: 'pushgate',
      ttl: 86400,
    }).catch((err) => log.error('security alert failed', safeError(err)));
  }

  // Origin/Fetch-Metadata check for every state-changing admin request (CSRF defence in
  // depth; SameSite=Strict cookies are the first layer, the CSRF token the third).
  function requireSameOrigin(req) {
    if (req.headers.origin !== config.publicOrigin) throw errors.forbidden();
    const site = req.headers['sec-fetch-site'];
    if (site !== undefined && site !== 'same-origin') throw errors.forbidden();
  }

  function requireSession(req, client) {
    const session = auth.getSession(readCookie(req, SESSION_COOKIE));
    if (!session) throw errors.unauthorized();
    if (req.method !== 'GET' && !safeEqual(req.headers['x-csrf-token'] ?? '', session.csrf)) {
      audit.recordThrottled('admin.csrf_rejected', { accountId: session.accountId, ip: client.ip });
      throw errors.forbidden();
    }
    return session;
  }

  function checkBlocked(ip) {
    const blocked = limits.adminFailures.blockedFor(clientKey(ip));
    if (blocked) {
      audit.recordThrottled('auth.blocked', { ip, detail: { zone: 'admin' } });
      throw errors.rateLimited(blocked);
    }
  }

  // Database health for the overview, computed at most every HEALTH_CHECK_INTERVAL_MS: the check
  // blocks the process while it reads the database, so it must not run on every request.
  let health = { at: -Infinity, value: 'ok' };
  function databaseHealth() {
    const t = Date.now();
    if (t - health.at >= HEALTH_CHECK_INTERVAL_MS) {
      health = { at: t, value: db.prepare('PRAGMA quick_check').get().quick_check === 'ok' ? 'ok' : 'error' };
    }
    return health.value;
  }

  // Test notifications go through the same per-account and global budgets as sent ones.
  function takeSendBudget(accountId) {
    for (const [bucket, id] of [[limits.perAccount, accountId], [limits.global, 'global']]) {
      const wait = bucket.take(id);
      if (wait) throw errors.rateLimited(wait);
    }
  }

  function challengeResponse(result) {
    return { challenge_id: result.challengeId, options: result.options };
  }

  // A stale or unknown challenge is not a credential failure and is not counted toward the
  // brute-force block (otherwise someone else's challenge flood could lock the admin out).
  // While a client is blocked, further failures are refused with 429 and not counted.
  function verifyFailed(result, ip, event) {
    if (result.error === 'challenge') throw errors.badRequest('challenge_expired', 'Challenge expired or unknown; start again');
    checkBlocked(ip);
    limits.adminFailures.fail(clientKey(ip));
    audit.recordThrottled(event, { ip, detail: { reason: 'verification_failed' } });
    throw errors.unauthorized();
  }

  function startSession(res, passkeyId) {
    const s = auth.createSession(passkeyId);
    res.setHeader('Set-Cookie', sessionCookie(s.token, sessionMaxAge));
    return s;
  }

  // Routes: [method, regex, handler(ctx)]; `auth: false` routes run without a session.
  const routes = [
    ['GET', /^\/admin\/api\/session$/, { auth: false }, ({ req }) => {
      const session = auth.getSession(readCookie(req, SESSION_COOKIE));
      // With several accounts, signing in is always offered: the passkey picks the account.
      const common = { accounts: multiAccount ? 'multiple' : 'single', features, web };
      const account = session && accounts.get(session.accountId);
      if (!account) return { authenticated: false, setup_complete: multiAccount || auth.hasAdmin(DEFAULT_ACCOUNT), ...common };
      return {
        authenticated: true, setup_complete: true, csrf_token: session.csrf, expires_at: session.expiresAt,
        account: { id: account.id, name: account.name }, ...common,
      };
    }],

    // ---- first administrator / recovery enrollment (one-time token from the CLI) ----
    ['POST', /^\/admin\/api\/enroll\/options$/, { auth: false }, async ({ req, client }) => {
      checkBlocked(client.ip);
      const { token } = await body(req, schemas.enrollOptions);
      const accountId = auth.enrollmentTokenAccount(token);
      if (!accountId) {
        limits.adminFailures.fail(clientKey(client.ip));
        audit.recordThrottled('admin.enroll_failed', { ip: client.ip, detail: { reason: 'invalid_token' } });
        throw errors.unauthorized();
      }
      return challengeResponse(await auth.registrationOptions('enroll', accountId));
    }],
    ['POST', /^\/admin\/api\/enroll\/verify$/, { auth: false }, async ({ req, res, client }) => {
      checkBlocked(client.ip);
      const data = await body(req, schemas.enrollVerify);
      const accountId = auth.enrollmentTokenAccount(data.token);
      const result = accountId
        ? await auth.verifyRegistration({ kind: 'enroll', accountId, challengeId: data.challenge_id, response: data.response, name: data.name, token: data.token })
        : { error: 'invalid' };
      if (!result.id) verifyFailed(result, client.ip, 'admin.enroll_failed');
      audit.record('admin.passkey_enrolled', { accountId, actor: 'enrollment-token', ip: client.ip, detail: { passkey: data.name } });
      securityAlert(accountId, 'Passkey enrolled', `Passkey "${data.name}" was enrolled with an enrollment token; all other sessions were signed out.`, client);
      const s = startSession(res, result.id);
      return { ok: true, csrf_token: s.csrf };
    }],

    // ---- login ----
    // A block after failed sign-ins never refuses a valid passkey: anyone sharing the
    // administrator's address (NAT, the same /64) could otherwise lock them out at will.
    // Passkeys cannot be guessed; the block limits the noise and marks the client in the events.
    ['POST', /^\/admin\/api\/login\/options$/, { auth: false }, async () => challengeResponse(await auth.authenticationOptions())],
    ['POST', /^\/admin\/api\/login\/verify$/, { auth: false }, async ({ req, res, client }) => {
      const data = await body(req, schemas.loginVerify);
      const result = await auth.verifyAuthentication({ challengeId: data.challenge_id, response: data.response });
      if (!result.id) verifyFailed(result, client.ip, 'admin.login_failed');
      limits.adminFailures.reset(clientKey(client.ip));
      audit.record('admin.login', { accountId: result.accountId, actor: `passkey:${result.id.slice(0, 12)}`, ip: client.ip });
      securityAlert(result.accountId, 'Admin sign-in', 'Someone signed in to Pushgate with a passkey.', client);
      const s = startSession(res, result.id);
      return { ok: true, csrf_token: s.csrf };
    }],
    // Re-confirmation with a passkey for `fresh` routes, without starting a new session. The
    // challenge is bound to the session that asked for it.
    ['POST', /^\/admin\/api\/reauth\/options$/, {}, async ({ session }) => challengeResponse(await auth.authenticationOptions('reauth', session.hash))],
    ['POST', /^\/admin\/api\/reauth\/verify$/, {}, async ({ req, session, client }) => {
      const data = await body(req, schemas.loginVerify);
      const result = await auth.verifyAuthentication({ kind: 'reauth', challengeId: data.challenge_id, response: data.response, sessionHash: session.hash });
      // Only a passkey of the session's own account can confirm its changes.
      if (!result.id || result.accountId !== session.accountId) throw errors.badRequest('verification_failed', 'Passkey confirmation failed');
      auth.markVerified(session.hash);
      audit.record('admin.reverified', { accountId: session.accountId, actor: 'admin', ip: client.ip });
      return { ok: true };
    }],
    ['POST', /^\/admin\/api\/logout$/, {}, ({ res, session, client }) => {
      auth.destroySession(session.hash);
      res.setHeader('Set-Cookie', sessionCookie('', 0));
      audit.record('admin.logout', { accountId: session.accountId, actor: 'admin', ip: client.ip });
      return { ok: true };
    }],
    // Signs out every other session of the account, e.g. one opened with a stolen cookie.
    ['POST', /^\/admin\/api\/sessions\/revoke-others$/, { fresh: true }, ({ session, client }) => {
      const revoked = auth.revokeAllSessions(session.accountId, { except: session.hash });
      audit.record('admin.sessions_revoked', { accountId: session.accountId, actor: 'admin', ip: client.ip, detail: { count: revoked } });
      securityAlert(session.accountId, 'Other sessions signed out', `${revoked} other session(s) of this account were signed out.`, client);
      return { revoked };
    }],

    // ---- overview / health ----
    ['GET', /^\/admin\/api\/overview$/, {}, ({ client, session }) => {
      const recent = db.prepare(`SELECT d.id, d.key_id, k.name AS service, d.priority, d.created_at, d.status,
                                        d.targeted, d.delivered, d.failed, d.removed
                                 FROM deliveries d LEFT JOIN api_keys k ON k.id = d.key_id AND k.account_id = d.account_id
                                 WHERE d.account_id = ?
                                 ORDER BY d.created_at DESC LIMIT 20`).all(session.accountId);
      return {
        version,
        uptime_seconds: Math.floor((Date.now() - startedAt) / 1000),
        database: databaseHealth(),
        notifications_enabled: config.notificationsEnabled,
        sending_paused: accounts.isPaused(session.accountId),
        active_keys: keys.list(session.accountId).filter((k) => k.status === 'active').length,
        devices: devices.count(session.accountId),
        your_ip: client.ip,
        via_proxy: client.viaProxy,
        vapid_public_key: config.vapid.publicKey,
        history_retention_days: config.historyRetentionDays,
        recent_deliveries: recent,
      };
    }],
    ['PUT', /^\/admin\/api\/settings$/, {}, async ({ req, client, session }) => {
      const data = await body(req, schemas.settings);
      accounts.setPaused(session.accountId, data.sending_paused);
      audit.record('settings.changed', { accountId: session.accountId, actor: 'admin', ip: client.ip, detail: { sending_paused: data.sending_paused } });
      securityAlert(session.accountId, data.sending_paused ? 'Sending paused' : 'Sending resumed',
        data.sending_paused ? 'Notification sending was paused: services can no longer reach your devices.' : 'Notification sending was resumed.', client);
      return { sending_paused: data.sending_paused };
    }],
    ['GET', /^\/admin\/api\/events$/, {}, ({ url, session }) => {
      const before = url.searchParams.get('before');
      return { events: auditList(session.accountId, before) };
    }],

    // ---- service API keys ----
    ['GET', /^\/admin\/api\/keys$/, {}, ({ session }) => ({ keys: keys.list(session.accountId) })],
    ['POST', /^\/admin\/api\/keys$/, { fresh: true }, async ({ req, client, session }) => {
      const data = await body(req, schemas.createKey);
      if (data.expires_at != null && data.expires_at <= Date.now()) {
        throw errors.badRequest('validation_failed', 'Request body is invalid', { details: [{ field: 'expires_at', issue: 'must be in the future' }] });
      }
      if (keys.list(session.accountId).filter((k) => k.status === 'active').length >= config.maxApiKeys) {
        throw new HttpError(409, 'key_limit', 'Maximum number of active API keys reached; revoke one first');
      }
      const scopes = data.allow_high_priority ? [SCOPES.SEND, SCOPES.SEND_HIGH] : [SCOPES.SEND];
      const { key, record } = keys.create(session.accountId, { name: data.name, description: data.description ?? '', expiresAt: data.expires_at ?? null, scopes });
      audit.record('api_key.created', { accountId: session.accountId, actor: 'admin', ip: client.ip, detail: { key_id: record.id, name: record.name, scopes } });
      securityAlert(session.accountId, 'API key created', `Service API key "${record.name}" (${record.id}) was created.`, client);
      // The full key is returned exactly once and is never stored.
      return { status: 201, body: { key, record } };
    }],
    ['POST', /^\/admin\/api\/keys\/([^/]+)\/revoke$/, {}, ({ params, client, session }) => {
      if (!isValidKeyId(params[0]) || !keys.revoke(session.accountId, params[0])) throw errors.notFound();
      audit.record('api_key.revoked', { accountId: session.accountId, actor: 'admin', ip: client.ip, detail: { key_id: params[0] } });
      const record = keys.get(session.accountId, params[0]);
      securityAlert(session.accountId, 'API key revoked', `Service API key "${record.name}" (${record.id}) was revoked and can no longer send.`, client);
      return { record };
    }],
    ['POST', /^\/admin\/api\/keys\/([^/]+)\/rotate$/, { fresh: true }, async ({ req, params, client, session }) => {
      const data = await body(req, schemas.rotateKey);
      const rotated = isValidKeyId(params[0]) ? keys.rotate(session.accountId, params[0], { graceSeconds: (data.grace_hours ?? 0) * 3600 }) : null;
      if (!rotated) {
        const existing = isValidKeyId(params[0]) ? keys.get(session.accountId, params[0]) : null;
        if (existing?.status === 'active') throw new HttpError(409, 'already_rotated', 'This key was already rotated; rotate its replacement instead');
        throw errors.notFound();
      }
      audit.record('api_key.rotated', { accountId: session.accountId, actor: 'admin', ip: client.ip, detail: { old_key_id: params[0], new_key_id: rotated.record.id, grace_hours: data.grace_hours ?? 0 } });
      securityAlert(session.accountId, 'API key rotated', `Service API key "${rotated.record.name}" was rotated (new id ${rotated.record.id}).`, client);
      return { status: 201, body: { key: rotated.key, record: rotated.record, previous: keys.get(session.accountId, params[0]) } };
    }],

    // ---- devices (push subscriptions) ----
    ['GET', /^\/admin\/api\/devices$/, {}, ({ session }) => ({ devices: devices.list(session.accountId), vapid_public_key: config.vapid.publicKey })],
    // A registered device receives every notification, so registering one is a sensitive change.
    ['POST', /^\/admin\/api\/devices$/, { fresh: true }, async ({ req, client, session }) => {
      const data = await body(req, schemas.registerDevice);
      let sub;
      try {
        sub = checkSubscription(data.subscription, config.pushHosts);
      } catch (err) {
        throw errors.badRequest('invalid_subscription', err.message);
      }
      const result = devices.upsert(session.accountId, { name: data.name, minPriority: data.min_priority ?? 'low', ...sub }, config.maxDevices);
      if (!result) throw new HttpError(409, 'device_limit', 'Maximum number of devices reached');
      if (result.conflict) throw new HttpError(409, 'device_in_other_account', 'This device receives notifications for another account; disable it there first');
      audit.record(result.created ? 'device.registered' : 'device.updated', { accountId: session.accountId, actor: 'admin', ip: client.ip, detail: { device: result.device.id, name: data.name } });
      securityAlert(session.accountId, result.created ? 'Device registered' : 'Device subscription replaced',
        `Device "${data.name}" will now receive notifications of priority ${result.device.min_priority} or higher.`, client);
      return { status: result.created ? 201 : 200, body: { device: result.device } };
    }],
    ['PATCH', /^\/admin\/api\/devices\/([^/]+)$/, {}, async ({ req, params, client, session }) => {
      const data = await body(req, schemas.updateDevice);
      const before = DEVICE_ID.test(params[0]) ? devices.get(session.accountId, params[0]) : null;
      if (!before || !devices.update(session.accountId, params[0], { name: data.name, minPriority: data.min_priority })) throw errors.notFound();
      audit.record('device.updated', { accountId: session.accountId, actor: 'admin', ip: client.ip, detail: { device: params[0] } });
      const device = devices.get(session.accountId, params[0]);
      // A raised minimum priority silently drops notifications, so it is reported like removal.
      if (device.min_priority !== before.min_priority) {
        const renamed = device.name !== before.name ? ` (now named "${device.name}")` : '';
        securityAlert(session.accountId, 'Device filter changed', `Device "${before.name}"${renamed} now only receives notifications of priority ${device.min_priority} or higher.`, client);
      }
      return { device };
    }],
    ['DELETE', /^\/admin\/api\/devices\/([^/]+)$/, {}, ({ params, client, session }) => {
      const device = DEVICE_ID.test(params[0]) ? devices.get(session.accountId, params[0]) : null;
      if (!device) throw errors.notFound();
      // Alert first, so the device being removed is told as well (the last one included).
      securityAlert(session.accountId, 'Device removed', `Device "${device.name}" was removed and no longer receives notifications.`, client);
      if (!devices.remove(session.accountId, params[0])) throw errors.notFound();
      audit.record('device.removed', { accountId: session.accountId, actor: 'admin', ip: client.ip, detail: { device: params[0] } });
      return { ok: true };
    }],
    ['POST', /^\/admin\/api\/test-push$/, {}, async ({ req, client, session }) => {
      const data = await body(req, schemas.testPush);
      if (data.device_id && !devices.get(session.accountId, data.device_id)) throw errors.notFound();
      takeSendBudget(session.accountId);
      const outcome = await pusher.deliver({
        accountId: session.accountId,
        title: 'Pushgate test',
        message: `Test notification sent at ${new Date().toISOString()}`,
        priority: 'high',
        service: 'pushgate',
        deviceId: data.device_id ?? null,
        ttl: 300,
      });
      audit.record('push.test', { accountId: session.accountId, actor: 'admin', ip: client.ip, detail: { status: outcome.status, device: data.device_id ?? 'all' } });
      return outcome;
    }],

    // ---- passkeys ----
    ['GET', /^\/admin\/api\/passkeys$/, {}, ({ session }) => ({
      passkeys: auth.listPasskeys(session.accountId).map((p) => ({ ...p, current: p.id === session.passkeyId })),
    })],
    ['POST', /^\/admin\/api\/passkeys\/options$/, { fresh: true }, async ({ session }) => {
      if (auth.listPasskeys(session.accountId).length >= config.maxPasskeys) throw passkeyLimit();
      return challengeResponse(await auth.registrationOptions('add', session.accountId));
    }],
    ['POST', /^\/admin\/api\/passkeys\/verify$/, { fresh: true }, async ({ req, client, session }) => {
      const data = await body(req, schemas.addPasskeyVerify);
      const result = await auth.verifyRegistration({ kind: 'add', accountId: session.accountId, challengeId: data.challenge_id, response: data.response, name: data.name });
      if (result.error === 'limit') throw passkeyLimit();
      if (!result.id) throw errors.badRequest('verification_failed', 'Passkey registration failed');
      audit.record('admin.passkey_added', { accountId: session.accountId, actor: 'admin', ip: client.ip, detail: { passkey: data.name } });
      securityAlert(session.accountId, 'Passkey added', `Passkey "${data.name}" was added to the administrator account.`, client);
      return { status: 201, body: { ok: true } };
    }],
    ['DELETE', /^\/admin\/api\/passkeys\/([^/]+)$/, { fresh: true }, ({ params, client, session }) => {
      if (!PASSKEY_ID.test(params[0])) throw errors.notFound();
      const r = auth.removePasskey(session.accountId, params[0]);
      if (r === 'last') throw new HttpError(409, 'last_passkey', 'Cannot remove the last passkey');
      if (r !== 'ok') throw errors.notFound();
      audit.record('admin.passkey_removed', { accountId: session.accountId, actor: 'admin', ip: client.ip, detail: { passkey: params[0].slice(0, 12) } });
      securityAlert(session.accountId, 'Passkey removed', 'A passkey was removed from the administrator account.', client);
      return { ok: true };
    }],
  ];

  function passkeyLimit() {
    return new HttpError(409, 'passkey_limit', 'Maximum number of passkeys reached; remove one first');
  }

  // Events nobody could be identified for (rejected networks, unknown keys) concern the whole
  // server: only the administrator of a single-account installation sees them.
  function auditList(accountId, before) {
    const b = before && /^\d{1,15}$/.test(before) ? Number(before) : null;
    return audit.list(accountId, { limit: 100, before: b, includeUnattributed: !multiAccount && accountId === DEFAULT_ACCOUNT });
  }

  // Access checks for one route, shared with plugin routes: same-origin for every change
  // (unless a route explicitly accepts cross-site requests), then either the per-client limit
  // for anonymous endpoints or a session with CSRF token, the per-account limit, and a recent
  // passkey if `fresh`. Anonymous plugin routes have their own bucket (`anonymousLimit:
  // 'plugin'`), so sign-ups or webhooks do not use up the administrator's sign-in budget.
  function authorize(req, client, opts) {
    if (req.method !== 'GET' && !opts.crossOrigin) requireSameOrigin(req);
    if (opts.auth === false) {
      // Endpoints anyone can call (session check, login, enrollment) are rate limited per client
      // inside the app, independent of any reverse proxy configuration.
      const plugin = opts.anonymousLimit === 'plugin';
      const wait = (plugin ? limits.pluginAnonymous : limits.adminAnonymous).take(clientKey(client.ip));
      if (wait) {
        audit.recordThrottled('rate_limited', { ip: client.ip, detail: { limit: plugin ? 'plugin_anonymous' : 'admin_anonymous' } });
        throw errors.rateLimited(wait);
      }
      return null;
    }
    const session = requireSession(req, client);
    // Signed-in requests are limited per account: one account must not be able to keep the
    // shared server busy for everyone else.
    const wait = limits.adminSession.take(session.accountId);
    if (wait) {
      audit.recordThrottled('rate_limited', { accountId: session.accountId, actor: 'admin', ip: client.ip, detail: { limit: 'admin_session' } });
      throw errors.rateLimited(wait);
    }
    if (opts.fresh && !auth.recentlyVerified(session)) {
      throw new HttpError(403, 'reauth_required', 'Confirm with your passkey to make this change');
    }
    return session;
  }

  // Handles a request under /admin/api/; throws HttpError for any rejection.
  async function handle(req, res, url, client) {
    const matching = routes.filter(([, re]) => re.test(url.pathname));
    if (matching.length === 0) throw errors.notFound();
    const route = matching.find(([method]) => method === req.method);
    if (!route) throw errors.methodNotAllowed();
    const [, re, opts, handler] = route;
    const session = authorize(req, client, opts);
    const params = re.exec(url.pathname).slice(1).map((p) => {
      try {
        return decodeURIComponent(p);
      } catch {
        throw errors.notFound();
      }
    });
    sendResult(res, await handler({ req, res, url, client, session, params }));
  }

  return { handle, authorize };
}
