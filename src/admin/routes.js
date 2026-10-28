// Admin JSON API used by the PWA. Every route except session bootstrap and login/enrollment
// requires a passkey session; every state-changing route requires a same-origin request
// and the per-session CSRF token. Routes marked `fresh` additionally need a recent passkey
// confirmation, and security-relevant changes are pushed to every registered device.
import crypto from 'node:crypto';
import { SCOPES, isValidKeyId } from '../apikeys.js';
import { getSetting, setSetting } from '../db.js';
import { checkSubscription } from '../devices.js';
import { safeError } from '../log.js';
import { clientKey } from '../netacl.js';
import { HttpError, errors, readJson, sendJson } from '../http.js';
import { schemas, validate } from '../validate.js';
import { PASSKEY_ID, SESSION_COOKIE, readCookie, sessionCookie } from './auth.js';

const ADMIN_BODY_LIMIT = 16384;
const DEVICE_ID = /^[A-Za-z0-9_-]{22}$/;

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

export function createAdminRoutes({ config, db, log, keys, devices, pusher, auth, audit, limits, version, startedAt }) {
  const sessionMaxAge = config.sessionMaxHours * 3600;

  // Out-of-band alert to every device, so a change made with a stolen session does not go
  // unnoticed. High priority passes every device filter and the pause switch does not apply.
  // Not awaited: the admin request must not wait for push services.
  function securityAlert(title, message, client) {
    pusher.deliver({
      title,
      message: `${message}\nFrom ${client.ip}. Not you? On the server run "cli.js sessions revoke-all" and review Security events.`,
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
      audit.recordThrottled('admin.csrf_rejected', { ip: client.ip });
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

  function challengeResponse(result) {
    return { challenge_id: result.challengeId, options: result.options };
  }

  // A stale or unknown challenge is not a credential failure and is not counted toward the
  // brute-force block (otherwise someone else's challenge flood could lock the admin out).
  function verifyFailed(result, ip, event) {
    if (result.error === 'challenge') throw errors.badRequest('challenge_expired', 'Challenge expired or unknown; start again');
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
      if (!session) return { authenticated: false, setup_complete: auth.hasAdmin() };
      return { authenticated: true, setup_complete: true, csrf_token: session.csrf, expires_at: session.expiresAt };
    }],

    // ---- first administrator / recovery enrollment (one-time token from the CLI) ----
    ['POST', /^\/admin\/api\/enroll\/options$/, { auth: false }, async ({ req, client }) => {
      checkBlocked(client.ip);
      const { token } = await body(req, schemas.enrollOptions);
      if (!auth.enrollmentTokenValid(token)) {
        limits.adminFailures.fail(clientKey(client.ip));
        audit.recordThrottled('admin.enroll_failed', { ip: client.ip, detail: { reason: 'invalid_token' } });
        throw errors.unauthorized();
      }
      return challengeResponse(await auth.registrationOptions('enroll'));
    }],
    ['POST', /^\/admin\/api\/enroll\/verify$/, { auth: false }, async ({ req, res, client }) => {
      checkBlocked(client.ip);
      const data = await body(req, schemas.enrollVerify);
      const result = auth.enrollmentTokenValid(data.token)
        ? await auth.verifyRegistration({ kind: 'enroll', challengeId: data.challenge_id, response: data.response, name: data.name, token: data.token })
        : { error: 'invalid' };
      if (!result.id) verifyFailed(result, client.ip, 'admin.enroll_failed');
      audit.record('admin.passkey_enrolled', { actor: 'enrollment-token', ip: client.ip, detail: { passkey: data.name } });
      securityAlert('Passkey enrolled', `Passkey "${data.name}" was enrolled with an enrollment token; all other sessions were signed out.`, client);
      const s = startSession(res, result.id);
      return { ok: true, csrf_token: s.csrf };
    }],

    // ---- login ----
    ['POST', /^\/admin\/api\/login\/options$/, { auth: false }, async ({ client }) => {
      checkBlocked(client.ip);
      return challengeResponse(await auth.authenticationOptions());
    }],
    ['POST', /^\/admin\/api\/login\/verify$/, { auth: false }, async ({ req, res, client }) => {
      checkBlocked(client.ip);
      const data = await body(req, schemas.loginVerify);
      const result = await auth.verifyAuthentication({ challengeId: data.challenge_id, response: data.response });
      if (!result.id) verifyFailed(result, client.ip, 'admin.login_failed');
      limits.adminFailures.reset(clientKey(client.ip));
      audit.record('admin.login', { actor: `passkey:${result.id.slice(0, 12)}`, ip: client.ip });
      securityAlert('Admin sign-in', 'Someone signed in to Pushgate with a passkey.', client);
      const s = startSession(res, result.id);
      return { ok: true, csrf_token: s.csrf };
    }],
    // Re-confirmation with a passkey for `fresh` routes, without starting a new session.
    ['POST', /^\/admin\/api\/reauth\/options$/, {}, async () => challengeResponse(await auth.authenticationOptions('reauth'))],
    ['POST', /^\/admin\/api\/reauth\/verify$/, {}, async ({ req, session, client }) => {
      const data = await body(req, schemas.loginVerify);
      const result = await auth.verifyAuthentication({ kind: 'reauth', challengeId: data.challenge_id, response: data.response });
      if (!result.id) throw errors.badRequest('verification_failed', 'Passkey confirmation failed');
      auth.markVerified(session.hash);
      audit.record('admin.reverified', { actor: 'admin', ip: client.ip });
      return { ok: true };
    }],
    ['POST', /^\/admin\/api\/logout$/, {}, ({ res, session, client }) => {
      auth.destroySession(session.hash);
      res.setHeader('Set-Cookie', sessionCookie('', 0));
      audit.record('admin.logout', { actor: 'admin', ip: client.ip });
      return { ok: true };
    }],

    // ---- overview / health ----
    ['GET', /^\/admin\/api\/overview$/, {}, ({ client }) => {
      const recent = db.prepare(`SELECT d.id, d.key_id, k.name AS service, d.priority, d.created_at, d.status,
                                        d.targeted, d.delivered, d.failed, d.removed
                                 FROM deliveries d LEFT JOIN api_keys k ON k.id = d.key_id
                                 ORDER BY d.created_at DESC LIMIT 20`).all();
      return {
        version,
        uptime_seconds: Math.floor((Date.now() - startedAt) / 1000),
        database: db.prepare('PRAGMA quick_check').get().quick_check === 'ok' ? 'ok' : 'error',
        notifications_enabled: config.notificationsEnabled,
        sending_paused: getSetting(db, 'sending_paused') === 'true',
        active_keys: keys.list().filter((k) => k.status === 'active').length,
        devices: devices.count(),
        your_ip: client.ip,
        via_proxy: client.viaProxy,
        vapid_public_key: config.vapid.publicKey,
        history_retention_days: config.historyRetentionDays,
        recent_deliveries: recent,
      };
    }],
    ['PUT', /^\/admin\/api\/settings$/, {}, async ({ req, client }) => {
      const data = await body(req, schemas.settings);
      setSetting(db, 'sending_paused', data.sending_paused);
      audit.record('settings.changed', { actor: 'admin', ip: client.ip, detail: { sending_paused: data.sending_paused } });
      securityAlert(data.sending_paused ? 'Sending paused' : 'Sending resumed',
        data.sending_paused ? 'Notification sending was paused: services can no longer reach your devices.' : 'Notification sending was resumed.', client);
      return { sending_paused: data.sending_paused };
    }],
    ['GET', /^\/admin\/api\/events$/, {}, ({ url }) => {
      const before = url.searchParams.get('before');
      return { events: auditList(before) };
    }],

    // ---- service API keys ----
    ['GET', /^\/admin\/api\/keys$/, {}, () => ({ keys: keys.list() })],
    ['POST', /^\/admin\/api\/keys$/, { fresh: true }, async ({ req, client }) => {
      const data = await body(req, schemas.createKey);
      if (data.expires_at != null && data.expires_at <= Date.now()) {
        throw errors.badRequest('validation_failed', 'Request body is invalid', { details: [{ field: 'expires_at', issue: 'must be in the future' }] });
      }
      const scopes = data.allow_high_priority ? [SCOPES.SEND, SCOPES.SEND_HIGH] : [SCOPES.SEND];
      const { key, record } = keys.create({ name: data.name, description: data.description ?? '', expiresAt: data.expires_at ?? null, scopes });
      audit.record('api_key.created', { actor: 'admin', ip: client.ip, detail: { key_id: record.id, name: record.name, scopes } });
      securityAlert('API key created', `Service API key "${record.name}" (${record.id}) was created.`, client);
      // The full key is returned exactly once and is never stored.
      return { status: 201, body: { key, record } };
    }],
    ['POST', /^\/admin\/api\/keys\/([^/]+)\/revoke$/, {}, ({ params, client }) => {
      if (!isValidKeyId(params[0]) || !keys.revoke(params[0])) throw errors.notFound();
      audit.record('api_key.revoked', { actor: 'admin', ip: client.ip, detail: { key_id: params[0] } });
      return { record: keys.get(params[0]) };
    }],
    ['POST', /^\/admin\/api\/keys\/([^/]+)\/rotate$/, { fresh: true }, async ({ req, params, client }) => {
      const data = await body(req, schemas.rotateKey);
      const rotated = isValidKeyId(params[0]) ? keys.rotate(params[0], { graceSeconds: (data.grace_hours ?? 0) * 3600 }) : null;
      if (!rotated) {
        const existing = isValidKeyId(params[0]) ? keys.get(params[0]) : null;
        if (existing?.status === 'active') throw new HttpError(409, 'already_rotated', 'This key was already rotated; rotate its replacement instead');
        throw errors.notFound();
      }
      audit.record('api_key.rotated', { actor: 'admin', ip: client.ip, detail: { old_key_id: params[0], new_key_id: rotated.record.id, grace_hours: data.grace_hours ?? 0 } });
      securityAlert('API key rotated', `Service API key "${rotated.record.name}" was rotated (new id ${rotated.record.id}).`, client);
      return { status: 201, body: { key: rotated.key, record: rotated.record, previous: keys.get(params[0]) } };
    }],

    // ---- devices (push subscriptions) ----
    ['GET', /^\/admin\/api\/devices$/, {}, () => ({ devices: devices.list(), vapid_public_key: config.vapid.publicKey })],
    // A registered device receives every notification, so registering one is a sensitive change.
    ['POST', /^\/admin\/api\/devices$/, { fresh: true }, async ({ req, client }) => {
      const data = await body(req, schemas.registerDevice);
      let sub;
      try {
        sub = checkSubscription(data.subscription, config.pushHosts);
      } catch (err) {
        throw errors.badRequest('invalid_subscription', err.message);
      }
      const result = devices.upsert({ name: data.name, minPriority: data.min_priority ?? 'low', ...sub }, config.maxDevices);
      if (!result) throw new HttpError(409, 'device_limit', 'Maximum number of devices reached');
      audit.record(result.created ? 'device.registered' : 'device.updated', { actor: 'admin', ip: client.ip, detail: { device: result.device.id, name: data.name } });
      securityAlert(result.created ? 'Device registered' : 'Device subscription replaced',
        `Device "${data.name}" will now receive all notifications.`, client);
      return { status: result.created ? 201 : 200, body: { device: result.device } };
    }],
    ['PATCH', /^\/admin\/api\/devices\/([^/]+)$/, {}, async ({ req, params, client }) => {
      const data = await body(req, schemas.updateDevice);
      if (!DEVICE_ID.test(params[0]) || !devices.update(params[0], { name: data.name, minPriority: data.min_priority })) throw errors.notFound();
      audit.record('device.updated', { actor: 'admin', ip: client.ip, detail: { device: params[0] } });
      return { device: devices.get(params[0]) };
    }],
    ['DELETE', /^\/admin\/api\/devices\/([^/]+)$/, {}, ({ params, client }) => {
      const device = DEVICE_ID.test(params[0]) ? devices.get(params[0]) : null;
      if (!device) throw errors.notFound();
      // Alert first, so the device being removed is told as well (the last one included).
      securityAlert('Device removed', `Device "${device.name}" was removed and no longer receives notifications.`, client);
      if (!devices.remove(params[0])) throw errors.notFound();
      audit.record('device.removed', { actor: 'admin', ip: client.ip, detail: { device: params[0] } });
      return { ok: true };
    }],
    ['POST', /^\/admin\/api\/test-push$/, {}, async ({ req, client }) => {
      const data = await body(req, schemas.testPush);
      if (data.device_id && !devices.get(data.device_id)) throw errors.notFound();
      const outcome = await pusher.deliver({
        title: 'Pushgate test',
        message: `Test notification sent at ${new Date().toISOString()}`,
        priority: 'high',
        service: 'pushgate',
        deviceId: data.device_id ?? null,
        ttl: 300,
      });
      audit.record('push.test', { actor: 'admin', ip: client.ip, detail: { status: outcome.status, device: data.device_id ?? 'all' } });
      return outcome;
    }],

    // ---- passkeys ----
    ['GET', /^\/admin\/api\/passkeys$/, {}, ({ session }) => ({
      passkeys: auth.listPasskeys().map((p) => ({ ...p, current: p.id === session.passkeyId })),
    })],
    ['POST', /^\/admin\/api\/passkeys\/options$/, { fresh: true }, async () => challengeResponse(await auth.registrationOptions('add'))],
    ['POST', /^\/admin\/api\/passkeys\/verify$/, { fresh: true }, async ({ req, client }) => {
      const data = await body(req, schemas.addPasskeyVerify);
      const result = await auth.verifyRegistration({ kind: 'add', challengeId: data.challenge_id, response: data.response, name: data.name });
      if (!result.id) throw errors.badRequest('verification_failed', 'Passkey registration failed');
      audit.record('admin.passkey_added', { actor: 'admin', ip: client.ip, detail: { passkey: data.name } });
      securityAlert('Passkey added', `Passkey "${data.name}" was added to the administrator account.`, client);
      return { status: 201, body: { ok: true } };
    }],
    ['DELETE', /^\/admin\/api\/passkeys\/([^/]+)$/, { fresh: true }, ({ params, client }) => {
      if (!PASSKEY_ID.test(params[0])) throw errors.notFound();
      const r = auth.removePasskey(params[0]);
      if (r === 'last') throw new HttpError(409, 'last_passkey', 'Cannot remove the last passkey');
      if (r !== 'ok') throw errors.notFound();
      audit.record('admin.passkey_removed', { actor: 'admin', ip: client.ip, detail: { passkey: params[0].slice(0, 12) } });
      securityAlert('Passkey removed', 'A passkey was removed from the administrator account.', client);
      return { ok: true };
    }],
  ];

  function auditList(before) {
    const b = before && /^\d{1,15}$/.test(before) ? Number(before) : null;
    return audit.list({ limit: 100, before: b });
  }

  // Handles a request under /admin/api/; throws HttpError for any rejection.
  return async function handleAdmin(req, res, url, client) {
    const matching = routes.filter(([, re]) => re.test(url.pathname));
    if (matching.length === 0) throw errors.notFound();
    const route = matching.find(([method]) => method === req.method);
    if (!route) throw errors.methodNotAllowed();
    const [, re, opts, handler] = route;
    if (req.method !== 'GET') requireSameOrigin(req);
    if (opts.auth === false) {
      // Endpoints anyone can call (session check, login, enrollment) are rate limited per client
      // inside the app, independent of any reverse proxy configuration.
      const wait = limits.adminAnonymous.take(clientKey(client.ip));
      if (wait) {
        audit.recordThrottled('rate_limited', { ip: client.ip, detail: { limit: 'admin_anonymous' } });
        throw errors.rateLimited(wait);
      }
    }
    const session = opts.auth === false ? null : requireSession(req, client);
    if (opts.fresh && !auth.recentlyVerified(session)) {
      throw new HttpError(403, 'reauth_required', 'Confirm with your passkey to make this change');
    }
    const params = re.exec(url.pathname).slice(1).map((p) => {
      try {
        return decodeURIComponent(p);
      } catch {
        throw errors.notFound();
      }
    });
    const result = await handler({ req, res, url, client, session, params });
    if (result && typeof result.status === 'number' && result.body) sendJson(res, result.status, result.body);
    else sendJson(res, 200, result);
  };
}
