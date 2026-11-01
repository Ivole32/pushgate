// Request pipeline: request id → security headers → client resolution → network ACL → route.
// Plugins (src/plugins.js) can replace services and add hooks and routes; without them the
// built-in defaults below apply.
import crypto from 'node:crypto';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { UnknownAccountError, createAccounts } from './accounts.js';
import { createApiKeys } from './apikeys.js';
import { createAudit } from './audit.js';
import { ConfigError } from './config.js';
import { migratePlugins } from './db.js';
import { createDevices } from './devices.js';
import { HttpError, errors, sendError, sendJson, sendResult, setSecurityHeaders } from './http.js';
import { safeError } from './log.js';
import { ipInCidrs, isLoopback, normalizeIp, resolveClient } from './netacl.js';
import { createNotifyHandler } from './notify.js';
import { resolvePlugins } from './plugins.js';
import { createPusher } from './push.js';
import { createFailureLimiter, createRateLimiter } from './ratelimit.js';
import { loadStatic, serveStatic } from './static.js';
import { createAdminAuth } from './admin/auth.js';
import { createAdminRoutes } from './admin/routes.js';

const PUBLIC_DIR = fileURLToPath(new URL('../public/', import.meta.url));
export const VERSION = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;

// A replaced limiter must answer like the built-in one: a number of seconds (0 = allowed). Any
// other answer (a Promise from an async implementation, undefined, NaN) is a plugin bug; it is
// logged and refused, never treated as "allowed".
const REFUSE_SECONDS = 60;
function seconds(value, log, what) {
  if (typeof value === 'number' && Number.isFinite(value) && value >= 0) return value === 0 ? 0 : Math.max(1, Math.ceil(value));
  log.error('plugin service returned an invalid value; refusing', { service: what, type: typeof value });
  return REFUSE_SECONDS;
}

function checkedRateLimiter(factory, log) {
  return (perMinute) => {
    const inner = factory(perMinute);
    return { take: (id) => seconds(inner.take(id), log, 'rateLimiter.take') };
  };
}

function checkedFailureLimiter(factory, log) {
  return (opts) => {
    const inner = factory(opts);
    return {
      blockedFor: (id) => seconds(inner.blockedFor(id), log, 'failureLimiter.blockedFor'),
      fail: (id) => inner.fail(id) === true,
      reset: (id) => inner.reset(id),
    };
  };
}

// `send` replaces the push transport like a plugin would (used by the tests). `multiAccount`
// serves several accounts instead of only the default one (see src/accounts.js).
export function createApp({ config, db, log, send, plugins = [], multiAccount = false }) {
  if (typeof multiAccount !== 'boolean') throw new ConfigError('multiAccount must be true or false');
  const ext = resolvePlugins(plugins);
  migratePlugins(db, ext.migrations);
  const services = {
    transport: ext.services.transport ?? send,
    rateLimiter: ext.services.rateLimiter ? checkedRateLimiter(ext.services.rateLimiter, log) : createRateLimiter,
    failureLimiter: ext.services.failureLimiter ? checkedFailureLimiter(ext.services.failureLimiter, log) : createFailureLimiter,
  };

  // Who may reach the sending API before any key is looked at: TRUSTED_CIDRS, unless a plugin
  // replaces the check (it gets the default as `fallback`). Only an explicit `true` allows.
  const defaultApiAccess = (client) => ipInCidrs(client.ip, config.trustedCidrs);
  let apiAccess = defaultApiAccess;
  if (ext.services.apiAccess) {
    log.warn('sending API network check replaced by a plugin', { plugin: ext.owners.apiAccess });
    apiAccess = (client) => ext.services.apiAccess(client, { config, fallback: defaultApiAccess }) === true;
  }

  const audit = createAudit(db, log);
  const accounts = createAccounts(db);
  const keys = createApiKeys(db, config.pepper);
  const devices = createDevices(db);
  const auth = createAdminAuth({ db, config, accounts });
  const pusher = createPusher({ config, db, devices, audit, log, ...(services.transport ? { send: services.transport } : {}) });
  const failureWindow = { windowMs: 10 * 60000, blockMs: config.authBlockMinutes * 60000 };
  const limits = {
    perKey: services.rateLimiter(config.rateLimitPerKeyPerMinute),
    perAccount: services.rateLimiter(config.rateLimitPerAccountPerMinute),
    global: services.rateLimiter(config.rateLimitGlobalPerMinute),
    apiFailures: services.failureLimiter({ limit: config.authFailureLimit, ...failureWindow }),
    adminFailures: services.failureLimiter({ limit: config.authFailureLimit, ...failureWindow }),
    adminAnonymous: services.rateLimiter(config.rateLimitAdminAnonymousPerMinute),
    adminSession: services.rateLimiter(config.rateLimitAdminPerAccountPerMinute),
    pluginAnonymous: services.rateLimiter(config.rateLimitPluginAnonymousPerMinute),
  };
  const files = loadStatic(PUBLIC_DIR);
  // Plugin screens: each plugin's web directory is served under /plugins/<name>/, and the web
  // app imports its entry module (same origin, so the CSP stays unchanged).
  const web = [];
  for (const w of ext.web) {
    const loaded = loadStatic(w.dir);
    for (const [p, file] of loaded) if (p !== '/' && file) files.set(`/plugins/${w.plugin}${p}`, file);
    const entry = `/plugins/${w.plugin}/${w.entry}`;
    if (!files.has(entry)) throw new ConfigError(`plugin "${w.plugin}": web entry "${w.entry}" is not in ${w.dir}`);
    web.push(entry);
  }
  const ctx = {
    config, db, log, audit, accounts, keys, devices, auth, pusher, limits, multiAccount, web,
    hooks: ext.hooks, features: ext.features, plugins: ext.names, version: VERSION, startedAt: Date.now(),
  };
  const handleNotify = createNotifyHandler(ctx);
  const admin = createAdminRoutes(ctx);
  const hsts = config.publicOrigin.startsWith('https:');

  // Plugin routes match exact paths and may not hide the web app's files.
  const extRoutes = new Map();
  for (const r of ext.routes) {
    if (files.has(r.path)) throw new ConfigError(`plugin "${r.plugin}": route path "${r.path}" is a web app file`);
    const same = extRoutes.get(r.path) ?? [];
    if (same.some((o) => o.zone !== r.zone)) throw new ConfigError(`plugin "${r.plugin}": all methods of route path "${r.path}" need the same zone`);
    extRoutes.set(r.path, [...same, r]);
  }

  // PWA/admin zone: the configured admin networks, or everyone with the explicit ADMIN_PUBLIC opt-in.
  const adminAllowed = (ip) => config.adminPublic || ipInCidrs(ip, config.adminCidrs);

  // Requests must name pushgate's own host (the port may differ behind a proxy). A page on
  // another name that resolves to this server (DNS rebinding) is refused before any route.
  function hostAllowed(header) {
    if (typeof header !== 'string') return false;
    const m = /^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+)(?::\d{1,5})?$/.exec(header);
    return m !== null && m[1].toLowerCase() === config.rpId;
  }

  async function handleExtension(req, res, url, client, candidates) {
    const route = candidates.find((r) => r.method === req.method);
    if (!route) throw errors.methodNotAllowed();
    const session = admin.authorize(req, client, {
      auth: route.auth === 'none' ? false : undefined,
      fresh: route.auth === 'fresh',
      crossOrigin: route.crossOrigin,
      anonymousLimit: 'plugin',
    });
    sendResult(res, await route.handler({ req, res, url, client, session, ctx }));
  }

  function reject(res, requestId, client, zone, reason) {
    audit.recordThrottled('network.rejected', { ip: client.ip ?? client.peer, detail: { zone, reason } });
    sendError(res, errors.forbidden(), requestId);
  }

  async function route(req, res, url, client, requestId) {
    const { pathname } = url;

    // Health check: from loopback (container health check) or the admin networks.
    if (pathname === '/healthz') {
      const peer = normalizeIp(req.socket.remoteAddress);
      const local = isLoopback(peer) && !client.viaProxy;
      if (!local && !(client.ok && adminAllowed(client.ip))) return reject(res, requestId, client, 'health', client.reason ?? 'cidr');
      db.prepare('SELECT 1').get();
      return sendJson(res, 200, { status: 'ok' });
    }

    if (!client.ok) return reject(res, requestId, client, 'any', client.reason);
    if (!hostAllowed(req.headers.host)) {
      audit.recordThrottled('network.rejected', { ip: client.ip, detail: { zone: 'any', reason: 'host' } });
      throw new HttpError(421, 'misdirected_request', 'This server does not serve that host name');
    }

    // Sending API: only the configured sender networks.
    if (pathname.startsWith('/api/')) {
      if (!apiAccess(client)) return reject(res, requestId, client, 'api', 'cidr');
      if (pathname !== '/api/v1/notifications') throw errors.notFound();
      if (req.method !== 'POST') throw errors.methodNotAllowed();
      return handleNotify(req, res, client);
    }

    // Plugin routes: "public" ones from every network, "app" ones like the web app.
    const candidates = extRoutes.get(pathname);
    if (candidates && candidates[0].zone === 'public') return handleExtension(req, res, url, client, candidates);

    // Everything else (PWA and admin API).
    if (!adminAllowed(client.ip)) return reject(res, requestId, client, 'admin', 'cidr');
    if (candidates) return handleExtension(req, res, url, client, candidates);
    if (pathname.startsWith('/admin/api/')) return admin.handle(req, res, url, client);
    if (req.method !== 'GET' && req.method !== 'HEAD') throw errors.methodNotAllowed();
    if (!serveStatic(files, req, res, pathname)) throw errors.notFound();
  }

  async function handle(req, res) {
    const started = process.hrtime.bigint();
    const requestId = crypto.randomBytes(8).toString('hex');
    res.setHeader('X-Request-Id', requestId);
    setSecurityHeaders(res, { hsts });
    const client = resolveClient(req.socket.remoteAddress, req.headers, config.trustedProxies);

    let url;
    try {
      url = new URL(req.url, 'http://localhost');
    } catch {
      url = null;
    }
    try {
      // Only canonical paths: the URL parser turns "\" into "/" and resolves (encoded) dot
      // segments, which a reverse proxy does not, so its location rules (rate limits, allow
      // lists) could see a different path than the router here.
      if (!url || req.url.length > 2048 || req.url.split('?')[0] !== url.pathname) throw errors.badRequest();
      await route(req, res, url, client, requestId);
    } catch (caught) {
      // Data for an account removed during the request: answered like a missing session.
      const err = caught instanceof UnknownAccountError ? errors.unauthorized() : caught;
      if (err instanceof HttpError) {
        if (!res.headersSent) sendError(res, err, requestId);
      } else {
        log.error('request failed', { request_id: requestId, ...safeError(err) });
        if (!res.headersSent) sendError(res, new HttpError(500, 'internal_error', 'Internal error'), requestId);
        else res.destroy();
      }
    } finally {
      // Access log: method, path (no query string), status, client — never headers or bodies.
      log.info('request', {
        request_id: requestId,
        method: req.method,
        path: url ? url.pathname.slice(0, 200) : null,
        status: res.statusCode,
        ip: client.ip ?? client.peer,
        ms: Number((process.hrtime.bigint() - started) / 1000000n),
      });
    }
  }

  return { handle, ctx };
}
