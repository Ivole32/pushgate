// Request pipeline: request id → security headers → client resolution → network ACL → route.
// Plugins (src/plugins.js) can replace services and add hooks and routes; without them the
// built-in defaults below apply.
import crypto from 'node:crypto';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
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

// `send` replaces the push transport like a plugin would (used by the tests).
export function createApp({ config, db, log, send, plugins = [] }) {
  const ext = resolvePlugins(plugins);
  migratePlugins(db, ext.migrations);
  const services = { rateLimiter: createRateLimiter, failureLimiter: createFailureLimiter, transport: send, ...ext.services };

  // Who may reach the sending API before any key is looked at: TRUSTED_CIDRS, unless a plugin
  // replaces the check (it gets the default as `fallback`). Only an explicit `true` allows.
  const defaultApiAccess = (client) => ipInCidrs(client.ip, config.trustedCidrs);
  let apiAccess = defaultApiAccess;
  if (ext.services.apiAccess) {
    log.warn('sending API network check replaced by a plugin', { plugin: ext.owners.apiAccess });
    apiAccess = (client) => ext.services.apiAccess(client, { config, fallback: defaultApiAccess }) === true;
  }

  const audit = createAudit(db, log);
  const keys = createApiKeys(db, config.pepper);
  const devices = createDevices(db);
  const auth = createAdminAuth({ db, config });
  const pusher = createPusher({ config, db, devices, audit, log, ...(services.transport ? { send: services.transport } : {}) });
  const failureWindow = { windowMs: 10 * 60000, blockMs: config.authBlockMinutes * 60000 };
  const limits = {
    perKey: services.rateLimiter(config.rateLimitPerKeyPerMinute),
    global: services.rateLimiter(config.rateLimitGlobalPerMinute),
    apiFailures: services.failureLimiter({ limit: config.authFailureLimit, ...failureWindow }),
    adminFailures: services.failureLimiter({ limit: config.authFailureLimit, ...failureWindow }),
    adminAnonymous: services.rateLimiter(config.rateLimitAdminAnonymousPerMinute),
  };
  const ctx = {
    config, db, log, audit, keys, devices, auth, pusher, limits,
    hooks: ext.hooks, features: ext.features, plugins: ext.names, version: VERSION, startedAt: Date.now(),
  };
  const handleNotify = createNotifyHandler(ctx);
  const admin = createAdminRoutes(ctx);
  const files = loadStatic(PUBLIC_DIR);
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

  async function handleExtension(req, res, url, client, candidates) {
    const route = candidates.find((r) => r.method === req.method);
    if (!route) throw errors.methodNotAllowed();
    const session = admin.authorize(req, client, {
      auth: route.auth === 'none' ? false : undefined,
      fresh: route.auth === 'fresh',
      crossOrigin: route.crossOrigin,
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
    } catch (err) {
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
