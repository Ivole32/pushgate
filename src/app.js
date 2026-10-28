// Request pipeline: request id → security headers → client resolution → network ACL → route.
import crypto from 'node:crypto';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createApiKeys } from './apikeys.js';
import { createAudit } from './audit.js';
import { createDevices } from './devices.js';
import { HttpError, errors, sendError, sendJson, setSecurityHeaders } from './http.js';
import { safeError } from './log.js';
import { ipInCidrs, isLoopback, normalizeIp, resolveClient } from './netacl.js';
import { createNotifyHandler } from './notify.js';
import { createPusher } from './push.js';
import { createFailureLimiter, createRateLimiter } from './ratelimit.js';
import { loadStatic, serveStatic } from './static.js';
import { createAdminAuth } from './admin/auth.js';
import { createAdminRoutes } from './admin/routes.js';

const PUBLIC_DIR = fileURLToPath(new URL('../public/', import.meta.url));
export const VERSION = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;

export function createApp({ config, db, log, send }) {
  const audit = createAudit(db, log);
  const keys = createApiKeys(db, config.pepper);
  const devices = createDevices(db);
  const auth = createAdminAuth({ db, config });
  const pusher = createPusher({ config, db, devices, audit, log, ...(send ? { send } : {}) });
  const failureWindow = { windowMs: 10 * 60000, blockMs: config.authBlockMinutes * 60000 };
  const limits = {
    perKey: createRateLimiter(config.rateLimitPerKeyPerMinute),
    global: createRateLimiter(config.rateLimitGlobalPerMinute),
    apiFailures: createFailureLimiter({ limit: config.authFailureLimit, ...failureWindow }),
    adminFailures: createFailureLimiter({ limit: config.authFailureLimit, ...failureWindow }),
    adminAnonymous: createRateLimiter(config.rateLimitAdminAnonymousPerMinute),
  };
  const ctx = { config, db, log, audit, keys, devices, auth, pusher, limits, version: VERSION, startedAt: Date.now() };
  const handleNotify = createNotifyHandler(ctx);
  const handleAdmin = createAdminRoutes(ctx);
  const files = loadStatic(PUBLIC_DIR);
  const hsts = config.publicOrigin.startsWith('https:');

  // PWA/admin zone: the configured admin networks, or everyone with the explicit ADMIN_PUBLIC opt-in.
  const adminAllowed = (ip) => config.adminPublic || ipInCidrs(ip, config.adminCidrs);

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
      if (!ipInCidrs(client.ip, config.trustedCidrs)) return reject(res, requestId, client, 'api', 'cidr');
      if (pathname !== '/api/v1/notifications') throw errors.notFound();
      if (req.method !== 'POST') throw errors.methodNotAllowed();
      return handleNotify(req, res, client);
    }

    // Everything else (PWA and admin API).
    if (!adminAllowed(client.ip)) return reject(res, requestId, client, 'admin', 'cidr');
    if (pathname.startsWith('/admin/api/')) return handleAdmin(req, res, url, client);
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
