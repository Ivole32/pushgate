// Process entry point: configuration, HTTP server, periodic maintenance, graceful shutdown.
import http from 'node:http';
import { createApp, VERSION } from './app.js';
import { ConfigError, loadConfig } from './config.js';
import { openDatabase, purgeExpired } from './db.js';
import { createLogger, safeError } from './log.js';

export function createServer(app) {
  const server = http.createServer({
    maxHeaderSize: 16384,
    headersTimeout: 10000,
    requestTimeout: 30000,
    keepAliveTimeout: 5000,
  }, app.handle);
  server.maxRequestsPerSocket = 100;
  return server;
}

function main() {
  let config;
  try {
    config = loadConfig(process.env);
  } catch (err) {
    // Configuration errors never contain secret values (only names and validation messages).
    process.stderr.write(`${err instanceof ConfigError ? err.message : 'Failed to load configuration'}\n`);
    process.exit(1);
  }
  const log = createLogger({ level: config.logLevel });
  const db = openDatabase(config.dataDir);
  const app = createApp({ config, db, log });
  const server = createServer(app);

  purgeExpired(db, config);
  const maintenance = setInterval(() => {
    try {
      purgeExpired(db, config);
    } catch (err) {
      log.error('maintenance failed', safeError(err));
    }
  }, 3600000);
  maintenance.unref();

  server.listen(config.port, config.host, () => {
    log.info('pushgate started', {
      version: VERSION,
      listen: `${config.host}:${config.port}`,
      public_origin: config.publicOrigin,
      trusted_cidrs: config.trustedCidrs.map((c) => c.text),
      admin_cidrs: config.adminPublic ? 'PUBLIC (ADMIN_PUBLIC=true)' : config.adminCidrs.map((c) => c.text),
      trusted_proxies: config.trustedProxies.map((c) => c.text),
      notifications_enabled: config.notificationsEnabled,
      admin_configured: app.ctx.auth.hasAdmin(),
    });
    if (config.adminPublic) {
      log.warn('ADMIN_PUBLIC=true: the web app and admin API accept connections from every address (passkey login still required)');
    }
    if (!app.ctx.auth.hasAdmin()) {
      log.warn('no administrator passkey yet: create an enrollment token with "node src/cli.js enroll-token"');
    }
  });

  let stopping = false;
  const shutdown = (signal) => {
    if (stopping) return;
    stopping = true;
    log.info('shutting down', { signal });
    clearInterval(maintenance);
    server.close(() => {
      db.close();
      log.info('stopped');
      process.exit(0);
    });
    server.closeIdleConnections();
    // In-flight deliveries get a bounded amount of time to finish.
    setTimeout(() => {
      log.warn('forced shutdown after timeout');
      server.closeAllConnections();
      try {
        db.close();
      } catch {
        // already closed
      }
      process.exit(0);
    }, 10000).unref();
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('unhandledRejection', (err) => log.error('unhandled rejection', safeError(err)));
}

if (import.meta.main) main();
