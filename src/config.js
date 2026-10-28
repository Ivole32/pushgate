// Configuration and secrets. Everything is validated at startup and any problem aborts
// startup: there is no fallback that would widen access.
import fs from 'node:fs';
import crypto from 'node:crypto';
import { parseCidrList } from './netacl.js';

export class ConfigError extends Error {}

const DEFAULT_PUSH_HOSTS = 'push.apple.com,fcm.googleapis.com,push.services.mozilla.com,notify.windows.com';

function int(env, name, def, min, max, errors) {
  const raw = env[name];
  if (raw === undefined || raw === '') return def;
  if (!/^\d+$/.test(raw)) { errors.push(`${name} must be an integer`); return def; }
  const n = Number(raw);
  if (n < min || n > max) { errors.push(`${name} must be between ${min} and ${max}`); return def; }
  return n;
}

function bool(env, name, def, errors) {
  const raw = env[name];
  if (raw === undefined || raw === '') return def;
  if (raw === 'true') return true;
  if (raw === 'false') return false;
  errors.push(`${name} must be "true" or "false"`);
  return def;
}

function cidrs(env, name, errors, opts) {
  try {
    return parseCidrList(env[name], { name, ...opts });
  } catch (err) {
    errors.push(err.message);
    return [];
  }
}

export function readSecretFile(file, label) {
  if (!file) throw new ConfigError(`${label} file path is not configured`);
  let stat;
  try {
    stat = fs.statSync(file);
  } catch {
    throw new ConfigError(`${label} file is missing or unreadable`);
  }
  if (!stat.isFile() || stat.size === 0 || stat.size > 16384) throw new ConfigError(`${label} file is empty or invalid`);
  try {
    return fs.readFileSync(file, 'utf8');
  } catch (err) {
    throw new ConfigError(unreadableSecretMessage(label, stat, err?.code, process.getuid?.()));
  }
}

// Explains why a secret file cannot be read, using metadata only (never the contents).
export function unreadableSecretMessage(label, stat, code, processUid) {
  const mode = (stat.mode & 0o777).toString(8).padStart(3, '0');
  let hint = 'run "scripts/gen-secrets.sh --fix-permissions" on the host (secrets directory 0700, files 0444)';
  if (stat.uid === 65534) {
    hint = 'the file owner is not mapped into the container (Docker user-namespace remapping or rootless Docker); ' + hint;
  } else if (code === 'EACCES' && (stat.mode & 0o004)) {
    hint = 'the file is world-readable, so a security module (SELinux/AppArmor) is probably denying access; on SELinux run "chcon -t container_file_t secrets/*"';
  }
  return `${label} file is unreadable (${code ?? 'error'}; file uid ${stat.uid}, mode ${mode}; process uid ${processUid ?? 'n/a'}): ${hint}`;
}

export function parsePepper(text) {
  const trimmed = String(text).trim();
  if (!/^[A-Za-z0-9+/_-]+=*$/.test(trimmed)) throw new ConfigError('API key pepper must be base64');
  const bytes = Buffer.from(trimmed, 'base64');
  if (bytes.length < 32) throw new ConfigError('API key pepper must contain at least 32 random bytes');
  return bytes;
}

// Accepts a PEM encoded P-256 private key (SEC1 or PKCS#8) and returns the raw
// base64url values expected by the web-push library.
export function parseVapidKey(pem) {
  let key;
  try {
    key = crypto.createPrivateKey({ key: pem, format: 'pem' });
  } catch {
    throw new ConfigError('VAPID private key is not a valid PEM private key');
  }
  if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') {
    throw new ConfigError('VAPID private key must be an EC P-256 (prime256v1) key');
  }
  const jwk = key.export({ format: 'jwk' });
  const x = Buffer.from(jwk.x, 'base64url');
  const y = Buffer.from(jwk.y, 'base64url');
  const publicKey = Buffer.concat([Buffer.from([4]), x, y]).toString('base64url');
  return { publicKey, privateKey: jwk.d };
}

export function loadConfig(env = process.env, { readSecrets = true } = {}) {
  const errors = [];

  let publicOrigin = null;
  let rpId = null;
  try {
    const url = new URL(env.PUBLIC_ORIGIN ?? '');
    const local = url.hostname === 'localhost';
    if (url.protocol !== 'https:' && !(local && url.protocol === 'http:')) {
      errors.push('PUBLIC_ORIGIN must use https:// (http:// is accepted only for localhost)');
    }
    if (url.pathname !== '/' || url.search || url.hash || url.username || url.password) {
      errors.push('PUBLIC_ORIGIN must be an origin only, e.g. https://notify.example.lan');
    }
    publicOrigin = url.origin;
    rpId = url.hostname;
  } catch {
    errors.push('PUBLIC_ORIGIN is missing or not a URL');
  }

  const vapidSubject = env.VAPID_SUBJECT ?? '';
  if (!/^(mailto:[^\s@]+@[^\s@]+|https:\/\/\S+)$/.test(vapidSubject)) {
    errors.push('VAPID_SUBJECT must be a mailto: address or https:// URL');
  }

  const pushHosts = String(env.PUSH_ENDPOINT_HOSTS || DEFAULT_PUSH_HOSTS)
    .split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
  for (const h of pushHosts) {
    if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(h)) errors.push(`PUSH_ENDPOINT_HOSTS entry "${h}" is not a hostname`);
  }

  const logLevel = env.LOG_LEVEL || 'info';
  if (!['debug', 'info', 'warn', 'error'].includes(logLevel)) errors.push('LOG_LEVEL is invalid');

  const config = {
    publicOrigin,
    rpId,
    host: env.LISTEN_HOST || '0.0.0.0',
    port: int(env, 'PORT', 8080, 1, 65535, errors),
    dataDir: env.DATA_DIR || '/data',
    trustedCidrs: cidrs(env, 'TRUSTED_CIDRS', errors),
    adminCidrs: cidrs(env, 'ADMIN_CIDRS', errors),
    trustedProxies: cidrs(env, 'TRUSTED_PROXIES', errors, { allowEmpty: true }),
    notificationsEnabled: bool(env, 'NOTIFICATIONS_ENABLED', true, errors),
    requireSetupBeforeSending: bool(env, 'REQUIRE_SETUP_BEFORE_SENDING', true, errors),
    vapidSubject,
    pushHosts,
    rateLimitPerKeyPerMinute: int(env, 'RATE_LIMIT_PER_KEY_PER_MINUTE', 30, 1, 10000, errors),
    rateLimitGlobalPerMinute: int(env, 'RATE_LIMIT_GLOBAL_PER_MINUTE', 120, 1, 100000, errors),
    authFailureLimit: int(env, 'AUTH_FAILURE_LIMIT', 10, 1, 1000, errors),
    authBlockMinutes: int(env, 'AUTH_BLOCK_MINUTES', 15, 1, 1440, errors),
    historyRetentionDays: int(env, 'HISTORY_RETENTION_DAYS', 7, 0, 365, errors),
    auditRetentionDays: int(env, 'AUDIT_RETENTION_DAYS', 90, 1, 3650, errors),
    sessionIdleMinutes: int(env, 'SESSION_IDLE_MINUTES', 30, 5, 1440, errors),
    sessionMaxHours: int(env, 'SESSION_MAX_HOURS', 12, 1, 168, errors),
    maxDevices: int(env, 'MAX_DEVICES', 20, 1, 200, errors),
    logLevel,
    pepperFile: env.API_KEY_PEPPER_FILE || '/run/secrets/api_key_pepper',
    vapidKeyFile: env.VAPID_PRIVATE_KEY_FILE || '/run/secrets/vapid_private_key',
    pepper: null,
    vapid: null,
  };

  if (readSecrets) {
    try {
      config.pepper = parsePepper(readSecretFile(config.pepperFile, 'API key pepper'));
    } catch (err) {
      errors.push(err.message);
    }
    try {
      config.vapid = parseVapidKey(readSecretFile(config.vapidKeyFile, 'VAPID private key'));
    } catch (err) {
      errors.push(err.message);
    }
  }

  if (errors.length) throw new ConfigError('Invalid configuration:\n  - ' + errors.join('\n  - '));
  return config;
}
