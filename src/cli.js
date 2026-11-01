// Administrative CLI. It runs inside the container (`docker compose exec pushgate ...`), so
// using it requires shell access to the host — that is the trust anchor for initial setup
// and recovery.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { DEFAULT_ACCOUNT, createAccounts } from './accounts.js';
import { createApiKeys, SCOPES, isValidKeyId } from './apikeys.js';
import { createAudit } from './audit.js';
import { ConfigError, loadConfig } from './config.js';
import { backupDatabase, openDatabase } from './db.js';
import { createDevices } from './devices.js';
import { createLogger } from './log.js';
import { createAdminAuth } from './admin/auth.js';
import { schemas, validate } from './validate.js';

const USAGE = `Usage: node src/cli.js <command> [options]

Commands for keys, devices, passkeys and enrollment act on one account: --account <id>
(default: "default", the only account of a self-hosted installation).

Setup and recovery
  gen-secrets --out <dir>            Generate api_key_pepper and vapid_private_key (development use)
  check-config                       Validate configuration and secrets, then exit
  enroll-token [--replace-passkeys]  One-time token (15 min) to enroll an administrator passkey;
                                     --replace-passkeys removes the other passkeys when it is used
  sessions revoke-all                Sign out every admin session (only the account's with --account)
  passkeys list
  passkeys remove <passkey-id>       Also removes the last passkey (enroll a new one with a token)

Service API keys
  keys list
  keys create --name <name> [--description <text>] [--expires-days <n>] [--allow-high]
  keys revoke <key-id>
  keys rotate <key-id> [--grace-hours <n>]

Devices
  devices list
  devices remove <device-id>

Accounts
  accounts list
  accounts create --name <name>      Then enroll its administrator: enroll-token --account <id>
  accounts remove <account-id>       Deletes the account with all its keys, devices and passkeys

Operations
  backup --out <file>                Consistent online copy of the database
  vapid-public-key                   Print the VAPID public key
`;

function fail(message) {
  process.stderr.write(message + '\n');
  process.exit(1);
}

function genSecrets(out) {
  if (!out) fail('gen-secrets requires --out <dir>');
  // Same layout as scripts/gen-secrets.sh: private directory, world-readable files, so the
  // container user can read them under any user-namespace mapping (see README).
  fs.mkdirSync(out, { recursive: true, mode: 0o700 });
  fs.chmodSync(out, 0o700);
  const write = (name, content) => {
    const file = path.join(out, name);
    // 'wx' refuses to overwrite: replacing secrets invalidates all keys/subscriptions.
    fs.writeFileSync(file, content, { mode: 0o444, flag: 'wx' });
    process.stdout.write(`wrote ${file}\n`);
  };
  const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  try {
    write('api_key_pepper', crypto.randomBytes(32).toString('base64') + '\n');
    write('vapid_private_key', privateKey.export({ format: 'pem', type: 'pkcs8' }));
  } catch (err) {
    fail(err.code === 'EEXIST' ? 'refusing to overwrite an existing secret file' : 'could not write secret files');
  }
}

// Values may come from web forms (names) and are written to the operator's terminal: control
// and invisible characters are shown as escapes, never sent raw.
const printable = (v) => String(v ?? '').replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, (c) => `\\u{${c.codePointAt(0).toString(16)}}`);

function table(rows, columns) {
  if (rows.length === 0) return process.stdout.write('(none)\n');
  const cells = rows.map((r) => columns.map((c) => printable(r[c])));
  const widths = columns.map((c, i) => Math.max(c.length, ...cells.map((r) => r[i].length)));
  const line = (vals) => vals.map((v, i) => v.padEnd(widths[i])).join('  ') + '\n';
  process.stdout.write(line(columns));
  for (const r of cells) process.stdout.write(line(r));
}

const iso = (t) => (t ? new Date(t).toISOString() : '');

function main(argv) {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      out: { type: 'string' },
      name: { type: 'string' },
      description: { type: 'string' },
      'expires-days': { type: 'string' },
      'allow-high': { type: 'boolean' },
      'grace-hours': { type: 'string' },
      account: { type: 'string' },
      'replace-passkeys': { type: 'boolean' },
      help: { type: 'boolean', short: 'h' },
    },
  });
  const [cmd, sub, arg] = positionals;
  if (!cmd || values.help) return process.stdout.write(USAGE);
  if (cmd === 'gen-secrets') return genSecrets(values.out);
  // Database, WAL and backup files are created private (gen-secrets sets its own modes above).
  process.umask(0o077);

  let config;
  try {
    config = loadConfig(process.env);
  } catch (err) {
    fail(err instanceof ConfigError ? err.message : 'Failed to load configuration');
  }
  if (cmd === 'check-config') return process.stdout.write('configuration OK\n');
  if (cmd === 'vapid-public-key') return process.stdout.write(config.vapid.publicKey + '\n');

  const db = openDatabase(config.dataDir);
  const log = createLogger({ level: 'warn', sink: (l) => process.stderr.write(l + '\n') });
  const audit = createAudit(db, log);
  const keys = createApiKeys(db, config.pepper);
  const accounts = createAccounts(db);
  const auth = createAdminAuth({ db, config, accounts });
  const actor = 'cli';
  const accountId = values.account ?? DEFAULT_ACCOUNT;

  try {
    if (!accounts.get(accountId)) fail('no account with that id (see "accounts list")');
    if (cmd === 'enroll-token') {
      const replacePasskeys = values['replace-passkeys'] === true;
      const { token, expiresAt } = auth.createEnrollmentToken(accountId, { replacePasskeys });
      audit.record('admin.enrollment_token_created', { accountId, actor, detail: { replace_passkeys: replacePasskeys } });
      process.stdout.write(`${token}\n\nValid until ${iso(expiresAt)} for one passkey enrollment` +
        (replacePasskeys ? '; enrolling removes every other passkey of the account.\n' : '.\n') +
        `Open ${config.publicOrigin}/ on the device, choose "Set up with enrollment token" and paste it.\n`);
    } else if (cmd === 'sessions' && sub === 'revoke-all') {
      const scoped = values.account !== undefined;
      const n = auth.revokeAllSessions(scoped ? accountId : null);
      audit.record('admin.sessions_revoked', { accountId: scoped ? accountId : null, actor, detail: { count: n } });
      process.stdout.write(`revoked ${n} session(s)\n`);
    } else if (cmd === 'passkeys' && sub === 'list') {
      table(auth.listPasskeys(accountId).map((p) => ({ ...p, created_at: iso(p.created_at), last_used_at: iso(p.last_used_at) })),
        ['id', 'name', 'created_at', 'last_used_at']);
    } else if (cmd === 'passkeys' && sub === 'remove') {
      if (!arg || auth.removePasskey(accountId, arg, { allowLast: true }) !== 'ok') fail('no passkey with that id');
      audit.record('admin.passkey_removed', { accountId, actor, detail: { passkey: arg.slice(0, 12) } });
      process.stdout.write(`removed ${arg} (its sessions are signed out)\n`);
    } else if (cmd === 'accounts' && sub === 'list') {
      table(accounts.list().map((a) => ({ ...a, sending_paused: a.sending_paused ? 'yes' : 'no', created_at: iso(a.created_at) })),
        ['id', 'name', 'sending_paused', 'created_at']);
    } else if (cmd === 'accounts' && sub === 'create') {
      const problems = validate({ name: values.name }, { name: schemas.createKey.name });
      if (problems.length) fail(problems.map((p) => `${p.field} ${p.issue}`).join('\n'));
      const account = accounts.create({ name: values.name });
      audit.record('account.created', { accountId: account.id, actor, detail: { name: account.name } });
      process.stdout.write(`created account ${account.id} ("${printable(account.name)}"); enroll its administrator with: enroll-token --account ${account.id}\n`);
    } else if (cmd === 'accounts' && sub === 'remove') {
      const r = arg ? accounts.remove(arg) : 'missing';
      if (r === 'default') fail('the default account cannot be removed');
      if (r !== 'ok') fail('no account with that id');
      audit.record('account.removed', { actor, detail: { account: arg } });
      process.stdout.write(`removed account ${arg} and all its data\n`);
    } else if (cmd === 'keys' && sub === 'list') {
      table(keys.list(accountId).map((k) => ({ ...k, scopes: k.scopes.join(','), created_at: iso(k.created_at), expires_at: iso(k.expires_at), last_used_at: iso(k.last_used_at) })),
        ['id', 'name', 'status', 'scopes', 'created_at', 'expires_at', 'last_used_at']);
    } else if (cmd === 'keys' && sub === 'create') {
      const days = values['expires-days'];
      if (days !== undefined && !/^\d{1,4}$/.test(days)) fail('--expires-days must be a positive integer');
      const input = { name: values.name, description: values.description ?? '' };
      const problems = validate(input, { name: schemas.createKey.name, description: schemas.createKey.description });
      if (problems.length) fail(problems.map((p) => `${p.field} ${p.issue}`).join('\n'));
      const scopes = values['allow-high'] ? [SCOPES.SEND, SCOPES.SEND_HIGH] : [SCOPES.SEND];
      const expiresAt = days ? Date.now() + Number(days) * 86400000 : null;
      const { key, record } = keys.create(accountId, { ...input, expiresAt, scopes });
      audit.record('api_key.created', { accountId, actor, detail: { key_id: record.id, name: record.name, scopes } });
      process.stdout.write(`${key}\n\nKey id ${record.id} for "${record.name}". This is the only time the key is shown.\n`);
    } else if (cmd === 'keys' && sub === 'revoke') {
      if (!isValidKeyId(arg) || !keys.revoke(accountId, arg)) fail('no active key with that id');
      audit.record('api_key.revoked', { accountId, actor, detail: { key_id: arg } });
      process.stdout.write(`revoked ${arg}\n`);
    } else if (cmd === 'keys' && sub === 'rotate') {
      const grace = values['grace-hours'] ?? '0';
      if (!/^\d{1,3}$/.test(grace) || Number(grace) > 168) fail('--grace-hours must be 0..168');
      const rotated = isValidKeyId(arg) ? keys.rotate(accountId, arg, { graceSeconds: Number(grace) * 3600 }) : null;
      if (!rotated) fail('no active key with that id, or it was already rotated (rotate its replacement)');
      audit.record('api_key.rotated', { accountId, actor, detail: { old_key_id: arg, new_key_id: rotated.record.id, grace_hours: Number(grace) } });
      process.stdout.write(`${rotated.key}\n\nNew key id ${rotated.record.id}; old key ${arg} ` +
        (Number(grace) ? `stops working in ${grace} hour(s).\n` : 'is revoked.\n'));
    } else if (cmd === 'devices' && sub === 'list') {
      const devices = createDevices(db);
      table(devices.list(accountId).map((d) => ({ ...d, created_at: iso(d.created_at), last_success_at: iso(d.last_success_at) })),
        ['id', 'name', 'push_service', 'min_priority', 'created_at', 'last_success_at', 'failure_count']);
    } else if (cmd === 'devices' && sub === 'remove') {
      if (!arg || !createDevices(db).remove(accountId, arg)) fail('no device with that id');
      audit.record('device.removed', { accountId, actor, detail: { device: arg } });
      process.stdout.write(`removed ${arg}\n`);
    } else if (cmd === 'backup') {
      if (!values.out) fail('backup requires --out <file>');
      backupDatabase(db, values.out);
      audit.record('backup.created', { actor });
      process.stdout.write(`backup written to ${values.out}\n`);
    } else {
      process.stderr.write(USAGE);
      process.exitCode = 2;
    }
  } finally {
    db.close();
  }
}

try {
  main(process.argv.slice(2));
} catch (err) {
  fail(err?.code === 'ERR_PARSE_ARGS_UNKNOWN_OPTION' ? `${err.message}\n\n${USAGE}` : 'command failed');
}
