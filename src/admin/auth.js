// Administrator authentication: passkeys (WebAuthn), one-time enrollment tokens and sessions.
//
// Each account is one administrator identity that can hold several passkeys. The first passkey
// of an account (and any recovery passkey) can only be enrolled with a one-time token for that
// account: created by the CLI (shell access to the host) or by a plugin after its own checks
// (e.g. a verified sign-up). Signing in needs no account name: the passkey identifies it.
import crypto from 'node:crypto';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { DEFAULT_ACCOUNT, checkAccountId } from '../accounts.js';
import { transaction } from '../db.js';
import { CHALLENGE_TOKEN_PATTERN } from '../validate.js';

export const SESSION_COOKIE = '__Host-pushgate_session';
export const ENROLLMENT_TOKEN_TTL_MS = 15 * 60 * 1000;
// Plugins may issue longer-lived tokens (e.g. for a link in a sign-up email), up to this.
export const ENROLLMENT_TOKEN_MAX_TTL_MS = 24 * 3600 * 1000;
// Credential ids are client-chosen; anything stored must stay addressable by the API.
export const PASSKEY_ID = /^[A-Za-z0-9_-]{1,512}$/;
// Sensitive changes (passkeys, API keys, new devices) need a passkey confirmation this recent,
// so a borrowed or stolen session cookie alone cannot take over the account.
export const REVERIFY_AFTER_MS = 5 * 60 * 1000;
const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const ENROLLMENT_PATTERN = /^pge_[A-Za-z0-9_-]{43}$/;
const SESSION_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const TRANSPORTS = new Set(['ble', 'cable', 'hybrid', 'internal', 'nfc', 'smart-card', 'usb']);

const sha256 = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');

// Transports come verbatim from the client and are echoed to browsers in excludeCredentials,
// where an invalid value makes navigator.credentials.create() throw. Keep only known names.
export function cleanTransports(value) {
  return Array.isArray(value) ? [...new Set(value.filter((t) => TRANSPORTS.has(t)))] : [];
}

function parseTransports(json) {
  try {
    return cleanTransports(JSON.parse(json));
  } catch {
    return [];
  }
}

export function createAdminAuth({ db, config, accounts, now = () => Date.now() }) {
  const origin = config.publicOrigin;
  const rpID = config.rpId;
  // WebAuthn challenges are stateless signed tokens: the server keeps nothing for a challenge it
  // hands out, so anonymous clients (with ADMIN_PUBLIC on: the whole internet) cannot fill a
  // table and block the administrator's sign-in. The key is random per process: challenges live
  // only 5 minutes, and a restart must invalidate them (the used-challenge set below is in memory).
  const challengeKey = crypto.randomBytes(32);
  // Challenges that completed a successful ceremony, kept until they expire, so each one can be
  // used only once. Only successful verifications add entries, so this stays tiny.
  const usedChallenges = new Map();

  function hasAdmin(accountId) {
    return db.prepare('SELECT COUNT(*) AS n FROM passkeys WHERE account_id = ?').get(checkAccountId(accountId)).n > 0;
  }

  // ---- enrollment tokens -------------------------------------------------------------

  function createEnrollmentToken(accountId, { ttlMs = ENROLLMENT_TOKEN_TTL_MS } = {}) {
    if (!accounts.get(checkAccountId(accountId))) throw new TypeError('unknown account');
    if (!Number.isSafeInteger(ttlMs) || ttlMs < 60000 || ttlMs > ENROLLMENT_TOKEN_MAX_TTL_MS) throw new TypeError('invalid token lifetime');
    const token = 'pge_' + crypto.randomBytes(32).toString('base64url');
    const t = now();
    db.prepare('INSERT INTO enrollment_tokens (token_hash, account_id, created_at, expires_at) VALUES (?, ?, ?, ?)')
      .run(sha256(token), accountId, t, t + ttlMs);
    return { token, expiresAt: t + ttlMs };
  }

  // Returns the token's account id, or null if the token is unknown, used or expired.
  function enrollmentTokenAccount(token) {
    if (typeof token !== 'string' || !ENROLLMENT_PATTERN.test(token)) return null;
    const row = db.prepare('SELECT * FROM enrollment_tokens WHERE token_hash = ?').get(sha256(token));
    return row && !row.used_at && row.expires_at > now() ? row.account_id : null;
  }

  // ---- challenges ----------------------------------------------------------------------

  const mac = (payload) => crypto.createHmac('sha256', challengeKey).update(payload).digest('base64url');

  // Token = base64url(JSON {k: kind, a: account, c: challenge, e: expiry}) "." HMAC. Binding the
  // kind stops a login challenge from being used for enrollment and vice versa; binding the
  // account (registration only) stops options issued for one account being completed in another.
  function issueChallenge(kind, challenge, accountId = null) {
    const payload = Buffer.from(JSON.stringify({ k: kind, a: accountId, c: challenge, e: now() + CHALLENGE_TTL_MS })).toString('base64url');
    return `${payload}.${mac(payload)}`;
  }

  // Returns the challenge string, or null if the token is forged, expired, of another kind or
  // account, or already used.
  function openChallenge(token, kind, accountId = null) {
    if (typeof token !== 'string' || !CHALLENGE_TOKEN_PATTERN.test(token)) return null;
    const [payload, tag] = token.split('.');
    const expected = Buffer.from(mac(payload));
    const given = Buffer.from(tag);
    if (expected.length !== given.length || !crypto.timingSafeEqual(expected, given)) return null;
    let data;
    try {
      data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    } catch {
      return null;
    }
    if (data?.k !== kind || (data.a ?? null) !== accountId || typeof data.c !== 'string' || !Number.isSafeInteger(data.e) || data.e <= now()) return null;
    if (usedChallenges.has(data.c)) return null;
    return { challenge: data.c, expires: data.e };
  }

  // Marks a challenge as used. Called synchronously after verification succeeded: there is no
  // await between this check and the insert, so two concurrent submissions of the same
  // successful response cannot both win.
  function consumeChallenge(c) {
    const t = now();
    // Re-check expiry: it may have passed during verification, and pruning below would otherwise
    // drop the record of an earlier successful use of this same challenge.
    if (c.expires <= t) return false;
    for (const [k, exp] of usedChallenges) if (exp <= t) usedChallenges.delete(k);
    if (usedChallenges.has(c.challenge)) return false;
    usedChallenges.set(c.challenge, c.expires);
    return true;
  }

  // ---- registration (enrollment and adding passkeys) ------------------------------------

  async function registrationOptions(kind, accountId) {
    const account = accounts.get(checkAccountId(accountId));
    if (!account) throw new TypeError('unknown account');
    const existing = db.prepare('SELECT id, transports FROM passkeys WHERE account_id = ?').all(accountId);
    const single = accountId === DEFAULT_ACCOUNT;
    const options = await generateRegistrationOptions({
      rpName: 'Pushgate',
      rpID,
      userID: Buffer.from(accounts.webauthnUserId(accountId), 'base64url'),
      userName: single ? 'admin' : account.name,
      userDisplayName: single ? 'Pushgate administrator' : `Pushgate: ${account.name}`,
      attestationType: 'none',
      excludeCredentials: existing.map((p) => ({ id: p.id, transports: parseTransports(p.transports) })),
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      supportedAlgorithmIDs: [-7, -257],
    });
    return { challengeId: issueChallenge(kind, options.challenge, accountId), options };
  }

  // Returns { id } or { error: 'challenge' } (forged/expired/used challenge, not counted as a
  // credential failure) or { error: 'invalid' }. For enrollment the account is the token's.
  async function verifyRegistration({ kind, accountId, challengeId, response, name, token = null }) {
    checkAccountId(accountId);
    const c = openChallenge(challengeId, kind, accountId);
    if (!c) return { error: 'challenge' };
    let result;
    try {
      result = await verifyRegistrationResponse({
        response,
        expectedChallenge: c.challenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        requireUserVerification: true,
      });
    } catch {
      return { error: 'invalid' };
    }
    if (!result.verified || !result.registrationInfo) return { error: 'invalid' };
    const cred = result.registrationInfo.credential;
    // The library accepts credential ids of any length; an id the API cannot address could
    // never be removed again.
    if (typeof cred.id !== 'string' || !PASSKEY_ID.test(cred.id)) return { error: 'invalid' };
    if (!consumeChallenge(c)) return { error: 'challenge' };
    return transaction(db, () => {
      // Checked first: a refused enrollment must neither spend the token nor sign anyone out.
      if (db.prepare('SELECT 1 FROM passkeys WHERE id = ?').get(cred.id)) return { error: 'invalid' };
      if (kind === 'enroll') {
        // Consume the token atomically with storing the passkey.
        const res = db.prepare('UPDATE enrollment_tokens SET used_at = ? WHERE token_hash = ? AND account_id = ? AND used_at IS NULL AND expires_at > ?')
          .run(now(), sha256(token), accountId, now());
        if (res.changes !== 1) return { error: 'invalid' };
        // Recovery: whoever held a session of this account before (possibly the reason for
        // recovering) is signed out. The caller starts a new session for the enrolling device.
        db.prepare('DELETE FROM sessions WHERE passkey_id IN (SELECT id FROM passkeys WHERE account_id = ?)').run(accountId);
      }
      db.prepare('INSERT INTO passkeys (id, account_id, public_key, counter, transports, name, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
        .run(cred.id, accountId, Buffer.from(cred.publicKey), cred.counter, JSON.stringify(cleanTransports(cred.transports)), name, now());
      return { id: cred.id };
    });
  }

  // ---- authentication -------------------------------------------------------------------

  // kind 'login' starts a session; kind 'reauth' re-confirms the holder of an existing one.
  async function authenticationOptions(kind = 'login') {
    const options = await generateAuthenticationOptions({ rpID, userVerification: 'required', allowCredentials: [] });
    return { challengeId: issueChallenge(kind, options.challenge), options };
  }

  // Returns { id, accountId } or an error like verifyRegistration. The passkey decides the account.
  async function verifyAuthentication({ challengeId, response, kind = 'login' }) {
    const c = openChallenge(challengeId, kind);
    if (!c) return { error: 'challenge' };
    const row = typeof response.id === 'string' ? db.prepare('SELECT * FROM passkeys WHERE id = ?').get(response.id) : null;
    if (!row) return { error: 'invalid' };
    let result;
    try {
      result = await verifyAuthenticationResponse({
        response,
        expectedChallenge: c.challenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        credential: { id: row.id, publicKey: new Uint8Array(row.public_key), counter: row.counter, transports: parseTransports(row.transports) },
        requireUserVerification: true,
      });
    } catch {
      return { error: 'invalid' };
    }
    if (!result.verified) return { error: 'invalid' };
    if (!consumeChallenge(c)) return { error: 'challenge' };
    // MAX: concurrent sign-ins finish in any order; the stored counter must never go back.
    db.prepare('UPDATE passkeys SET counter = MAX(counter, ?), last_used_at = ? WHERE id = ?').run(result.authenticationInfo.newCounter, now(), row.id);
    return { id: row.id, accountId: row.account_id };
  }

  function listPasskeys(accountId) {
    return db.prepare('SELECT id, name, created_at, last_used_at FROM passkeys WHERE account_id = ? ORDER BY created_at').all(checkAccountId(accountId))
      .map((p) => ({ id: p.id, name: p.name, created_at: p.created_at, last_used_at: p.last_used_at }));
  }

  // Refuses to delete an account's last passkey so its administrator cannot lock themselves out.
  // The CLI (shell access to the host) may remove any passkey; a new one is enrolled with a token.
  function removePasskey(accountId, id, { allowLast = false } = {}) {
    checkAccountId(accountId);
    return transaction(db, () => {
      if (!db.prepare('SELECT 1 FROM passkeys WHERE id = ? AND account_id = ?').get(id, accountId)) return 'missing';
      if (!allowLast && db.prepare('SELECT COUNT(*) AS n FROM passkeys WHERE account_id = ?').get(accountId).n <= 1) return 'last';
      db.prepare('DELETE FROM passkeys WHERE id = ? AND account_id = ?').run(id, accountId);
      return 'ok';
    });
  }

  // ---- sessions -------------------------------------------------------------------------

  // Sessions are only created right after a passkey ceremony, so they start verified.
  function createSession(passkeyId) {
    const token = crypto.randomBytes(32).toString('base64url');
    const csrf = crypto.randomBytes(32).toString('base64url');
    const t = now();
    const expiresAt = t + config.sessionMaxHours * 3600000;
    db.prepare('INSERT INTO sessions (token_hash, csrf_token, passkey_id, created_at, last_seen_at, expires_at, verified_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .run(sha256(token), csrf, passkeyId, t, t, expiresAt, t);
    return { token, csrf, expiresAt };
  }

  function markVerified(hash) {
    db.prepare('UPDATE sessions SET verified_at = ? WHERE token_hash = ?').run(now(), hash);
  }

  function recentlyVerified(session) {
    return now() - session.verifiedAt < REVERIFY_AFTER_MS;
  }

  function getSession(token) {
    if (typeof token !== 'string' || !SESSION_PATTERN.test(token)) return null;
    const hash = sha256(token);
    const row = db.prepare(`SELECT s.*, p.account_id FROM sessions s JOIN passkeys p ON p.id = s.passkey_id
                            WHERE s.token_hash = ?`).get(hash);
    if (!row) return null;
    const t = now();
    if (row.expires_at <= t || row.last_seen_at + config.sessionIdleMinutes * 60000 <= t) {
      db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(hash);
      return null;
    }
    db.prepare('UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?').run(t, hash);
    return { hash, csrf: row.csrf_token, passkeyId: row.passkey_id, accountId: row.account_id, expiresAt: row.expires_at, verifiedAt: row.verified_at };
  }

  function destroySession(hash) {
    db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(hash);
  }

  // All sessions of one account, or of every account when no account is given (CLI).
  function revokeAllSessions(accountId = null) {
    if (accountId === null) return db.prepare('DELETE FROM sessions').run().changes;
    return db.prepare('DELETE FROM sessions WHERE passkey_id IN (SELECT id FROM passkeys WHERE account_id = ?)')
      .run(checkAccountId(accountId)).changes;
  }

  return {
    hasAdmin,
    createEnrollmentToken,
    enrollmentTokenAccount,
    registrationOptions,
    verifyRegistration,
    authenticationOptions,
    verifyAuthentication,
    listPasskeys,
    removePasskey,
    createSession,
    markVerified,
    recentlyVerified,
    getSession,
    destroySession,
    revokeAllSessions,
  };
}

export function readCookie(req, name) {
  const header = req.headers.cookie;
  if (typeof header !== 'string') return null;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq > 0 && part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim();
  }
  return null;
}

export function sessionCookie(token, maxAgeSeconds) {
  return `${SESSION_COOKIE}=${token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=${maxAgeSeconds}`;
}
