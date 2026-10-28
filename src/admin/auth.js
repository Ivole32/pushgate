// Administrator authentication: passkeys (WebAuthn), one-time enrollment tokens and sessions.
//
// There is a single administrator identity that can hold several passkeys. The first passkey
// (and any recovery passkey) can only be enrolled with a one-time token created by the CLI
// inside the container, i.e. by someone with shell access to the host.
import crypto from 'node:crypto';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { getSetting, setSetting, transaction } from '../db.js';
import { CHALLENGE_TOKEN_PATTERN } from '../validate.js';

export const SESSION_COOKIE = '__Host-pushgate_session';
export const ENROLLMENT_TOKEN_TTL_MS = 15 * 60 * 1000;
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

export function createAdminAuth({ db, config, now = () => Date.now() }) {
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

  function userId() {
    let id = getSetting(db, 'webauthn_user_id');
    if (!id) {
      id = crypto.randomBytes(32).toString('base64url');
      setSetting(db, 'webauthn_user_id', id);
    }
    return Buffer.from(id, 'base64url');
  }

  function hasAdmin() {
    return db.prepare('SELECT COUNT(*) AS n FROM passkeys').get().n > 0;
  }

  // ---- enrollment tokens -------------------------------------------------------------

  function createEnrollmentToken() {
    const token = 'pge_' + crypto.randomBytes(32).toString('base64url');
    const t = now();
    db.prepare('INSERT INTO enrollment_tokens (token_hash, created_at, expires_at) VALUES (?, ?, ?)')
      .run(sha256(token), t, t + ENROLLMENT_TOKEN_TTL_MS);
    return { token, expiresAt: t + ENROLLMENT_TOKEN_TTL_MS };
  }

  function enrollmentTokenValid(token) {
    if (typeof token !== 'string' || !ENROLLMENT_PATTERN.test(token)) return false;
    const row = db.prepare('SELECT * FROM enrollment_tokens WHERE token_hash = ?').get(sha256(token));
    return Boolean(row && !row.used_at && row.expires_at > now());
  }

  // ---- challenges ----------------------------------------------------------------------

  const mac = (payload) => crypto.createHmac('sha256', challengeKey).update(payload).digest('base64url');

  // Token = base64url(JSON {k: kind, c: challenge, e: expiry}) "." HMAC. Binding the kind stops a
  // login challenge from being used for enrollment and vice versa.
  function issueChallenge(kind, challenge) {
    const payload = Buffer.from(JSON.stringify({ k: kind, c: challenge, e: now() + CHALLENGE_TTL_MS })).toString('base64url');
    return `${payload}.${mac(payload)}`;
  }

  // Returns the challenge string, or null if the token is forged, expired, of another kind or
  // already used.
  function openChallenge(token, kind) {
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
    if (data?.k !== kind || typeof data.c !== 'string' || !Number.isSafeInteger(data.e) || data.e <= now()) return null;
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

  async function registrationOptions(kind) {
    const existing = db.prepare('SELECT id, transports FROM passkeys').all();
    const options = await generateRegistrationOptions({
      rpName: 'Pushgate',
      rpID,
      userID: userId(),
      userName: 'admin',
      userDisplayName: 'Pushgate administrator',
      attestationType: 'none',
      excludeCredentials: existing.map((p) => ({ id: p.id, transports: parseTransports(p.transports) })),
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      supportedAlgorithmIDs: [-7, -257],
    });
    return { challengeId: issueChallenge(kind, options.challenge), options };
  }

  // Returns { id } or { error: 'challenge' } (forged/expired/used challenge, not counted as a
  // credential failure) or { error: 'invalid' }.
  async function verifyRegistration({ kind, challengeId, response, name, token = null }) {
    const c = openChallenge(challengeId, kind);
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
      if (kind === 'enroll') {
        // Consume the token atomically with storing the passkey.
        const res = db.prepare('UPDATE enrollment_tokens SET used_at = ? WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?')
          .run(now(), sha256(token), now());
        if (res.changes !== 1) return { error: 'invalid' };
        // Recovery: whoever held a session before (possibly the reason for recovering) is
        // signed out. The caller starts a new session for the enrolling device.
        db.prepare('DELETE FROM sessions').run();
      }
      if (db.prepare('SELECT 1 FROM passkeys WHERE id = ?').get(cred.id)) return { error: 'invalid' };
      db.prepare('INSERT INTO passkeys (id, public_key, counter, transports, name, created_at) VALUES (?, ?, ?, ?, ?, ?)')
        .run(cred.id, Buffer.from(cred.publicKey), cred.counter, JSON.stringify(cleanTransports(cred.transports)), name, now());
      return { id: cred.id };
    });
  }

  // ---- authentication -------------------------------------------------------------------

  // kind 'login' starts a session; kind 'reauth' re-confirms the holder of an existing one.
  async function authenticationOptions(kind = 'login') {
    const options = await generateAuthenticationOptions({ rpID, userVerification: 'required', allowCredentials: [] });
    return { challengeId: issueChallenge(kind, options.challenge), options };
  }

  // Same result shape as verifyRegistration.
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
    return { id: row.id };
  }

  function listPasskeys() {
    return db.prepare('SELECT id, name, created_at, last_used_at FROM passkeys ORDER BY created_at').all()
      .map((p) => ({ id: p.id, name: p.name, created_at: p.created_at, last_used_at: p.last_used_at }));
  }

  // Refuses to delete the last passkey so the administrator cannot lock themselves out. The CLI
  // (shell access to the host) may remove any passkey; a new one is enrolled with a token.
  function removePasskey(id, { allowLast = false } = {}) {
    return transaction(db, () => {
      if (!allowLast && db.prepare('SELECT COUNT(*) AS n FROM passkeys').get().n <= 1) return 'last';
      return db.prepare('DELETE FROM passkeys WHERE id = ?').run(id).changes === 1 ? 'ok' : 'missing';
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
    const row = db.prepare('SELECT * FROM sessions WHERE token_hash = ?').get(hash);
    if (!row) return null;
    const t = now();
    if (row.expires_at <= t || row.last_seen_at + config.sessionIdleMinutes * 60000 <= t) {
      db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(hash);
      return null;
    }
    db.prepare('UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?').run(t, hash);
    return { hash, csrf: row.csrf_token, passkeyId: row.passkey_id, expiresAt: row.expires_at, verifiedAt: row.verified_at };
  }

  function destroySession(hash) {
    db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(hash);
  }

  function revokeAllSessions() {
    return db.prepare('DELETE FROM sessions').run().changes;
  }

  return {
    hasAdmin,
    createEnrollmentToken,
    enrollmentTokenValid,
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
