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

export const SESSION_COOKIE = '__Host-pushgate_session';
export const ENROLLMENT_TOKEN_TTL_MS = 15 * 60 * 1000;
const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const MAX_CHALLENGES = 1000;
const MAX_CHALLENGES_PER_CLIENT = 5;
const ENROLLMENT_PATTERN = /^pge_[A-Za-z0-9_-]{43}$/;
const SESSION_PATTERN = /^[A-Za-z0-9_-]{43}$/;

const sha256 = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');

export function createAdminAuth({ db, config, now = () => Date.now() }) {
  const challenges = new Map();
  const origin = config.publicOrigin;
  const rpID = config.rpId;

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

  // Outstanding challenges are capped per client and globally. When a cap is reached new
  // requests are refused instead of evicting existing challenges, so a flood from one client
  // cannot cancel another client's (the administrator's) sign-in in progress.
  function storeChallenge(kind, challenge, client) {
    const t = now();
    for (const [id, c] of challenges) if (c.expires <= t) challenges.delete(id);
    let mine = 0;
    for (const c of challenges.values()) if (c.client === client) mine++;
    if (mine >= MAX_CHALLENGES_PER_CLIENT || challenges.size >= MAX_CHALLENGES) return null;
    const id = crypto.randomBytes(16).toString('base64url');
    challenges.set(id, { kind, challenge, client, expires: t + CHALLENGE_TTL_MS });
    return id;
  }

  // Challenges are single use: they are removed on the first verification attempt.
  function takeChallenge(id, kind) {
    const c = challenges.get(id);
    challenges.delete(id);
    if (!c || c.kind !== kind || c.expires <= now()) return null;
    return c;
  }

  // ---- registration (enrollment and adding passkeys) ------------------------------------

  // Returns null when the client has too many outstanding challenges.
  async function registrationOptions(kind, client) {
    const existing = db.prepare('SELECT id, transports FROM passkeys').all();
    const options = await generateRegistrationOptions({
      rpName: 'Pushgate',
      rpID,
      userID: userId(),
      userName: 'admin',
      userDisplayName: 'Pushgate administrator',
      attestationType: 'none',
      excludeCredentials: existing.map((p) => ({ id: p.id, transports: JSON.parse(p.transports) })),
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      supportedAlgorithmIDs: [-7, -257],
    });
    const challengeId = storeChallenge(kind, options.challenge, client);
    return challengeId ? { challengeId, options } : null;
  }

  // Returns { id } or { error: 'challenge' } (unknown/expired/used challenge, not counted as a
  // credential failure) or { error: 'invalid' }.
  async function verifyRegistration({ kind, challengeId, response, name, token = null }) {
    const c = takeChallenge(challengeId, kind);
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
    return transaction(db, () => {
      if (kind === 'enroll') {
        // Consume the token atomically with storing the passkey.
        const res = db.prepare('UPDATE enrollment_tokens SET used_at = ? WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?')
          .run(now(), sha256(token), now());
        if (res.changes !== 1) return { error: 'invalid' };
      }
      if (db.prepare('SELECT 1 FROM passkeys WHERE id = ?').get(cred.id)) return { error: 'invalid' };
      db.prepare('INSERT INTO passkeys (id, public_key, counter, transports, name, created_at) VALUES (?, ?, ?, ?, ?, ?)')
        .run(cred.id, Buffer.from(cred.publicKey), cred.counter, JSON.stringify(cred.transports ?? []), name, now());
      return { id: cred.id };
    });
  }

  // ---- authentication -------------------------------------------------------------------

  async function authenticationOptions(client) {
    const options = await generateAuthenticationOptions({ rpID, userVerification: 'required', allowCredentials: [] });
    const challengeId = storeChallenge('login', options.challenge, client);
    return challengeId ? { challengeId, options } : null;
  }

  // Same result shape as verifyRegistration.
  async function verifyAuthentication({ challengeId, response }) {
    const c = takeChallenge(challengeId, 'login');
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
        credential: { id: row.id, publicKey: new Uint8Array(row.public_key), counter: row.counter, transports: JSON.parse(row.transports) },
        requireUserVerification: true,
      });
    } catch {
      return { error: 'invalid' };
    }
    if (!result.verified) return { error: 'invalid' };
    db.prepare('UPDATE passkeys SET counter = ?, last_used_at = ? WHERE id = ?').run(result.authenticationInfo.newCounter, now(), row.id);
    return { id: row.id };
  }

  function listPasskeys() {
    return db.prepare('SELECT id, name, created_at, last_used_at FROM passkeys ORDER BY created_at').all()
      .map((p) => ({ id: p.id, name: p.name, created_at: p.created_at, last_used_at: p.last_used_at }));
  }

  // Refuses to delete the last passkey so the administrator cannot lock themselves out.
  function removePasskey(id) {
    return transaction(db, () => {
      if (db.prepare('SELECT COUNT(*) AS n FROM passkeys').get().n <= 1) return 'last';
      return db.prepare('DELETE FROM passkeys WHERE id = ?').run(id).changes === 1 ? 'ok' : 'missing';
    });
  }

  // ---- sessions -------------------------------------------------------------------------

  function createSession(passkeyId) {
    const token = crypto.randomBytes(32).toString('base64url');
    const csrf = crypto.randomBytes(32).toString('base64url');
    const t = now();
    const expiresAt = t + config.sessionMaxHours * 3600000;
    db.prepare('INSERT INTO sessions (token_hash, csrf_token, passkey_id, created_at, last_seen_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)')
      .run(sha256(token), csrf, passkeyId, t, t, expiresAt);
    return { token, csrf, expiresAt };
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
    return { hash, csrf: row.csrf_token, passkeyId: row.passkey_id, expiresAt: row.expires_at };
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
