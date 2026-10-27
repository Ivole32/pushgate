# Architecture and security decisions

## Overview

Pushgate is one Node.js process behind a TLS reverse proxy (Caddy). It stores metadata in SQLite and
sends notifications through the standard Web Push protocol to an iOS Home Screen web app (PWA).

```
 LAN service ──HTTPS──▶ Caddy ──HTTP (internal docker network)──▶ pushgate ──HTTPS (VAPID, RFC 8291)──▶ Apple Web Push ──▶ iPhone PWA
   (curl, cron,          :443     X-Forwarded-For overwritten         │                                                        service worker
    monitoring)                                                      ▼                                                        showNotification()
                                                               SQLite on /data
 iPhone (admin) ──HTTPS──▶ Caddy ──▶ pushgate /  (PWA, passkey login, device registration, key management)
```

Data flow for one notification:

1. Caddy terminates TLS and **overwrites** `X-Forwarded-For` with the TCP peer address.
2. pushgate checks that the TCP peer is the configured proxy (otherwise: reject), takes the single
   client address from `X-Forwarded-For`, and checks it against `TRUSTED_CIDRS`.
3. Per-IP brute-force block check, then API key parse (format check), lookup by public key id,
   HMAC comparison in constant time, revocation/expiry/scope check.
4. Per-key and global rate limits.
5. Only now is the body read (8 KiB cap), parsed and validated against a strict schema.
6. The payload (≤ 3 KiB of JSON) is encrypted per device by the `web-push` library (aes128gcm,
   RFC 8291) and signed with VAPID (RFC 8292), then POSTed to each subscription endpoint.
7. 404/410 responses delete the subscription; 429/5xx/network errors are retried at most twice.
8. A delivery record **without title or message** is stored for `HISTORY_RETENTION_DAYS` (default 7).

## Stack

| Choice | Why | Tradeoff |
|---|---|---|
| Node.js 24 LTS, plain `node:http` | One runtime for server, CLI, service worker and tests; no web framework needed for ~25 routes | Hand-written router and validator (small, tested) |
| `node:sqlite` (built in) | No native addon, no extra dependency; WAL + busy timeout is plenty for a single process | Node flags the module "experimental" (release candidate in 24.x); warning is suppressed at startup |
| `web-push` | De-facto standard, maintained Web Push + VAPID implementation | 5 small transitive dependencies |
| `@simplewebauthn/server` | Mature WebAuthn/passkey verification | ~10 transitive dependencies (ASN.1 parsing) |
| Vanilla JS PWA | No build step, no frontend dependencies, strict CSP without `unsafe-inline` | Plain DOM code |
| Caddy | Automatic TLS (internal CA or ACME DNS-01), safe forwarding-header defaults | Second container |
| distroless `nodejs24` (nonroot) | No shell or package manager in the runtime image | Debugging requires `docker cp`/ a debug image |

Runtime dependencies are pinned exactly in `package.json` and locked in `package-lock.json`.
Base images are pinned by digest.

## Modules (`src/`)

| Module | Responsibility |
|---|---|
| `config.js` | Parse environment, read secret files, **fail closed** on missing/invalid values |
| `netacl.js` | CIDR parsing/matching, client IP resolution, trusted-proxy handling |
| `apikeys.js` | Key generation, HMAC hashing, verification, create/list/revoke/rotate |
| `ratelimit.js` | Token buckets (per key, global) and failure counters (brute-force blocks) |
| `validate.js` | Strict schema validation of request bodies |
| `notify.js` | `POST /api/v1/notifications` handler |
| `push.js` | Web Push delivery, retries, expired-subscription cleanup |
| `devices.js` | Subscription validation (endpoint allowlist) and storage |
| `admin/auth.js` | Passkeys (WebAuthn), enrollment tokens, sessions, CSRF |
| `admin/routes.js` | Admin JSON API used by the PWA |
| `audit.js`, `log.js` | Security events in SQLite (no secrets), JSON logs to stdout (no headers, no bodies) |
| `db.js` | SQLite connection, pragmas, migrations, retention purge, online backup |
| `http.js`, `static.js` | Response helpers, security headers, bounded body reader, static PWA files |
| `app.js`, `server.js`, `cli.js` | Request pipeline, process lifecycle and signals, administrative CLI |

## Data model (SQLite)

| Table | Contents | Secrets? |
|---|---|---|
| `api_keys` | public key id, name, description, **HMAC-SHA-256 of the key**, scopes, created/expires/revoked/last-used | hash only |
| `passkeys` | WebAuthn credential id, public key, sign counter, name | public keys only |
| `enrollment_tokens` | SHA-256 of one-time admin enrollment tokens, expiry, used time | hash only |
| `sessions` | SHA-256 of session token, CSRF token, timestamps | hash only (CSRF token is not a credential on its own) |
| `devices` | push endpoint, `p256dh`, `auth`, name, minimum priority, delivery stats | **yes**: subscription secrets, never returned by any API |
| `deliveries` | id, key id, priority, counts, status — **no title/message** | no |
| `audit_events` | type, actor, client IP, small JSON detail | no |
| `settings` | `sending_paused`, WebAuthn user handle | no |

## Important security decisions

1. **API key format** `pgk_<16 hex key id>_<43 char base64url secret>` (256-bit secret from
   `crypto.randomBytes`). The key id is public and allows O(1) lookup without enumerating hashes.
2. **Key hashing: HMAC-SHA-256 with a server-side pepper**, not a password hash. Keys are uniformly
   random 256-bit values, so offline guessing is infeasible and a deliberately slow hash would only
   add a CPU-exhaustion vector. The pepper lives in a secret file outside the database, so a stolen
   database alone cannot be used to verify guesses. Comparison uses `crypto.timingSafeEqual`; an
   unknown key id still performs an HMAC against a dummy value.
3. **Network ACL before authentication.** Unknown networks get `403` before any key is parsed.
   Forwarding headers are honoured *only* when the TCP peer is in `TRUSTED_PROXIES`, and then the
   header must contain exactly one address (Caddy is configured to overwrite it). When a proxy is
   configured, direct connections from anything else are refused (except the loopback health check).
4. **Fail closed configuration.** Missing/invalid `TRUSTED_CIDRS`, `ADMIN_CIDRS`, `/0` ranges,
   missing secrets or a non-HTTPS public origin abort startup.
5. **No default credentials, no open setup endpoint.** The first passkey can only be enrolled with a
   one-time token (15 minutes, hashed at rest) that is created with the CLI inside the container.
   Without an unexpired token, the enrollment endpoint rejects every request.
6. **Admin sessions**: `__Host-` cookie, `Secure; HttpOnly; SameSite=Strict`, 30 min idle / 12 h
   absolute, token hashed at rest. State-changing requests need a per-session CSRF header *and* a
   matching `Origin`.
   WebAuthn challenges are single use, expire after 5 minutes and are capped per client (5) and
   globally (1000); when full, new requests get `429` instead of evicting pending challenges, and
   stale challenges do not count toward the brute-force block.
7. **Brute-force counters** are keyed per IPv4 address or IPv6 /64, are not reset by a
   successful request, and active blocks are never evicted from the bounded in-memory table.
8. **Service keys cannot administer anything.** The admin API accepts only passkey sessions; API keys
   are accepted only by `/api/v1/notifications`.
9. **Subscription endpoint allowlist** (Apple, Google, Mozilla, Microsoft push hosts by default) so a
   registered "device" cannot turn the server into an SSRF proxy.
10. **Content is data, never markup.** The service worker passes title/body as plain strings to
   `showNotification`; the admin UI uses only `textContent`; CSP forbids inline script.
   Notification click always opens the app's own start page — requests cannot supply URLs or actions.
11. **No notification content at rest** by default; logs never contain bodies, headers or keys.

## Threat model (summary)

Assets: ability to push to the phone, service API keys, admin session/passkeys, subscription
secrets (`endpoint`, `p256dh`, `auth`), VAPID private key, pepper.

| Threat | Mitigation | Residual risk |
|---|---|---|
| Internet attacker | App never published; Caddy bound to a LAN address; host firewall; CIDR ACL | Misconfigured port forwarding on the router |
| Malicious/compromised LAN host without a key | Per-service API key required; brute-force blocks; rate limits | Can probe the UI/login page (passkey required) |
| Compromised service host | Can only use *its own* key (only send, optionally not `high`); revoke/rotate one key | Can send spam until revoked |
| Spoofed `X-Forwarded-For` | Header ignored unless TCP peer is the trusted proxy; Caddy overwrites it | Wrong `TRUSTED_PROXIES` value |
| IP spoofing | TCP handshake makes blind spoofing impractical for request/response; keys still required | On-path attacker on same L2 (ARP spoofing) can impersonate an IP — keys and TLS still apply |
| CSRF / XSS on admin UI | SameSite=Strict, CSRF header + Origin check, strict CSP, no `innerHTML` | Browser bugs |
| Stolen DB file / backup | Key hashes need pepper; no notification content | **Subscription secrets are in the DB**: whoever has them can push to the device (with the VAPID key) or at least identify the endpoint — protect backups |
| Compromised backend/host | — | Full compromise: attacker can send arbitrary notifications. Web Push encryption protects payloads **between this server and the browser**, not against this server |
| Apple/Google push service | Payload encrypted end-to-end between server and browser (RFC 8291) | Push service sees metadata: timing, size, endpoint, TTL/urgency |

No application-level end-to-end encryption (beyond Web Push's RFC 8291 encryption) is implemented,
because the sender and the encrypting server are the same trust domain here; claiming more would
be misleading.
