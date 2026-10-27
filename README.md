# Pushgate

A small, self-hosted gateway that lets services on your local network send push notifications to
your iPhone through a Home Screen web app (PWA) and standard Web Push. No native app, no email, no
third-party notification app.

```bash
curl -X POST https://notify.home.example/api/v1/notifications \
  -H "Authorization: Bearer $PUSHGATE_KEY" -H "Content-Type: application/json" \
  -d '{"title":"Production Alert","message":"A background worker has stopped.","priority":"high"}'
```

- One Node.js process + SQLite, behind Caddy for HTTPS. Two runtime dependencies
  (`web-push`, `@simplewebauthn/server`), no frontend dependencies.
- Network allowlist (CIDR) **and** a separate API key per sending service, hashed at rest.
- Passkey-protected admin web app for devices, keys, settings, health and security events.
- Notification contents are never stored; logs never contain keys, bodies or subscription data.

Contents: [Architecture](#architecture) · [Security model](#security-model) · [Setup](#setup) ·
[HTTPS](#https-and-the-reverse-proxy) · [iPhone](#iphone-installation) · [API keys](#api-keys) ·
[Sending](#sending-notifications) · [Operations](#operations) · [Troubleshooting](#troubleshooting-ios-delivery) ·
[Limitations](#known-limitations) · [Development](#development)

## Architecture

```
 LAN service ─HTTPS─▶ Caddy :443 ─HTTP, internal network─▶ pushgate ─HTTPS + VAPID─▶ Apple Web Push ─▶ iPhone PWA
                      (TLS, overwrites X-Forwarded-For)      │  SQLite (/data)
 iPhone admin ─HTTPS─▶ Caddy ─▶ pushgate  (PWA, passkey login, device + key management)
```

A notification request passes, in order: client IP resolution (forwarding header only from the
configured proxy) → CIDR allowlist → brute-force block check → API key verification → scope check →
per-key and global rate limits → kill switches → body read (≤ 8 KiB) and strict validation →
per-device encryption and delivery → response with delivery summary. Details, module layout, data
model and the threat model are in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). The API contract
is [docs/openapi.yaml](docs/openapi.yaml).

**Technology choices.** Node.js 24 (one language for server, CLI, service worker and tests), the
built-in `node:http` and `node:sqlite` (no web framework, no native addon), the maintained
`web-push` library for RFC 8291/8292, `@simplewebauthn/server` for passkeys, vanilla JS for the
PWA, Caddy for TLS, and a distroless non-root runtime image. Tradeoffs: a hand-written router and
validator (small and covered by tests), and `node:sqlite` is still labelled "experimental" in
Node 24 (its warning is suppressed; the API used here is basic and tested). A single process with
in-memory rate limits means one instance only, which matches the use case.

## Security model

### Four separate mechanisms

| Mechanism | Protects against | Does **not** protect against |
|---|---|---|
| **Network access control** (`TRUSTED_CIDRS`, `ADMIN_CIDRS`, firewall, bound interface) | Anything outside your LAN reaching the API or UI | Any host *inside* the allowed range — a private IP is not proof of trust |
| **Authentication** (per-service API key; passkeys for the admin) | Hosts on the LAN that do not hold a key; one service acting as another | A compromised service using *its own* key until you revoke it |
| **Web Push encryption** (RFC 8291 aes128gcm + VAPID) | Apple/Google/Mozilla push services and the network reading payloads | A compromised pushgate host/backend — it holds the plaintext and the VAPID key |
| **Application-level end-to-end encryption** | — | **Not implemented.** The sender and the encrypting server are the same trust domain here, so it would add complexity without a meaningful guarantee |

HTTPS (Caddy) protects requests between your services/phone and pushgate on the LAN.

### Threat assumptions

- The pushgate host and its Docker daemon are trusted. Anyone with shell/Docker access on it is an
  administrator (they can run the CLI, read the secrets and the database).
- The LAN is **not** fully trusted: other devices, guests, IoT gear or a compromised machine may
  be on it. Hence API keys are mandatory even from trusted ranges, and each service has its own
  key with the minimum scope (`notifications:send`; `high` priority only if granted).
- A compromised sending host can spam notifications with its own key until revoked; it cannot read
  or manage other keys (keys are only hashes; the admin API never accepts API keys).
- Apple's push service sees metadata (timing, size, urgency, TTL, endpoint), not content.

### Network risks you must consider

- **Shared Wi-Fi / guest networks:** if guests share the subnet in `TRUSTED_CIDRS`, they pass the
  network check (they still need a key). Put servers on a separate VLAN and list only that range,
  or list individual hosts (`192.168.1.20/32`).
- **VPNs:** a VPN that routes remote clients into an allowed range makes them "local". Decide
  explicitly whether your VPN subnet belongs in `ADMIN_CIDRS` (phone management on the go) and
  keep it out of `TRUSTED_CIDRS` unless needed.
- **Subnet overlap:** a VPN, Docker network or second router using the same private range as your
  LAN can make foreign traffic look local. Avoid overlapping ranges; Docker's internal
  `172.31.250.0/29` must not be in `TRUSTED_CIDRS`.
- **IP spoofing:** TCP makes blind spoofing of a request/response impractical, but an attacker on the
  same L2 segment (ARP spoofing) can impersonate an address. The API key still applies; TLS keeps
  it from being sniffed.
- **Misconfigured reverse proxy:** pushgate trusts `X-Forwarded-For` only from `TRUSTED_PROXIES`
  and only if it holds exactly one address. The shipped Caddyfile overwrites the header. If you
  replace Caddy, your proxy **must overwrite** (not append) the header, and `TRUSTED_PROXIES` must
  contain only the proxy's address. Never add `trusted_proxies` to the Caddyfile.
- **Docker NAT:** with some setups (Docker Desktop, rootless Docker, IPv6 via userland proxy) the
  client address seen behind the published port becomes a gateway address. Check "Your IP (as seen
  by server)" on the Health card — it must show your phone's real LAN address. If it shows a
  `172.x`/`192.168.65.x` gateway, fix the networking (on Linux: Docker Engine with iptables NAT,
  `userland-proxy` disabled, IPv4 address in `LISTEN_ADDRESS`) instead of trusting that range.

### Which control belongs to which layer

| Layer | Control |
|---|---|
| Router | No port forwarding to the server. |
| Host firewall | Allow `443/tcp` to the server only from LAN ranges that need it; allow outbound `443/tcp` (Web Push services, ACME). See [Ports and firewall](#ports-and-firewall). |
| Docker / Compose | Caddy publishes **one** port on **one** host address (`LISTEN_ADDRESS`); the backend publishes nothing and is on an `internal` network with Caddy; non-root, read-only, no capabilities. |
| Reverse proxy | TLS; overwrites `X-Forwarded-For`; 64 KiB request cap. |
| Application | Fails closed on bad config; CIDR check on every request (before authentication); refuses direct (non-proxy) connections when a proxy is configured; keys, scopes, rate limits, brute-force blocks, CSRF/Origin checks, strict schemas, CSP. |

### Secrets: environment variables vs. Compose secrets

Environment variables are visible in `docker inspect`, in `/proc/<pid>/environ`, are inherited by
child processes and frequently end up in logs or support bundles. Compose `secrets:` with `file:`
are bind-mounted read-only at `/run/secrets/<name>`; only the path appears in the container
configuration. They are **not** encrypted at rest on the host (unlike Swarm secrets), so the
host files must be protected (`0400`, owned by uid 65532, outside the repository, included in
encrypted backups). Pushgate reads secrets **only from files**; `.env` holds non-secret settings.

| Secret | Where | Effect if lost | Effect if leaked |
|---|---|---|---|
| `api_key_pepper` | `secrets/` (Compose secret) | All API keys stop working (recreate them) | With a DB copy, allows checking key guesses (still 256-bit keys) |
| `vapid_private_key` | `secrets/` (Compose secret) | All devices must re-subscribe | With the subscription data, allows pushing to your devices |
| SQLite DB | `pushgate-data` volume | Keys, devices, passkeys, history | Subscription endpoints/keys, key hashes, audit data |

API keys are stored as **HMAC-SHA-256(pepper, key)**. Keys contain 256 bits from a CSPRNG, so a
slow password hash (Argon2/bcrypt) adds no meaningful protection and would create a CPU-exhaustion
vector; the pepper (outside the DB) ensures a stolen database alone cannot verify guesses.
Verification uses a public key id for lookup and `crypto.timingSafeEqual` for comparison.

Containers are one layer, not a complete security boundary: a kernel or Docker vulnerability, a
mounted Docker socket (not used here) or a privileged container could break isolation.

## Setup

Requirements: Linux host with Docker Engine + Compose v2, a hostname for the server on your LAN,
outbound HTTPS from the host, and an iPhone on iOS/iPadOS **16.4 or later**.

```bash
git clone <this repository> pushgate && cd pushgate
cp .env.example .env
$EDITOR .env                 # replace EVERY value, especially TRUSTED_CIDRS / ADMIN_CIDRS
scripts/gen-secrets.sh       # creates secrets/api_key_pepper and secrets/vapid_private_key
sudo chown 65532:65532 secrets/* && sudo chmod 400 secrets/*
docker compose up -d --build
docker compose ps            # both services should become "healthy"
```

`TRUSTED_CIDRS=192.168.1.0/24,10.0.0.0/24` in `.env.example` are **examples only**. Replace them
with your actual, narrowest possible ranges. Pushgate refuses to start if `TRUSTED_CIDRS` or
`ADMIN_CIDRS` is missing, invalid, contains host bits, or contains `/0`.

### Initial administrator (one-time token)

There are no default credentials and no open setup endpoint. On the server:

```bash
docker compose exec pushgate /nodejs/bin/node src/cli.js enroll-token
```

This prints a one-time token valid for 15 minutes (stored only as a hash). Open the app on the
iPhone (ideally already from the Home Screen, see below), use **Set up with enrollment token**,
paste the token and create a passkey (stored in iCloud Keychain). The token is consumed atomically
with the passkey registration. Until an administrator exists, the sending API answers `503`
(`REQUIRE_SETUP_BEFORE_SENDING=true`).

Tip: `alias pg-cli='docker compose exec pushgate /nodejs/bin/node src/cli.js'` — `pg-cli --help`
lists all commands.

## HTTPS and the reverse proxy

Service workers, Web Push and passkeys require a secure context, so the iPhone must trust the
server's certificate. Pick one option in [deploy/Caddyfile](deploy/Caddyfile):

1. **ACME DNS-01 (recommended).** Use a real domain you own (e.g. `notify.home.example.com`)
   that resolves to the server's LAN IP in your local DNS. Build Caddy with your DNS provider
   plugin (`xcaddy build --with github.com/caddy-dns/<provider>`) and use `tls { dns <provider> ... }`.
   Publicly trusted certificate; nothing exposed to the internet.
2. **Own certificates** issued elsewhere: mount them read-only and use `tls /certs/fullchain.pem /certs/key.pem`.
3. **Caddy's internal CA (default in the file).** Export the root certificate and install it on the iPhone:
   ```bash
   docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt ./caddy-root.crt
   ```
   Transfer it to the iPhone (AirDrop/Files), install it in *Settings → General → VPN & Device
   Management*, then enable it in *Settings → General → About → Certificate Trust Settings*.
   Trusting a private CA lets anyone holding its key impersonate any site to that phone — keep the
   Caddy data volume protected. This project's tests do not cover Web Push with a user-installed
   root; if registration fails, use option 1.

`PUBLIC_ORIGIN` must exactly match the URL you open on the phone (scheme, host, and port if not
443); passkeys are bound to that hostname.

If you use another proxy (nginx, Traefik), it must (a) terminate TLS, (b) **overwrite**
`X-Forwarded-For` with the client address (nginx: `proxy_set_header X-Forwarded-For $remote_addr;`),
(c) be the only address in `TRUSTED_PROXIES`, and (d) be the only way to reach the backend.

### Ports and firewall

| Port | Direction | Purpose |
|---|---|---|
| 443/tcp on `LISTEN_ADDRESS` | inbound from LAN | Caddy (API, PWA, admin) |
| 8080/tcp | internal Docker network only | pushgate backend — **never published** |
| 443/tcp | outbound | Apple/Google/Mozilla push services; ACME if used |

Docker-published ports bypass `ufw`/`INPUT` rules. Restrict them in the `DOCKER-USER` chain, e.g.:

```bash
# allow LAN ranges to reach published container ports, drop everything else from the LAN interface
sudo iptables -I DOCKER-USER -i eth0 -j DROP
sudo iptables -I DOCKER-USER -i eth0 -s 192.168.1.0/24 -p tcp --dport 443 -j RETURN
sudo iptables -I DOCKER-USER -i eth0 -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
```

(Persist with your distribution's mechanism; adapt interface and ranges.) Binding to
`LISTEN_ADDRESS` already keeps the port off other interfaces.

## iPhone installation

Web Push on iOS works **only** for web apps added to the Home Screen, on iOS/iPadOS 16.4+.
It does not work in a normal Safari tab.

1. Open `PUBLIC_ORIGIN` in Safari (on the network allowed by `ADMIN_CIDRS`).
2. Share → **Add to Home Screen** → Add. Open Pushgate from the new icon.
3. Sign in with the passkey (or enroll, see above).
4. Under **This device**, tap **Enable notifications on this device** and allow notifications when
   iOS asks. The prompt only appears after a tap; if you dismiss it, re-enable in *Settings →
   Notifications → Pushgate*.
5. Tap **Send test notification**.

The phone does not need to be on the LAN to *receive* notifications (they come via Apple), only to
manage the app. Each device can set a minimum priority (e.g. only `high`).

## API keys

Create one key per sending service, in the app (**Service API keys → Create key**) or the CLI:

```bash
pg-cli keys create --name backup-job --description "nightly borg backup" --expires-days 365
pg-cli keys create --name alertmanager --allow-high   # may send priority "high"
pg-cli keys list
pg-cli keys rotate <key-id> --grace-hours 24          # new key; old one works for 24 h more
pg-cli keys revoke <key-id>                           # immediate
```

The full key (`pgk_<id>_<secret>`) is shown **once**; only its HMAC is stored. Store it in the
service's own secret store, not in shell history. Rotation and revocation affect only that one
service. Revocation is effective on the next request (keys are checked against the database on
every request).

## Sending notifications

```bash
# minimal
curl -sS https://notify.home.example/api/v1/notifications \
  -H "Authorization: Bearer $PUSHGATE_KEY" -H "Content-Type: application/json" \
  -d '{"title":"Backup finished","message":"borg: 12.3 GB, 0 errors"}'

# with options: replaces an earlier notification with the same tag; kept 1 h if the phone is offline
curl -sS https://notify.home.example/api/v1/notifications \
  -H "Authorization: Bearer $PUSHGATE_KEY" -H "Content-Type: application/json" \
  -d '{"title":"Disk almost full","message":"/var at 93%","priority":"high","tag":"disk-var","ttl":3600}'
```

Fields: `title` (≤ 200 chars, single line), `message` (≤ 2000 chars), optional `priority`
(`low` | `normal` | `high`), `tag` (`[A-Za-z0-9_-]{1,32}`), `ttl` (seconds). Unknown fields, URLs,
actions or HTML are rejected or never interpreted; text is displayed as plain text. The encoded
notification must fit 3 KiB (Web Push limit) or the API returns `413`.

Response: `{"id":"…","status":"delivered|partial|failed|no_devices|filtered","devices":{…}}`.
`status: failed` is returned with HTTP 502 so senders can retry. Errors use
`{"error":{"code","message","request_id"}}` with `400/401/403/405/413/415/429/503`
(see [docs/openapi.yaml](docs/openapi.yaml)).

## Operations

**Health:** `docker compose ps` (container health check hits `/healthz` over loopback); the app's
Health card shows version, DB check, sending state, key/device counts and recent deliveries
(metadata only, kept `HISTORY_RETENTION_DAYS`).

**Security events:** the app's *Security events* list (or the `audit_events` table) records key
creation/rotation/revocation, logins, enrollments, device changes, rejected requests (throttled to
one stored event per type and IP per minute; all are logged to stdout). Never contains keys, tokens,
subscription data or notification content. Retention: `AUDIT_RETENTION_DAYS`.

**Backup** (online, consistent):

```bash
pg-cli backup --out /data/backup-$(date +%F).db
docker compose cp pushgate:/data/backup-$(date +%F).db ./backups/
docker compose exec pushgate /nodejs/bin/node -e "require('fs').unlinkSync('/data/backup-$(date +%F).db')"
```

Back up `secrets/` and `.env` too, separately and encrypted — without the pepper, restored API keys
are useless; without the VAPID key, devices must re-subscribe.

**Restore:**

```bash
docker compose stop pushgate
docker run --rm --user 65532:65532 -v pushgate_pushgate-data:/data -v "$PWD/backups:/b:ro" \
  busybox:1.37 sh -c 'rm -f /data/pushgate.db-wal /data/pushgate.db-shm && cp /b/backup-YYYY-MM-DD.db /data/pushgate.db'
docker compose start pushgate
```

**Upgrade:**

```bash
pg-cli backup --out /data/pre-upgrade.db
git pull                       # review the changes, especially Dockerfile/compose.yaml
docker compose up -d --build   # schema migrations run automatically at start
docker compose ps
```

Base images are pinned by digest; update tag + digest in `Dockerfile`/`compose.yaml` deliberately,
then run `npm run test:container` and `npm run scan:image`.

**Graceful shutdown:** `docker compose stop` sends SIGTERM; pushgate stops accepting connections,
lets in-flight deliveries finish (≤ 10 s) and closes the database.

### Recovery procedures

| Situation | Action |
|---|---|
| Lost/broken passkey | `pg-cli enroll-token`, enroll a new passkey in the app, remove the old one under *Passkeys*. |
| Admin session possibly stolen | `pg-cli sessions revoke-all`, review *Security events*. |
| Service key leaked | `pg-cli keys revoke <id>` (or rotate). Other services are unaffected. |
| Device lost | Remove it under *Devices* (or `pg-cli devices remove <id>`); remove its passkey if it held one. |
| Host compromised | Treat everything as leaked: new `secrets/` (new pepper ⇒ recreate all keys; new VAPID key ⇒ re-subscribe devices), new passkeys, reinstall host. |
| Sending storm | Toggle *Pause all sending* in the app, or set `NOTIFICATIONS_ENABLED=false` and `docker compose up -d`. |

## Troubleshooting iOS delivery

- **No "Enable notifications" button / "not supported":** open the app from the Home Screen icon,
  not Safari; check iOS ≥ 16.4; the page must be HTTPS with a trusted certificate.
- **Permission prompt never appears:** it needs a tap; if previously denied, enable it in
  *Settings → Notifications → Pushgate* (only exists after adding to the Home Screen).
- **API says `delivered` but nothing shows:** check Focus/Do Not Disturb and notification summary
  settings; `low` urgency may be delayed by iOS; the device's *minimum priority* may filter it
  (`filtered` in the response).
- **`failed` with status 403 on the device:** VAPID problem — `VAPID_SUBJECT` must be a valid
  `mailto:` or `https:` URL; if the VAPID key changed, re-enable notifications on each device.
- **Device disappears from the list:** Apple returned 404/410 (app removed from Home Screen,
  notifications disabled, or subscription expired). Re-enable on the device.
- **Server cannot reach Apple:** outbound HTTPS to `*.push.apple.com` must be allowed; failures
  show as `failed` with no status (network error) after bounded retries.
- **403 on everything from the phone:** its address is not in `ADMIN_CIDRS`; compare with what the
  server logs as `ip` for the rejected request (`docker compose logs pushgate`).

## Known limitations

- Web Push on iOS requires 16.4+ and a Home Screen web app; Apple may throttle or delay
  notifications, and delivery is best-effort (no delivery receipts).
- Delivery is synchronous; nothing is queued across restarts. A request that fails (`502`) should be
  retried by the sender.
- Rate limits and brute-force blocks are in memory (reset on restart) and assume a single instance.
- One administrator identity (with multiple passkeys); no per-service routing to specific devices.
- `node:sqlite` is marked experimental in Node 24 (warning suppressed).
- Passkey login in the PWA needs a passkey provider on the device (iCloud Keychain or similar).
- The admin UI has not been verified on every iOS version; the automated tests exercise the server
  side (including a full software-authenticator passkey flow), not Safari itself.

## Development

```bash
npm ci
node src/cli.js gen-secrets --out .dev/secrets
npm run dev            # http://localhost:8080 with .env.development (localhost-only CIDRs)
node --env-file=.env.development src/cli.js enroll-token
```

Only `http://localhost` is accepted as a non-HTTPS origin; all other checks (CIDRs, keys, CSRF,
CSP, cookies) are identical to production.

### Tests and security checks

```bash
npm run lint
npm test                  # unit + HTTP security tests (node:test)
npm run audit             # npm audit, production dependencies
npm run test:container    # builds and runs the real compose stack: hardening, TLS proxy, restart, recreation
npm run scan:image        # npm audit + Trivy scan of the image (fails on HIGH/CRITICAL)
```

CI ([.github/workflows/ci.yml](.github/workflows/ci.yml)) runs all of them on every push and weekly.
