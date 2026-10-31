# Pushgate

A small, self-hosted gateway that lets your services send push notifications to your iPhone through a Home Screen web app (PWA) and standard Web Push. No native app, no email, no
third-party notification app.

```bash
curl -X POST https://notify.home.example/api/v1/notifications \
  -H "Authorization: Bearer $PUSHGATE_KEY" -H "Content-Type: application/json" \
  -d '{"title":"Production Alert","message":"A background worker has stopped.","priority":"high"}'
```

- One Node.js container + SQLite, published on `127.0.0.1` only, behind your host's HTTPS
  reverse proxy. Two runtime dependencies
  (`web-push`, `@simplewebauthn/server`), no frontend dependencies.
- Network allowlist (CIDR) **and** a separate API key per sending service, hashed at rest.
- Passkey-protected admin web app, reachable from any network by default, for devices, keys,
  settings, health and security events. See [How it is secured](#how-it-is-secured).
- Notification contents are never stored; logs never contain keys, bodies or subscription data.

Contents: [Setup](#setup) · [How it is secured](#how-it-is-secured) · [Architecture](#architecture) · [Security model](#security-model) ·
[HTTPS](#https-and-the-reverse-proxy) · [iPhone](#iphone-installation) · [API keys](#api-keys) ·
[Sending](#sending-notifications) · [Operations](#operations) · [Troubleshooting](#troubleshooting-ios-delivery) ·
[Limitations](#known-limitations) · [Development](#development) · [License](#license)

## Setup

The default setup: pushgate runs on a server with a public DNS name, you can open the web app and
set up your iPhone **from any network** (no VPN), and only the services you list may send
notifications. Receiving notifications never needs any of this: Apple delivers them to the phone
wherever it is.

**You need:** a Linux server with Docker Engine + Compose v2 and nginx (or Caddy) on the host; a
DNS name pointing at the server (e.g. `notify.example.com`); ports 80/443 reachable for the
certificate and the web app; the Docker subnet `172.20.2.0/24` and one port in 2000-2999 free;
an iPhone on iOS/iPadOS **16.4 or later**.

### 1. Install and configure

```bash
git clone <this repository> pushgate && cd pushgate
cp .env.example .env
$EDITOR .env
```

In `.env` set at least:

| Setting | Value |
|---|---|
| `PUBLIC_ORIGIN` | `https://notify.example.com` (your DNS name, exactly as you will open it) |
| `ADMIN_PUBLIC` | `true` (already the default): web app reachable from any network |
| `TRUSTED_CIDRS` | where your *sending* services connect from, e.g. `203.0.113.7/32`. See the comments in `.env.example`; unsure? Start with your best guess and read the refused address from *Security events* later |
| `VAPID_SUBJECT` | `mailto:you@example.com` (Apple requires a real contact) |

### 2. Create the secrets and start

```bash
scripts/gen-secrets.sh          # secrets/ (0700) with api_key_pepper + vapid_private_key (0444)
docker compose up -d --build
docker compose ps               # pushgate becomes "healthy"
```

### 3. HTTPS in front of it

```bash
certbot --nginx -d notify.example.com     # publicly trusted certificate
```

Then copy the `server { ... }` block and the `limit_req_zone` line from
[deploy/nginx-host.conf](deploy/nginx-host.conf) into your nginx site (adjust `server_name` and
the certificate paths) and reload: `nginx -t && systemctl reload nginx`. Caddy users: see
[deploy/Caddyfile.host](deploy/Caddyfile.host). Check `https://notify.example.com` loads the app.

### 4. Create the administrator passkey (one-time token)

There are no default passwords and no open setup page. On the server:

```bash
docker compose exec pushgate /nodejs/bin/node src/cli.js enroll-token
```

This prints a token valid for 15 minutes and for one use. Then on the iPhone (any network):

1. Open `https://notify.example.com` in **Safari** → Share → **Add to Home Screen** → Add.
   (Web Push on iOS only works in Home Screen web apps, iOS 16.4+.)
2. Open **Pushgate from the Home Screen icon**.
3. **Set up with enrollment token**: paste the token, tap **Create passkey**, confirm with Face ID.
   The passkey is stored in your iCloud Keychain; from now on you sign in with Face ID.
4. Under **This device** tap **Enable notifications on this device** and allow notifications.
5. Tap **Send test notification**.

### 5. Connect your services

In the app, **Service API keys → Create key** (one per service); copy the key, it is shown once.
Use it as in [Sending notifications](#sending-notifications). If a sender gets `403`, its address
is not in `TRUSTED_CIDRS`: the app's *Security events* list shows it as `network.rejected`
(zone `api`) with the address to add. Edit `.env`, then `docker compose up -d`.

Tip: `alias pg-cli='docker compose --project-directory ~/pushgate exec pushgate /nodejs/bin/node src/cli.js'`
lets you run `pg-cli enroll-token`, `pg-cli keys list`, ... from any directory.

### Restricting the web app to your own networks instead

If you prefer the web app to be reachable only from home or a VPN, replace `ADMIN_PUBLIC=true`
with `ADMIN_CIDRS=<networks>` (e.g. `192.168.1.0/24,10.8.0.0/24`). pushgate refuses to start if
neither or both are set, so the choice is always explicit.

## How it is secured

In plain terms, here is what an attacker on the internet runs into, from the outside in.

**The sending API is not public.** Only addresses in `TRUSTED_CIDRS` can even reach
`/api/v1/notifications`; everything else is refused before an API key is looked at. On top of
that every service needs its own key (256 random bits, stored only as a keyed hash, revocable
individually), with rate limits and temporary blocks after failed attempts. A block only stops
further failed attempts: a sender with a valid key is still served, so a neighbour behind the same
router cannot silence your alerts. `0.0.0.0/0` (and any range wider than `/8` for IPv4 or `/7` for
IPv6) is refused in every setting, so the API cannot be opened to everyone by mistake.

**The web app is public, but useless without your passkey.**

- *Login* uses passkeys only: no passwords that could be guessed, phished or leaked. A passkey
  is a key pair; the private half never leaves your iPhone/iCloud Keychain, and it only works on
  your exact domain, so a look-alike phishing site gets nothing.
- *Creating the first passkey* (or a recovery passkey) requires a one-time token that can only be
  created on the server's command line, expires after 15 minutes and works once. Someone who finds
  your site cannot register their own passkey.
- *Sessions* after login live in a cookie the page's scripts cannot read (`HttpOnly`), that is only
  sent over HTTPS to your exact host (`__Host-`, `Secure`) and never with requests started by
  other sites (`SameSite=Strict`). Every change additionally needs a per-session token and a
  matching `Origin`, which blocks cross-site request forgery. Sessions expire after 30 minutes idle
  and 12 hours at most.
- *Sensitive changes* (adding or removing passkeys, creating or rotating API keys, registering a
  device) need a passkey confirmation from the last 5 minutes, so a stolen session cookie alone
  cannot take over the account. The app asks you to confirm with Face ID when needed.
- *Security alerts*: sign-ins, passkey changes, enrollments, API key changes (including
  revocation), device changes (including minimum-priority filters) and pausing are pushed as
  high-priority notifications to every registered device (a removed device is told too). A recovery enrollment signs out every other session.
- *Login challenges* (the random value your passkey signs) are signed tokens rather than server
  memory, so floods of login requests cannot fill a table and block your own sign-in; each
  challenge works once and for 5 minutes.
- *Abuse limits*: login and enrollment endpoints are rate limited per client inside the app
  (`RATE_LIMIT_ADMIN_ANONYMOUS_PER_MINUTE`, default 30) and in the nginx example; repeated failures
  block the client temporarily.
- *Browser hardening*: a strict Content Security Policy (only the app's own scripts can run),
  everything is shown as text and never as HTML, no third-party resources, and a `noindex` header
  keeps search engines away.

**What a stranger can still see:** that a Pushgate login page exists at your address, and its
static files (HTML/JS/CSS, which contain no secrets). They cannot list keys, devices or events,
send notifications, or register a device without logging in.

**What this does not protect against:** someone who controls the server itself (they can read the
secrets and send anything), someone who has your unlocked iPhone with the passkey, and a large
denial-of-service attack (that is your hosting provider's / a CDN's job). The code has thorough
automated security tests but no external audit.

## Architecture

```
 LAN service ─HTTPS─▶ host reverse proxy :443 ─HTTP─▶ 127.0.0.1:2580 ─▶ pushgate 172.20.2.10:8080 ─HTTPS + VAPID─▶ Apple Web Push ─▶ iPhone PWA
                      (TLS, overwrites X-Forwarded-For)   (loopback-only publish)      │  SQLite (/data)
 iPhone admin ─HTTPS─▶ host reverse proxy ─▶ pushgate  (PWA, passkey login, device + key management)

 Docker network 172.20.2.0/24; its gateway 172.20.2.1 is how loopback-published traffic arrives
 and is the only TRUSTED_PROXIES entry. Published ports: 127.0.0.1 only, range 2000-2999.
```

A notification request passes, in order: client IP resolution (forwarding header only from the
configured proxy) → CIDR allowlist → API key verification (failures count toward a per-client block) → scope check →
per-key and global rate limits → kill switches → body read (≤ 8 KiB) and strict validation →
per-device encryption and delivery → response with delivery summary. Details, module layout, data
model and the threat model are in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). The API contract
is [docs/openapi.yaml](docs/openapi.yaml).

**Technology choices.** Node.js 24 (one language for server, CLI, service worker and tests), the
built-in `node:http` and `node:sqlite` (no web framework, no native addon), the maintained
`web-push` library for RFC 8291/8292, `@simplewebauthn/server` for passkeys, vanilla JS for the
PWA, your existing host reverse proxy for TLS (examples for Caddy and nginx in `deploy/`), and a
distroless non-root runtime image. Tradeoffs: a hand-written router and
validator (small and covered by tests), and `node:sqlite` is still labelled "experimental" in
Node 24 (its warning is suppressed; the API used here is basic and tested). A single process with
in-memory rate limits means one instance only, which matches the use case.

## Security model

### Four separate mechanisms

| Mechanism | Protects against | Does **not** protect against |
|---|---|---|
| **Network access control** (`TRUSTED_CIDRS` for sending; optional `ADMIN_CIDRS`; loopback-only publish) | Anyone outside the listed addresses reaching the sending API (and the web app, if `ADMIN_CIDRS` is used) | Any host *inside* the allowed range — a private IP is not proof of trust |
| **Authentication** (per-service API key; passkeys for the admin) | Hosts on the LAN that do not hold a key; one service acting as another | A compromised service using *its own* key until you revoke it |
| **Web Push encryption** (RFC 8291 aes128gcm + VAPID) | Apple/Google/Mozilla push services and the network reading payloads | A compromised pushgate host/backend — it holds the plaintext and the VAPID key |
| **Application-level end-to-end encryption** | — | **Not implemented.** The sender and the encrypting server are the same trust domain here, so it would add complexity without a meaningful guarantee |

HTTPS (host reverse proxy) protects requests between your services/phone and pushgate on the LAN.

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
  LAN can make foreign traffic look local. Avoid overlapping ranges; the Docker network
  `172.20.2.0/24` must never be in `TRUSTED_CIDRS` or `ADMIN_CIDRS`.
- **IP spoofing:** TCP makes blind spoofing of a request/response impractical, but an attacker on the
  same L2 segment (ARP spoofing) can impersonate an address. The API key still applies; TLS keeps
  it from being sniffed.
- **Misconfigured reverse proxy:** pushgate trusts `X-Forwarded-For` only from `TRUSTED_PROXIES`
  (the Docker network gateway `172.20.2.1`) and only if it holds exactly one address. Your host
  proxy **must overwrite** (not append) the header with the TCP peer address and must not itself
  trust client-supplied forwarding headers (no `trusted_proxies` in Caddy, no `realip` module in
  nginx). See [deploy/](deploy/).
- **Loopback publishing:** traffic to `127.0.0.1:2580` reaches the container from the network
  gateway, so **every process on the host** that can open that port can claim any client address
  in `X-Forwarded-For`. The host is inside the trust boundary (see threat assumptions), and API
  keys are still required.
- **Verify the client address:** "Your IP (as seen by server)" on the Health card must show your
  phone's real LAN address with "(via proxy)". If requests are refused and the logs show
  `172.20.2.1` or another internal address, the host proxy is not setting `X-Forwarded-For`.

### Which control belongs to which layer

| Layer | Control |
|---|---|
| Router | No port forwarding to the server. |
| Host firewall | Allow the host proxy's `443/tcp` only from LAN ranges that need it; allow outbound `443/tcp` (Web Push services, ACME). See [Ports and firewall](#ports-and-firewall). |
| Docker / Compose | One port, published on `127.0.0.1` only (range 2000-2999); one network `172.20.2.0/24` with a fixed gateway; non-root, read-only, no capabilities, `no-new-privileges`, resource limits. |
| Host reverse proxy | TLS; overwrites `X-Forwarded-For`; 64 KiB request cap; optional IP allowlist. |
| Application | Fails closed on bad config; CIDR check on every request (before authentication); refuses connections that do not come from the trusted proxy (the gateway); keys, scopes, rate limits, brute-force blocks, CSRF/Origin checks, strict schemas, CSP. |

### Secrets: environment variables vs. Compose secrets

Environment variables are visible in `docker inspect`, in `/proc/<pid>/environ`, are inherited by
child processes and frequently end up in logs or support bundles. Compose `secrets:` with `file:`
are bind-mounted read-only at `/run/secrets/<name>`; only the path appears in the container
configuration. They are **not** encrypted at rest on the host (unlike Swarm secrets), so the
host files must be protected (outside the repository, included in encrypted backups). Pushgate
reads secrets **only from files**; `.env` holds non-secret settings.

**Secret file permissions.** The `secrets/` directory is `0700` (owned by the user who runs
`docker compose`, usually root) and the files in it are `0444`. Other host users cannot reach
the files because they cannot enter the directory. Compose bind-mounts each *file* directly to
`/run/secrets/<name>`, so the container never needs the directory, and `0444` lets the container
user read it whatever host uid it maps to. Matching a host uid instead (e.g. `chown 65532`) breaks
under Docker user-namespace remapping (`userns-remap`) and rootless Docker, where container uid
65532 is a different host uid. `scripts/gen-secrets.sh` creates this layout;
`scripts/gen-secrets.sh --fix-permissions` repairs it. On SELinux hosts also label the files:
`chcon -t container_file_t secrets/*`. Keep the directory `0700` when copying or restoring it.

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

## HTTPS and the reverse proxy

pushgate is published only on `127.0.0.1:${PUSHGATE_PORT}` (default `2580`), so all traffic goes
through the reverse proxy on the host. Examples: [deploy/nginx-host.conf](deploy/nginx-host.conf)
and [deploy/Caddyfile.host](deploy/Caddyfile.host). Whatever proxy you use must:

1. terminate TLS with a certificate the iPhone trusts (service workers, Web Push and passkeys
   require a secure context; Let's Encrypt is ideal);
2. forward to `http://127.0.0.1:2580` and **overwrite** `X-Forwarded-For` with the TCP peer
   address (Caddy: `header_up X-Forwarded-For {remote_host}`; nginx:
   `proxy_set_header X-Forwarded-For $remote_addr;`), and drop `Forwarded`/`X-Real-IP`;
3. not trust forwarding headers from its own clients.

pushgate accepts forwarded requests only from the Docker network gateway `172.20.2.1`
(`TRUSTED_PROXIES`, set in `compose.yaml`), requires exactly one address in the header, and then
checks that address against `TRUSTED_CIDRS` (and `ADMIN_CIDRS` if you use it). Requests without
the header are refused.

For a server that is *not* reachable from the internet (LAN only), use a certificate from ACME
DNS-01 or your own CA; with a private CA, install its root on the iPhone (*Settings → General →
VPN & Device Management*, then enable full trust in *Settings → General → About → Certificate
Trust Settings*). This project's tests do not cover Web Push with a user-installed root.

`PUBLIC_ORIGIN` must exactly match the URL you open on the phone (scheme, host, and port if not
443); passkeys are bound to that hostname.

### Ports and firewall

| Port | Bound to | Purpose |
|---|---|---|
| `2580/tcp` (`PUSHGATE_PORT`, 2000-2999) | `127.0.0.1` only | pushgate, for the host reverse proxy |
| 8080/tcp | container only (`172.20.2.10`) | pushgate inside the Docker network, not published |
| 443/tcp (and 80 for certbot) | host public address | host reverse proxy (web app, API) |
| 443/tcp outbound | — | Apple/Google/Mozilla push services; ACME |

Because the container port is published on loopback only, no `DOCKER-USER` rules are needed for
it. With `ADMIN_CIDRS` instead of `ADMIN_PUBLIC`, you can additionally restrict `443/tcp` in the
host firewall (e.g. `ufw allow from 192.168.1.0/24 to any port 443 proto tcp`).

### Docker network

All Docker addresses come from `172.20.2.0/24` (network `pushgate`, gateway `172.20.2.1`,
container `172.20.2.10`). They are set in `compose.yaml` and can be overridden with
`PUSHGATE_SUBNET`, `PUSHGATE_GATEWAY` and `PUSHGATE_IP` in `.env` (the gateway override also
changes `TRUSTED_PROXIES`). Compose refuses to start if another Docker network already uses an
overlapping range.

## iPhone installation

Web Push on iOS works **only** for web apps added to the Home Screen, on iOS/iPadOS 16.4+.
It does not work in a normal Safari tab. Step-by-step: [Setup, step 4](#4-create-the-administrator-passkey-one-time-token).
Notification permission is only requested after you tap **Enable notifications**; if you dismissed
the prompt, re-enable it in *Settings → Notifications → Pushgate*. Each device can set a minimum
priority (e.g. only `high`).

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
actions or HTML are rejected or never interpreted; text is displayed as plain text, and control,
invisible-format and line-separator characters are rejected. The notification title always starts
with the sending key's name (`backup-job: Backup finished`), so one service cannot pose as another.
A `tag` only replaces notifications of the same service (the key and its rotated successors); it is
scoped and hashed before it reaches the push service. The encoded notification must fit 3 KiB
(Web Push limit) or the API returns `413`.

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
one stored event per type and client (IPv4 address or IPv6 /64) per minute and 60 in total per
minute, the rest summarised as `audit.suppressed`; all are logged to stdout). Never contains keys, tokens,
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
  busybox:1.37@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e sh -c 'rm -f /data/pushgate.db-wal /data/pushgate.db-shm && cp /b/backup-YYYY-MM-DD.db /data/pushgate.db'
docker compose start pushgate
```

**Upgrade:**

```bash
pg-cli backup --out /data/pre-upgrade.db
git pull                       # review the changes, especially Dockerfile/compose.yaml
docker compose up -d --build   # schema migrations run automatically at start
docker compose ps
```

Behaviour changes in the security hardening release (October 2026), to check when upgrading
from an earlier version:

- Notification titles start with the sending key's name (`backup-job: Backup finished`). Rename keys
  whose names are not meant to be read on the lock screen.
- Tags only replace notifications from the same service, and tags sent before the upgrade no longer
  match new ones.
- Titles and messages with invisible format characters (zero-width spaces, BOM, bidi marks) are
  rejected with `400`. Emoji (including flags) and ZWNJ are allowed.
- Adding/removing passkeys, creating/rotating API keys and registering devices need a passkey
  confirmation from the last 5 minutes; sessions from before the upgrade confirm once.
- Sign-ins and security-relevant changes are pushed to every device as high-priority alerts.
- `TRUSTED_CIDRS`, `ADMIN_CIDRS` and `TRUSTED_PROXIES` ranges wider than `/8` (IPv4) or `/7` (IPv6)
  stop pushgate from starting.
- The image's `/data` directory is created mode `0700` (owned by uid 65532), so a new volume
  can no longer be listed by other users. The database files themselves were already `0600`.
- Request paths that are not canonical (`\`, `..`, absolute URLs) get `400`.

Base images are pinned by digest; update tag + digest in `Dockerfile`/`compose.yaml` deliberately,
then run `npm run test:container` and `npm run scan:image`.

**Graceful shutdown:** `docker compose stop` sends SIGTERM; pushgate stops accepting connections,
lets in-flight deliveries finish (≤ 10 s) and closes the database.

### Recovery procedures

| Situation | Action |
|---|---|
| Lost/broken passkey | `pg-cli enroll-token`, enroll a new passkey in the app (this signs out every other session), remove the old one under *Passkeys* or with `pg-cli passkeys list` / `pg-cli passkeys remove <id>`. |
| Admin session possibly stolen | `pg-cli sessions revoke-all`, review *Security events* and `pg-cli passkeys list`; remove any passkey you do not recognise with `pg-cli passkeys remove <id>`. |
| Service key leaked | `pg-cli keys revoke <id>` (or rotate). Other services are unaffected. |
| Device lost | Remove it under *Devices* (or `pg-cli devices remove <id>`); remove its passkey if it held one. |
| Host compromised | Treat everything as leaked: new `secrets/` (new pepper ⇒ recreate all keys; new VAPID key ⇒ re-subscribe devices), new passkeys, reinstall host. |
| Sending storm | Toggle *Pause all sending* in the app, or set `NOTIFICATIONS_ENABLED=false` and `docker compose up -d`. |

## Troubleshooting the deployment

- **`Cannot read package config /app/package.json: permission denied`** (container keeps
  restarting): older images copied the checkout's permission bits, so a checkout made with
  `umask 077` was unreadable by the runtime user. Update and rebuild:
  `git pull && docker compose up -d --build`.
- **`API key pepper file is unreadable`** (or VAPID key) at startup: the message shows the file's
  uid and mode as seen inside the container. Apply the supported layout and recreate:
  `scripts/gen-secrets.sh --fix-permissions && docker compose up -d --force-recreate`
  (see [Secret file permissions](#secrets-environment-variables-vs-compose-secrets)). A file uid of
  `65534` inside the container means Docker user-namespace remapping or rootless Docker; a
  world-readable file that still fails points to SELinux (`chcon -t container_file_t secrets/*`).
- **Compose: `Pool overlaps with other one on this space`**: another Docker network already uses
  part of `172.20.2.0/24`. List subnets with
  `docker network inspect -f '{{.Name}} {{range .IPAM.Config}}{{.Subnet}}{{end}}' $(docker network ls -q)`.

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
npm run dev            # http://localhost:2090 with .env.development (localhost-only CIDRs)
node --env-file=.env.development src/cli.js enroll-token
```

Only `http://localhost` is accepted as a non-HTTPS origin; all other checks (CIDRs, keys, CSRF,
CSP, cookies) are identical to production.

### Plugins

The self-hosted edition needs no plugins. Other editions (for example a hosted one kept in a
separate repository) start pushgate with `run({ plugins: [...] })` and can replace services such
as rate limiting or the push transport, add checks before and after sending, extra routes,
feature flags and their own tables. See [docs/PLUGINS.md](docs/PLUGINS.md).

### Tests and security checks

```bash
npm run lint
npm test                  # unit + HTTP security tests (node:test)
npm run audit             # npm audit, production dependencies
npm run test:container    # builds and runs the real compose stack: hardening, loopback port range,
                          # trusted-proxy handling, restart, recreation
npm run scan:image        # npm audit + Trivy scan of the image (fails on HIGH/CRITICAL)
```

CI ([.github/workflows/ci.yml](.github/workflows/ci.yml)) runs all of them on every push and weekly.

## License

pushgate is licensed under the [PolyForm Noncommercial License 1.0.0](LICENSE.md). In short:

- **Noncommercial use only.** You may use, change and share pushgate for personal, hobby, research
  and educational purposes and in noncommercial organizations. You may not sell it or use it to
  make money.
- **Credit the author.** Anyone you give a copy of pushgate, or of any part of it (changed or not),
  must also get the license (or its URL) and this notice:

  > Required Notice: Copyright (c) 2026 Ivole32 (https://github.com/Ivole32/pushgate)

- **No warranty, no liability.** The software comes as is; the author is not liable for any
  damages arising from its use.

This summary is for convenience; the [license text](LICENSE.md) is what applies. For commercial
use, ask the author for a separate license.
