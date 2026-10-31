# Plugins

Pushgate runs with built-in defaults and needs no plugins. A plugin replaces one of those
defaults or adds behaviour on top of them. To use plugins, write a small program that depends on
pushgate and starts it with them:

```js
// server.js of your own program
import { run } from 'pushgate';
import quotas from './quotas-plugin.js';

run({ plugins: [quotas] });
```

`run` is the same entry point the container uses (configuration from the environment,
maintenance, graceful shutdown), so your program only adds what is different.
Tests and custom servers can call `createApp({ config, db, log, plugins, multiAccount })` instead.
`run({ plugins, multiAccount: true })` serves several accounts (see [Accounts](#accounts)).

Plugins are trusted code chosen by the program that starts the server. They are never loaded
from configuration, the database or requests. Every plugin is checked at startup, and any
problem (unknown option, wrong API version, two plugins replacing the same service, a route on a
reserved path) aborts startup with a message naming the plugin.

## Public API

Import only from the package root (`import { ... } from 'pushgate'`, see
[src/index.js](../src/index.js)). Everything else in `src/` is internal. The contract is that list
plus `PLUGIN_API_VERSION`: a change that breaks plugins increases the version, and a plugin
written for another version is refused at startup.

The repository is `"private": true`, so it is not published to npm; depend on it by git tag:

```json
"dependencies": { "pushgate": "github:<owner>/pushgate#v1.1.0" }
```

## A plugin

```js
import { HttpError, PLUGIN_API_VERSION } from 'pushgate';

export default {
  name: 'quotas',                    // lowercase letters, digits, dashes
  apiVersion: PLUGIN_API_VERSION,

  services: {                        // replace built-in parts (at most one plugin each)
    rateLimiter: (perMinute) => createRedisLimiter(redis, perMinute),
  },

  hooks: {                           // add behaviour (any number of plugins, in order)
    async beforeSend({ account, key, client, notification }) {
      if (await overQuota(account.id)) throw new HttpError(429, 'quota_exceeded', 'Monthly quota reached');
    },
    async afterDelivery({ account, outcome }) {
      await meter(account.id, outcome.devices.delivered);
    },
  },

  routes: [                          // extra HTTP endpoints
    { method: 'GET', path: '/account/usage', handler: ({ ctx, session }) => usageFor(ctx.db, session.accountId) },
    { method: 'POST', path: '/billing/webhook', zone: 'public', auth: 'none', crossOrigin: true, handler: billingWebhook },
  ],

  features: { billing: true },       // flags for the web app

  web: { dir: '/app/quotas-web', entry: 'main.js' },   // extra screens in the web app

  migrations: [                      // own tables; append-only
    'CREATE TABLE quotas_usage (account_id TEXT PRIMARY KEY, month TEXT NOT NULL, sent INTEGER NOT NULL DEFAULT 0)',
  ],
};
```

## Services

Each service has exactly one implementation: the built-in one unless a plugin provides its own.

| Service | Signature | Built-in |
|---|---|---|
| `rateLimiter` | `(perMinute) => ({ take(id) })`; `take` returns 0 when allowed, otherwise seconds to wait | In-memory token bucket ([src/ratelimit.js](../src/ratelimit.js)) |
| `failureLimiter` | `({ limit, windowMs, blockMs }) => ({ blockedFor(id), fail(id), reset(id) })` | In-memory failure counter |
| `transport` | `async (subscription, payload, options) => ({ statusCode })`; throws an error with `statusCode` on failure, like `web-push` | `web-push`'s `sendNotification` |
| `apiAccess` | `(client, { config, fallback }) => boolean`: may this address reach the sending API? | `TRUSTED_CIDRS` |

`apiAccess` decides before any API key is looked at. Only an explicit `true` allows a request.
`fallback(client)` is the built-in check, so a plugin can extend it instead of replacing it. Pushgate
logs a warning at startup when a plugin replaces this check. `TRUSTED_CIDRS` is still required
in the configuration.

## Hooks

| Hook | When | Arguments | Effect |
|---|---|---|---|
| `beforeSend` | After the key, scopes, rate limits, kill switches and body checks, before anything is sent | `{ account, key, client, notification: { priority, ttl } }` | Throw an `HttpError` to refuse with that response. Any other error refuses with 500. Later hooks do not run. |
| `afterDelivery` | After delivery, before the response | `{ account, key, client, outcome }` | Errors are logged and ignored: the notification is already out, and an error response would make the sender send it again. |

`account` is the sending key's account (`{ id, name, sending_paused, created_at }`).

Hooks run for notifications sent with an API key only, not for test pushes or security alerts
from the web app. They never receive the title or message, so a plugin cannot store content
by accident.

## Routes

| Option | Values | Default |
|---|---|---|
| `method` | `GET`, `POST`, `PUT`, `PATCH`, `DELETE` | required |
| `path` | An exact path such as `/signup/verify`. No patterns or query strings. Not under `/api/`, `/admin/api/` or `/plugins/`, not `/healthz`, not a web app file | required |
| `zone` | `app`: the same networks as the web app (`ADMIN_PUBLIC` / `ADMIN_CIDRS`). `public`: every network. All methods of one path share a zone | `app` |
| `auth` | `session`: signed-in session (and CSRF token for changes). `fresh`: also a passkey confirmation from the last 5 minutes. `none`: anyone, rate limited per client like the login endpoints | `session` |
| `crossOrigin` | `true` skips the same-origin check for changes, e.g. for webhooks from a payment provider. Only with `auth: 'none'`; the handler must authenticate the request itself (e.g. a webhook signature) | `false` |
| `handler` | `async ({ req, res, url, client, session, ctx }) => result` | required |

A handler returns a value (sent as JSON with status 200) or `{ status, body }`. To answer
differently, write to `res` and return nothing. Throw an `HttpError` to reject. Plugin routes
pass the same checks as everything else first: forwarding-header rules, network zone, origin,
session. With `auth: 'session'` or `'fresh'`, `session.accountId` is the signed-in account;
a handler must only touch that account's data.

`ctx` holds pushgate's internals. These parts are part of the versioned contract:

| `ctx.` | Use |
|---|---|
| `accounts` | `create({ name })`, `get(id)`, `list()`, `rename(id, name)`, `isPaused(id)`, `setPaused(id, paused)`, `remove(id)` (deletes the account and all its data; not the default account) |
| `auth.createEnrollmentToken(accountId, { ttlMs })` | One-time token to enroll a passkey for the account: its first one (sign-up) or a recovery passkey. 1 minute to 24 hours, default 15 minutes |
| `keys`, `devices`, `audit` | Account-scoped: every function takes the account id first, e.g. `keys.list(accountId)` |
| `multiAccount`, `config`, `log`, `db` | Mode, configuration, logger, database (for the plugin's own tables) |

Anything else on `ctx` may change: pin the pushgate version you build against and run your tests
when you upgrade.

## Accounts

Every API key, passkey, device, delivery and security event belongs to one account, and every
query is limited to it. A self-hosted installation has one account, `default`, which owns
everything. `run({ plugins, multiAccount: true })` serves several:

- Signing in needs no account name: the passkey identifies the account. A session acts only on
  that account; a passkey of another account cannot confirm its changes.
- A key sends only to its account's devices, and each account has its own pause switch.
- Security alerts go to the devices of the affected account. They no longer suggest the server
  CLI, which hosted administrators cannot use.
- Events that happen before anyone is identified (rejected networks, unknown keys, failed
  sign-ins) are shown to no account, only in the logs.
- A browser subscription registered in one account cannot be registered in another (409
  `device_in_other_account`); it must be disabled there first.
- The session endpoint reports `accounts: 'multiple'`, and the web app shows the account's name
  and offers sign-in instead of the CLI enrollment instructions.

**Sign-up and recovery** are built from two pieces: your plugin checks whoever asks (e.g. a
verified email address, a payment, a waiting period for recovery), then creates the account if
needed and issues an enrollment token. The web app enrolls the passkey with it: either your
plugin screen calls `pushgate.enroll(token, name)`, or you send a link to
`https://<your host>/#enroll=<token>`, which fills in the token (the fragment never reaches the
server and is removed from the address bar). Enrolling with a token signs out every other
session of that account and alerts its devices, which is what recovery needs.

```js
// Sign-up route: after your own verification, create the account and hand out a token.
{
  method: 'POST', path: '/signup/complete', auth: 'none',
  async handler({ req, ctx }) {
    const { email } = await verifySignup(req);            // your code
    const account = ctx.accounts.create({ name: email });
    return { token: ctx.auth.createEnrollmentToken(account.id).token };
  },
}
```

The CLI works on one account at a time (`--account <id>`, default `default`) and manages
accounts with `accounts list`, `accounts create --name <name>` and `accounts remove <id>`.

## Features

`features` is a plain JSON object. The flags of all plugins are merged (two plugins setting
the same flag is a startup error) and returned to the web app as `features` from
`GET /admin/api/session`. Without plugins it is `{}`.

## Web app screens

`web: { dir, entry }` adds screens to the web app. `dir` is an absolute directory; its `.js`,
`.css`, `.html`, `.png` and `.webmanifest` files are served under `/plugins/<plugin name>/`, read
once at startup. The web app imports `entry` (a module in `dir`) and calls its default export
with a small API:

```js
// main.js
export default function setup(pushgate) {
  const card = pushgate.addSection({
    view: 'signed-in',                       // or 'signed-out'
    title: 'Usage',
    async onShow(el, session) {              // each time the view is shown
      const { used } = await pushgate.api('GET', '/account/usage');
      el.querySelector('p').textContent = `${used} notifications this month (${session.account.name})`;
    },
  });
  card.append(document.createElement('p'));
}
```

| `pushgate.` | Use |
|---|---|
| `addSection({ view, title, onShow })` | Adds a card to the signed-out or signed-in view and returns its element |
| `api(method, path, body)` | Same-origin JSON request with the session's CSRF token; throws with the server's message |
| `enroll(token, name)` | Creates a passkey with an enrollment token, then signs in |
| `session()` | `{ authenticated, account, accounts, features }` |
| `flash(message, kind)`, `reload()` | Show a message; reload the session and views |

The files are same-origin, so the Content Security Policy does not change; it still forbids
inline scripts and styles and external resources. Use `textContent`, never `innerHTML`, for
anything that comes from a server or a user. Plugin scripts run with the full rights of the
signed-in administrator in the browser.

## Migrations

`migrations` is an append-only list of SQL strings. Pushgate runs them after its own schema
and records how many have run per plugin (table `plugin_migrations`), so each runs once.
Add new steps at the end and never change existing ones. Prefix the tables with the plugin's
name (`quotas_usage`), so they cannot collide with current or future core tables.

## Limitations

- An account has one administrator identity (with several passkeys); there are no roles or teams.
- Rate limits are per key and server-wide; limits per account belong in a `beforeSend` hook.
- The database is SQLite and delivery is synchronous; neither can be replaced by a plugin.
