# Plugins

Pushgate runs with built-in defaults: that is the self-hosted edition, and it needs no plugins.
A plugin replaces one of those defaults or adds behaviour on top of them. Another edition, for
example a hosted one in a separate repository, is a small program that depends on pushgate and
starts it with its plugins:

```js
// server.js of another edition
import { run } from 'pushgate';
import cloud from './cloud-plugin.js';

run({ plugins: [cloud] });
```

`run` is the same entry point the self-hosted container uses (configuration from the
environment, maintenance, graceful shutdown), so the other edition only adds what is different.
Tests and custom servers can call `createApp({ config, db, log, plugins })` instead.

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
  name: 'cloud',                     // lowercase letters, digits, dashes
  apiVersion: PLUGIN_API_VERSION,

  services: {                        // replace built-in parts (at most one plugin each)
    rateLimiter: (perMinute) => createRedisLimiter(redis, perMinute),
  },

  hooks: {                           // add behaviour (any number of plugins, in order)
    async beforeSend({ key, client, notification }) {
      if (await overQuota(key.id)) throw new HttpError(429, 'quota_exceeded', 'Monthly quota reached');
    },
    async afterDelivery({ key, outcome }) {
      await meter(key.id, outcome.devices.delivered);
    },
  },

  routes: [                          // extra HTTP endpoints
    { method: 'GET', path: '/account/usage', handler: ({ ctx, session }) => usageFor(ctx.db) },
    { method: 'POST', path: '/billing/webhook', zone: 'public', auth: 'none', crossOrigin: true, handler: billingWebhook },
  ],

  features: { billing: true },       // flags for the web app

  migrations: [                      // own tables; append-only
    'CREATE TABLE cloud_usage (key_id TEXT PRIMARY KEY, month TEXT NOT NULL, sent INTEGER NOT NULL DEFAULT 0)',
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
| `beforeSend` | After the key, scopes, rate limits, kill switches and body checks, before anything is sent | `{ key, client, notification: { priority, ttl } }` | Throw an `HttpError` to refuse with that response. Any other error refuses with 500. Later hooks do not run. |
| `afterDelivery` | After delivery, before the response | `{ key, client, outcome }` | Errors are logged and ignored: the notification is already out, and an error response would make the sender send it again. |

Hooks run for notifications sent with an API key only, not for test pushes or security alerts
from the web app. They never receive the title or message, so a plugin cannot store content
by accident.

## Routes

| Option | Values | Default |
|---|---|---|
| `method` | `GET`, `POST`, `PUT`, `PATCH`, `DELETE` | required |
| `path` | An exact path such as `/signup/verify`. No patterns or query strings. Not under `/api/` or `/admin/api/`, not `/healthz`, not a web app file | required |
| `zone` | `app`: the same networks as the web app (`ADMIN_PUBLIC` / `ADMIN_CIDRS`). `public`: every network. All methods of one path share a zone | `app` |
| `auth` | `session`: signed-in session (and CSRF token for changes). `fresh`: also a passkey confirmation from the last 5 minutes. `none`: anyone, rate limited per client like the login endpoints | `session` |
| `crossOrigin` | `true` skips the same-origin check for changes, e.g. for webhooks from a payment provider. Only with `auth: 'none'`; the handler must authenticate the request itself (e.g. a webhook signature) | `false` |
| `handler` | `async ({ req, res, url, client, session, ctx }) => result` | required |

A handler returns a value (sent as JSON with status 200) or `{ status, body }`. To answer
differently, write to `res` and return nothing. Throw an `HttpError` to reject. Plugin routes
pass the same checks as everything else first: forwarding-header rules, network zone, origin,
session.

`ctx` holds pushgate's internals (`config`, `db`, `log`, `audit`, `keys`, `devices`, `pusher`,
...). They are useful but not part of the versioned contract: pin the pushgate version you build
against and run your tests when you upgrade.

## Features

`features` is a plain JSON object. The flags of all plugins are merged (two plugins setting
the same flag is a startup error) and returned to the web app as `features` from
`GET /admin/api/session`, so it can show extra screens. Without plugins it is `{}`.

## Migrations

`migrations` is an append-only list of SQL strings. Pushgate runs them after its own schema
and records how many have run per plugin (table `plugin_migrations`), so each runs once.
Add new steps at the end and never change existing ones. Prefix the tables with the plugin's
name (`cloud_usage`), so they cannot collide with current or future core tables.

## Not covered yet

- Accounts. Pushgate has one administrator and no `account_id` in its tables. A hosted
  edition needs that in the core; a plugin cannot add it safely afterwards.
- Replacing the sign-up and recovery flow. Plugin routes can add one, but the core
  enrollment still uses the CLI token.
- Extending the web app. The session endpoint returns `features`, but the PWA does not use
  them yet and cannot load screens from plugins.
- An asynchronous database (Postgres) and a delivery queue.
