// Plugin system. Without plugins pushgate runs with its built-in defaults. A plugin is a plain
// object that replaces a service, adds hooks, HTTP routes, feature flags for the web app, or its
// own database tables; a program that embeds pushgate passes its plugins to `run`/`createApp`.
// Plugins are trusted code chosen by that program: they are never loaded from configuration,
// the database or requests. Everything is checked at startup, and any problem aborts it.
import { ConfigError } from './config.js';

export const PLUGIN_API_VERSION = 1;

// Replaceable services: exactly one implementation each, the built-in one unless a plugin
// provides its own. Two plugins replacing the same service is a startup error.
const SERVICES = new Set(['rateLimiter', 'failureLimiter', 'transport', 'apiAccess']);
// Hooks: any number of plugins, called in the order the plugins were given.
const HOOKS = new Set(['beforeSend', 'afterDelivery']);
const KEYS = new Set(['name', 'apiVersion', 'services', 'hooks', 'routes', 'features', 'migrations']);
const METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']);
const ROUTE_KEYS = new Set(['method', 'path', 'zone', 'auth', 'crossOrigin', 'handler']);
const NAME = /^[a-z][a-z0-9-]{0,39}$/;
const ROUTE_PATH = /^(\/[A-Za-z0-9._~-]+)+$/;
// Core paths a plugin route can never take over.
const RESERVED = [/^\/api(\/|$)/, /^\/admin\/api(\/|$)/, /^\/healthz$/];

const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

function fail(plugin, message) {
  throw new ConfigError(`plugin "${plugin}": ${message}`);
}

function checkRoute(plugin, route, seen) {
  if (!isObject(route)) fail(plugin, 'every route must be an object');
  for (const k of Object.keys(route)) if (!ROUTE_KEYS.has(k)) fail(plugin, `route has unknown option "${k}"`);
  const { method, path, zone = 'app', auth = 'session', crossOrigin = false, handler } = route;
  if (!METHODS.has(method)) fail(plugin, `route method must be one of ${[...METHODS].join(', ')}`);
  if (typeof path !== 'string' || path.length > 200 || !ROUTE_PATH.test(path) || path.split('/').some((s) => s === '.' || s === '..')) {
    fail(plugin, `route path "${path}" must be an exact canonical path like /signup/verify`);
  }
  if (RESERVED.some((re) => re.test(path))) fail(plugin, `route path "${path}" is reserved by pushgate`);
  if (zone !== 'app' && zone !== 'public') fail(plugin, `route ${path}: zone must be "app" or "public"`);
  if (!['none', 'session', 'fresh'].includes(auth)) fail(plugin, `route ${path}: auth must be "none", "session" or "fresh"`);
  if (typeof crossOrigin !== 'boolean') fail(plugin, `route ${path}: crossOrigin must be a boolean`);
  // Requests from other sites may never act with the administrator's session.
  if (crossOrigin && auth !== 'none') fail(plugin, `route ${path}: crossOrigin is only allowed with auth "none"`);
  if (typeof handler !== 'function') fail(plugin, `route ${path}: handler must be a function`);
  const id = `${method} ${path}`;
  if (seen.has(id)) fail(plugin, `route ${id} is already defined by plugin "${seen.get(id)}"`);
  seen.set(id, plugin);
  return { method, path, zone, auth, crossOrigin, handler, plugin };
}

// Validates the plugins and merges them into one description of what to replace and add.
export function resolvePlugins(plugins = []) {
  if (!Array.isArray(plugins)) throw new ConfigError('plugins must be an array');
  const resolved = {
    names: [],
    services: {},
    hooks: Object.fromEntries([...HOOKS].map((h) => [h, []])),
    routes: [],
    features: {},
    migrations: [],
  };
  const owners = {};
  const seenRoutes = new Map();
  const featureOwners = {};

  for (const p of plugins) {
    if (!isObject(p) || typeof p.name !== 'string' || !NAME.test(p.name)) {
      throw new ConfigError('every plugin needs a name of lowercase letters, digits and dashes (max. 40)');
    }
    const name = p.name;
    if (resolved.names.includes(name)) fail(name, 'is given twice');
    for (const k of Object.keys(p)) if (!KEYS.has(k)) fail(name, `unknown option "${k}"`);
    if (p.apiVersion !== PLUGIN_API_VERSION) {
      fail(name, `targets plugin API version ${p.apiVersion}, this pushgate provides version ${PLUGIN_API_VERSION}`);
    }
    resolved.names.push(name);

    for (const [service, impl] of Object.entries(p.services ?? {})) {
      if (!SERVICES.has(service)) fail(name, `unknown service "${service}"`);
      if (typeof impl !== 'function') fail(name, `service "${service}" must be a function`);
      if (owners[service]) fail(name, `service "${service}" is already replaced by plugin "${owners[service]}"`);
      owners[service] = name;
      resolved.services[service] = impl;
    }
    for (const [hook, fn] of Object.entries(p.hooks ?? {})) {
      if (!HOOKS.has(hook)) fail(name, `unknown hook "${hook}"`);
      if (typeof fn !== 'function') fail(name, `hook "${hook}" must be a function`);
      resolved.hooks[hook].push({ plugin: name, fn });
    }
    if (p.routes !== undefined && !Array.isArray(p.routes)) fail(name, 'routes must be an array');
    for (const route of p.routes ?? []) resolved.routes.push(checkRoute(name, route, seenRoutes));

    if (p.features !== undefined && !isObject(p.features)) fail(name, 'features must be an object');
    for (const [flag, value] of Object.entries(p.features ?? {})) {
      if (featureOwners[flag]) fail(name, `feature "${flag}" is already set by plugin "${featureOwners[flag]}"`);
      featureOwners[flag] = name;
      // Sent to the web app as JSON: only plain values survive the round trip.
      resolved.features[flag] = JSON.parse(JSON.stringify(value) ?? 'null');
    }

    if (p.migrations !== undefined && !(Array.isArray(p.migrations) && p.migrations.every((m) => typeof m === 'string' && m.trim()))) {
      fail(name, 'migrations must be an array of SQL strings');
    }
    if (p.migrations?.length) resolved.migrations.push({ plugin: name, steps: p.migrations });
  }
  resolved.owners = owners;
  return resolved;
}
