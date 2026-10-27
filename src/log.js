// Structured JSON logging to stdout.
// Callers pass explicit, already-safe fields. Never pass request headers, bodies,
// API keys, subscription endpoints or key material to the logger.

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };

export function createLogger({ level = 'info', sink = (line) => process.stdout.write(line + '\n') } = {}) {
  const min = LEVELS[level] ?? LEVELS.info;
  const emit = (lvl, msg, fields) => {
    if (LEVELS[lvl] < min) return;
    sink(JSON.stringify({ ts: new Date().toISOString(), level: lvl, msg, ...fields }));
  };
  return {
    debug: (msg, fields = {}) => emit('debug', msg, fields),
    info: (msg, fields = {}) => emit('info', msg, fields),
    warn: (msg, fields = {}) => emit('warn', msg, fields),
    error: (msg, fields = {}) => emit('error', msg, fields),
  };
}

// Reduce an arbitrary error to a log-safe shape: class name and a status code only.
// Error messages from libraries can embed URLs or response bodies, so they are dropped.
export function safeError(err) {
  if (!err || typeof err !== 'object') return { error: 'unknown' };
  const out = { error: err.name || 'Error' };
  if (Number.isInteger(err.statusCode)) out.status = err.statusCode;
  if (typeof err.code === 'string' && /^[A-Z0-9_]{1,40}$/.test(err.code)) out.code = err.code;
  return out;
}
