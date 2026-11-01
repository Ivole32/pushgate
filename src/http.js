// HTTP helpers: security headers, JSON responses with generic errors, bounded body reading.

export const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self'",
  "connect-src 'self'",
  "manifest-src 'self'",
  "worker-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
  // DOM sinks that turn strings into HTML or script are refused; the web app creates its one
  // script URL (the service worker) through the "pushgate" policy.
  "require-trusted-types-for 'script'",
  'trusted-types pushgate',
].join('; ');

export function setSecurityHeaders(res, { hsts }) {
  res.setHeader('Content-Security-Policy', CSP);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  // A private admin app: keep it out of search engines even when it is reachable publicly.
  res.setHeader('X-Robots-Tag', 'noindex, nofollow');
  if (hsts) res.setHeader('Strict-Transport-Security', 'max-age=31536000');
}

export class HttpError extends Error {
  constructor(status, code, message, extra = {}) {
    super(message);
    this.status = status;
    this.code = code;
    this.extra = extra;
  }
}

export const errors = {
  badRequest: (code = 'bad_request', message = 'Bad request', extra) => new HttpError(400, code, message, extra),
  unauthorized: () => new HttpError(401, 'unauthorized', 'Authentication required'),
  forbidden: () => new HttpError(403, 'forbidden', 'Forbidden'),
  notFound: () => new HttpError(404, 'not_found', 'Not found'),
  methodNotAllowed: () => new HttpError(405, 'method_not_allowed', 'Method not allowed'),
  tooLarge: () => new HttpError(413, 'payload_too_large', 'Payload too large'),
  unsupportedMedia: () => new HttpError(415, 'unsupported_media_type', 'Content-Type must be application/json'),
  rateLimited: (retryAfter) => new HttpError(429, 'rate_limited', 'Too many requests', { retryAfter }),
  unavailable: (message = 'Service unavailable') => new HttpError(503, 'unavailable', message),
};

export function sendJson(res, status, body, headers = {}) {
  const data = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(data),
    'Cache-Control': 'no-store',
    ...headers,
  });
  res.end(data);
}

// Route handler results: a value is sent as 200 JSON, `{ status, body }` with that status.
// Only an object with exactly these keys (`body` optional) and an HTTP status 200-599 counts as
// such an envelope; any other value, e.g. a database row with a `status` column, is the body.
// Handlers that wrote the response themselves return nothing after doing so.
export function sendResult(res, result) {
  if (res.headersSent || res.writableEnded) return;
  const envelope = result !== null && typeof result === 'object' && !Array.isArray(result)
    && Number.isInteger(result.status) && result.status >= 200 && result.status <= 599
    && Object.keys(result).every((k) => k === 'status' || k === 'body');
  if (!envelope) return sendJson(res, 200, result);
  if (result.status === 204 || result.body === undefined) {
    res.writeHead(result.status, { 'Cache-Control': 'no-store', 'Content-Length': 0 });
    return res.end();
  }
  sendJson(res, result.status, result.body);
}

export function sendError(res, err, requestId) {
  const headers = {};
  if (err.extra?.retryAfter) headers['Retry-After'] = String(err.extra.retryAfter);
  const body = { error: { code: err.code, message: err.message, request_id: requestId } };
  if (err.extra?.details) body.error.details = err.extra.details;
  // Do not keep reading a body we are refusing: close the connection after responding.
  if (err.status === 413 || err.status === 401 || err.status === 403) headers.Connection = 'close';
  sendJson(res, err.status, body, headers);
}

export function isJsonContentType(req) {
  const ct = String(req.headers['content-type'] || '').toLowerCase();
  return /^application\/json\s*(;\s*charset=utf-8\s*)?$/.test(ct);
}

// Reads and parses a JSON body of at most `limit` bytes.
export function readJson(req, limit) {
  return new Promise((resolve, reject) => {
    if (!isJsonContentType(req)) return reject(errors.unsupportedMedia());
    const declared = req.headers['content-length'];
    if (declared !== undefined && (!/^\d+$/.test(declared) || Number(declared) > limit)) return reject(errors.tooLarge());
    const chunks = [];
    let size = 0;
    let done = false;
    const finish = (fn, value) => {
      if (done) return;
      done = true;
      fn(value);
    };
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > limit) {
        finish(reject, errors.tooLarge());
        req.pause();
        return;
      }
      chunks.push(chunk);
    });
    req.on('error', () => finish(reject, errors.badRequest()));
    req.on('end', () => {
      if (size === 0) return finish(reject, errors.badRequest('invalid_json', 'Request body must be a JSON object'));
      try {
        const text = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks));
        finish(resolve, JSON.parse(text));
      } catch {
        finish(reject, errors.badRequest('invalid_json', 'Request body is not valid JSON'));
      }
    });
  });
}
