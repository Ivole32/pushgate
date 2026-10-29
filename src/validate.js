// Strict, minimal schema validation. Unknown fields are always rejected.
//
// Field spec: { type: 'string'|'integer'|'boolean'|'array'|'object', required?, ... }
//   string:  minLength, maxLength (in code points), pattern, enum, multiline (allow \n and \t)
//   integer: min, max
//   array:   items (field spec), maxItems
//   object:  fields (map of field specs)

// Characters that can disguise text: controls (Cc), invisible format characters such as bidi
// marks/overrides/isolates, zero-width spaces and BOM (Cf), and the line/paragraph separators
// U+2028/U+2029, which break "single-line" fields. A single ZWJ or ZWNJ stays allowed (emoji
// sequences; Persian and Indic spelling), but not a run of them, which could encode hidden bits.
// Tag characters are invisible text except in the three standard subdivision flags (England,
// Scotland, Wales).
const CONTROL = /(?![\n\t\u200C\u200D])[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]|[\u200C\u200D]{2}/u;
const CONTROL_SINGLE_LINE = /(?![\u200C\u200D])[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]|[\u200C\u200D]{2}/u;
const FLAG_TAG_SEQUENCE = /\u{1F3F4}(?:\u{E0067}\u{E0062}(?:\u{E0065}\u{E006E}\u{E0067}|\u{E0073}\u{E0063}\u{E0074}|\u{E0077}\u{E006C}\u{E0073}))\u{E007F}/gu;

function check(value, spec, path, errors) {
  switch (spec.type) {
    case 'string': {
      if (typeof value !== 'string') return errors.push({ field: path, issue: 'must be a string' });
      const len = [...value].length;
      if (spec.minLength !== undefined && len < spec.minLength) return errors.push({ field: path, issue: `must be at least ${spec.minLength} characters` });
      if (spec.maxLength !== undefined && len > spec.maxLength) return errors.push({ field: path, issue: `must be at most ${spec.maxLength} characters` });
      if ((spec.multiline ? CONTROL : CONTROL_SINGLE_LINE).test(value.replace(FLAG_TAG_SEQUENCE, ''))) return errors.push({ field: path, issue: 'contains control characters' });
      if (spec.enum && !spec.enum.includes(value)) return errors.push({ field: path, issue: `must be one of: ${spec.enum.join(', ')}` });
      if (spec.pattern && !spec.pattern.test(value)) return errors.push({ field: path, issue: 'has an invalid format' });
      return;
    }
    case 'integer':
      if (!Number.isSafeInteger(value)) return errors.push({ field: path, issue: 'must be an integer' });
      if (spec.min !== undefined && value < spec.min) return errors.push({ field: path, issue: `must be >= ${spec.min}` });
      if (spec.max !== undefined && value > spec.max) return errors.push({ field: path, issue: `must be <= ${spec.max}` });
      return;
    case 'boolean':
      if (typeof value !== 'boolean') errors.push({ field: path, issue: 'must be a boolean' });
      return;
    case 'array':
      if (!Array.isArray(value)) return errors.push({ field: path, issue: 'must be an array' });
      if (spec.maxItems !== undefined && value.length > spec.maxItems) return errors.push({ field: path, issue: `must have at most ${spec.maxItems} items` });
      value.forEach((v, i) => check(v, spec.items, `${path}[${i}]`, errors));
      return;
    case 'object':
      // fields: null marks an opaque object that a library validates (WebAuthn responses).
      if (spec.fields === null) {
        if (value === null || typeof value !== 'object' || Array.isArray(value)) errors.push({ field: path, issue: 'must be an object' });
        return;
      }
      return checkObject(value, spec.fields, path, errors);
    default:
      throw new Error('bad schema');
  }
}

function checkObject(value, fields, path, errors) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return errors.push({ field: path || '(body)', issue: 'must be a JSON object' });
  }
  for (const key of Object.keys(value)) {
    if (!Object.hasOwn(fields, key)) errors.push({ field: path ? `${path}.${key}` : key, issue: 'is not allowed' });
  }
  for (const [key, spec] of Object.entries(fields)) {
    const p = path ? `${path}.${key}` : key;
    if (!Object.hasOwn(value, key) || value[key] === undefined) {
      if (spec.required) errors.push({ field: p, issue: 'is required' });
      continue;
    }
    if (value[key] === null && spec.nullable) continue;
    check(value[key], spec, p, errors);
  }
}

// Returns a list of { field, issue }; empty means valid. Field names in the result come
// from the schema or from the client's own keys, never from server state.
export function validate(value, fields) {
  const errors = [];
  checkObject(value, fields, '', errors);
  // Bound the response size even for hostile input with thousands of unknown keys.
  return errors.slice(0, 20).map((e) => ({ field: String(e.field).slice(0, 80), issue: e.issue }));
}

export const PRIORITIES = ['low', 'normal', 'high'];
// Signed, stateless WebAuthn challenge token issued by admin/auth.js: payload.mac
export const CHALLENGE_TOKEN_PATTERN = /^[A-Za-z0-9_-]{20,400}\.[A-Za-z0-9_-]{43}$/;
export const priorityRank = (p) => PRIORITIES.indexOf(p);

export const schemas = {
  notification: {
    title: { type: 'string', required: true, minLength: 1, maxLength: 200 },
    message: { type: 'string', required: true, minLength: 1, maxLength: 2000, multiline: true },
    priority: { type: 'string', enum: PRIORITIES },
    // Notifications with the same tag replace each other on the device.
    tag: { type: 'string', pattern: /^[A-Za-z0-9_-]{1,32}$/ },
    // Seconds the push service keeps the message while the device is offline.
    ttl: { type: 'integer', min: 0, max: 2419200 },
  },
  createKey: {
    name: { type: 'string', required: true, minLength: 1, maxLength: 64 },
    description: { type: 'string', maxLength: 200 },
    expires_at: { type: 'integer', min: 0, nullable: true },
    allow_high_priority: { type: 'boolean' },
  },
  rotateKey: {
    grace_hours: { type: 'integer', min: 0, max: 168 },
  },
  registerDevice: {
    name: { type: 'string', required: true, minLength: 1, maxLength: 64 },
    min_priority: { type: 'string', enum: PRIORITIES },
    subscription: {
      type: 'object',
      required: true,
      fields: {
        endpoint: { type: 'string', required: true, minLength: 1, maxLength: 1024 },
        expirationTime: { type: 'integer', nullable: true },
        keys: {
          type: 'object',
          required: true,
          fields: {
            p256dh: { type: 'string', required: true, pattern: /^[A-Za-z0-9_-]{80,100}={0,2}$/ },
            auth: { type: 'string', required: true, pattern: /^[A-Za-z0-9_-]{16,32}={0,2}$/ },
          },
        },
      },
    },
  },
  updateDevice: {
    name: { type: 'string', minLength: 1, maxLength: 64 },
    min_priority: { type: 'string', enum: PRIORITIES },
  },
  settings: {
    sending_paused: { type: 'boolean', required: true },
  },
  enrollOptions: {
    token: { type: 'string', required: true, minLength: 1, maxLength: 100 },
  },
  enrollVerify: {
    token: { type: 'string', required: true, minLength: 1, maxLength: 100 },
    challenge_id: { type: 'string', required: true, pattern: CHALLENGE_TOKEN_PATTERN },
    name: { type: 'string', required: true, minLength: 1, maxLength: 64 },
    response: { type: 'object', required: true, fields: null },
  },
  addPasskeyVerify: {
    challenge_id: { type: 'string', required: true, pattern: CHALLENGE_TOKEN_PATTERN },
    name: { type: 'string', required: true, minLength: 1, maxLength: 64 },
    response: { type: 'object', required: true, fields: null },
  },
  loginVerify: {
    challenge_id: { type: 'string', required: true, pattern: CHALLENGE_TOKEN_PATTERN },
    response: { type: 'object', required: true, fields: null },
  },
  testPush: {
    device_id: { type: 'string', pattern: /^[A-Za-z0-9_-]{22}$/ },
  },
};
