// Minimal software WebAuthn authenticator (ES256, "none" attestation) for end-to-end tests of
// passkey enrollment and login. It produces the same JSON a browser sends.
import crypto from 'node:crypto';

const b64url = (buf) => Buffer.from(buf).toString('base64url');
const sha256 = (data) => crypto.createHash('sha256').update(data).digest();

function head(major, n) {
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n < 256) return Buffer.from([(major << 5) | 24, n]);
  if (n < 65536) return Buffer.from([(major << 5) | 25, n >> 8, n & 0xff]);
  const b = Buffer.alloc(5);
  b[0] = (major << 5) | 26;
  b.writeUInt32BE(n, 1);
  return b;
}

function cbor(value) {
  if (typeof value === 'number') return value >= 0 ? head(0, value) : head(1, -1 - value);
  if (typeof value === 'string') {
    const s = Buffer.from(value, 'utf8');
    return Buffer.concat([head(3, s.length), s]);
  }
  if (Buffer.isBuffer(value)) return Buffer.concat([head(2, value.length), value]);
  if (value instanceof Map) {
    return Buffer.concat([head(5, value.size), ...[...value].flatMap(([k, v]) => [cbor(k), cbor(v)])]);
  }
  throw new Error('unsupported CBOR value');
}

const u32 = (n) => {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n);
  return b;
};

export function createSoftAuthenticator({ origin, rpId, idLength = 16 }) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' });
  const credentialId = crypto.randomBytes(idLength);
  const rpIdHash = sha256(rpId);
  let counter = 0;
  let userHandle = null;

  return {
    id: b64url(credentialId),

    register(options, { clientOrigin = origin, transports = ['internal'] } = {}) {
      userHandle = options.user.id;
      const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge: options.challenge, origin: clientOrigin, crossOrigin: false }));
      const coseKey = cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, 'base64url')], [-3, Buffer.from(jwk.y, 'base64url')]]));
      const idLen = Buffer.from([credentialId.length >> 8, credentialId.length & 0xff]);
      const authData = Buffer.concat([rpIdHash, Buffer.from([0x45]), u32(counter), Buffer.alloc(16), idLen, credentialId, coseKey]);
      const attestationObject = cbor(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData]]));
      return {
        id: b64url(credentialId),
        rawId: b64url(credentialId),
        type: 'public-key',
        response: { clientDataJSON: b64url(clientData), attestationObject: b64url(attestationObject), transports },
        clientExtensionResults: {},
      };
    },

    login(options, { clientOrigin = origin } = {}) {
      counter += 1;
      const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: options.challenge, origin: clientOrigin, crossOrigin: false }));
      const authData = Buffer.concat([rpIdHash, Buffer.from([0x05]), u32(counter)]);
      const signature = crypto.sign('sha256', Buffer.concat([authData, sha256(clientData)]), privateKey);
      return {
        id: b64url(credentialId),
        rawId: b64url(credentialId),
        type: 'public-key',
        response: {
          clientDataJSON: b64url(clientData),
          authenticatorData: b64url(authData),
          signature: b64url(signature),
          userHandle,
        },
        clientExtensionResults: {},
      };
    },
  };
}
