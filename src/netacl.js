// CIDR-based network access control and client IP resolution.
import net from 'node:net';

function ipv4ToBigInt(ip) {
  return ip.split('.').reduce((acc, part) => (acc << 8n) | BigInt(Number(part)), 0n);
}

function ipv6ToBigInt(ip) {
  let addr = ip;
  // Embedded IPv4 tail, e.g. ::ffff:192.0.2.1
  const v4 = addr.match(/(\d+\.\d+\.\d+\.\d+)$/);
  if (v4) {
    const n = ipv4ToBigInt(v4[1]);
    addr = addr.slice(0, -v4[1].length) + ((n >> 16n) & 0xffffn).toString(16) + ':' + (n & 0xffffn).toString(16);
  }
  const [head, tail] = addr.includes('::') ? addr.split('::') : [addr, null];
  const headParts = head ? head.split(':') : [];
  const tailParts = tail ? tail.split(':') : [];
  const missing = 8 - headParts.length - tailParts.length;
  const parts = tail === null ? headParts : [...headParts, ...Array(missing).fill('0'), ...tailParts];
  return parts.reduce((acc, part) => (acc << 16n) | BigInt(parseInt(part, 16)), 0n);
}

const isMapped = (n) => n >> 32n === 0xffffn;
const mappedToIpv4 = (n) => [24n, 16n, 8n, 0n].map((s) => String((n >> s) & 0xffn)).join('.');

// Returns a canonical address string, or null if the input is not a plain IP address.
// IPv4-mapped IPv6 addresses (::ffff:a.b.c.d, in any spelling) are converted to IPv4 so that
// one rule covers both socket representations. Zone ids (fe80::1%eth0) are rejected.
export function normalizeIp(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 64) return null;
  const family = net.isIP(value);
  if (family === 4) return value;
  if (family !== 6 || value.includes('%')) return null;
  const n = ipv6ToBigInt(value);
  return isMapped(n) ? mappedToIpv4(n) : value.toLowerCase();
}

// Wide IPv6 ranges (shorter than /16) are accepted only inside the private and link-local
// blocks, so fc00::/7 stays possible but a typo cannot trust a large part of the internet.
const IPV6_LOCAL = [{ network: ipv6ToBigInt('fc00::'), prefix: 7 }, { network: ipv6ToBigInt('fe80::'), prefix: 10 }];
const inIpv6Block = (value, { network, prefix }) => value >> BigInt(128 - prefix) === network >> BigInt(128 - prefix);

export function parseCidr(text) {
  const raw = String(text).trim();
  const slash = raw.indexOf('/');
  if (slash < 0) throw new Error(`invalid CIDR "${raw}": missing prefix length`);
  const addr = raw.slice(0, slash);
  const prefixText = raw.slice(slash + 1);
  if (!/^\d{1,3}$/.test(prefixText)) throw new Error(`invalid CIDR "${raw}": bad prefix length`);
  const prefix = Number(prefixText);
  const family = net.isIP(addr);
  if (family === 0 || addr.includes('%')) throw new Error(`invalid CIDR "${raw}": bad address`);
  const bits = family === 4 ? 32 : 128;
  if (prefix > bits) throw new Error(`invalid CIDR "${raw}": prefix too long`);
  // A /0 range matches every address. That is never a "trusted local network".
  if (prefix === 0) throw new Error(`refusing CIDR "${raw}": /0 would allow every address`);
  // Nor are a few very wide ranges (e.g. 0.0.0.0/1 + 128.0.0.0/1). The limits still allow the
  // widest private ranges: 10.0.0.0/8 and fc00::/7.
  const minPrefix = family === 4 ? 8 : 7;
  if (prefix < minPrefix) throw new Error(`refusing CIDR "${raw}": prefixes shorter than /${minPrefix} cover too much of the internet`);
  const value = family === 4 ? ipv4ToBigInt(addr) : ipv6ToBigInt(addr);
  if (family === 6 && isMapped(value)) throw new Error(`invalid CIDR "${raw}": use the IPv4 form instead of IPv4-mapped IPv6`);
  if (family === 6 && prefix < 16 && !IPV6_LOCAL.some((b) => prefix >= b.prefix && inIpv6Block(value, b))) {
    throw new Error(`refusing CIDR "${raw}": IPv6 prefixes shorter than /16 are only allowed within fc00::/7 and fe80::/10`);
  }
  const mask = ((1n << BigInt(prefix)) - 1n) << BigInt(bits - prefix);
  if ((value & ~mask & ((1n << BigInt(bits)) - 1n)) !== 0n) {
    throw new Error(`invalid CIDR "${raw}": host bits set (did you mean the network address?)`);
  }
  return { family, network: value, mask, prefix, text: raw };
}

// Parses a comma separated list. Throws on any invalid entry: a typo must never widen access.
export function parseCidrList(text, { allowEmpty = false, name = 'CIDR list' } = {}) {
  const items = String(text ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  if (items.length === 0 && !allowEmpty) throw new Error(`${name} is empty`);
  return items.map((item) => {
    try {
      return parseCidr(item);
    } catch (err) {
      throw new Error(`${name}: ${err.message}`, { cause: err });
    }
  });
}

export function ipInCidrs(ip, cidrs) {
  const addr = normalizeIp(ip);
  if (!addr) return false;
  const family = net.isIP(addr);
  const value = family === 4 ? ipv4ToBigInt(addr) : ipv6ToBigInt(addr);
  return cidrs.some((c) => c.family === family && (value & c.mask) === c.network);
}

export function isLoopback(ip) {
  const addr = normalizeIp(ip);
  return addr !== null && (addr === '::1' || /^127\./.test(addr));
}

// Determines the client address of a request.
// Forwarding headers are only consulted when the TCP peer is a configured trusted proxy,
// and then the proxy must have overwritten X-Forwarded-For with exactly one address.
export function resolveClient(socketAddress, headers, trustedProxies) {
  const peer = normalizeIp(socketAddress);
  if (!peer) return { ok: false, reason: 'invalid_peer', peer: null, ip: null };
  if (trustedProxies.length === 0) return { ok: true, ip: peer, peer, viaProxy: false };
  if (!ipInCidrs(peer, trustedProxies)) return { ok: false, reason: 'direct_access', peer, ip: peer };
  const xff = headers['x-forwarded-for'];
  if (typeof xff !== 'string') return { ok: false, reason: 'missing_forwarded_for', peer, ip: null };
  const parts = xff.split(',').map((s) => s.trim());
  if (parts.length !== 1) return { ok: false, reason: 'ambiguous_forwarded_for', peer, ip: null };
  const ip = normalizeIp(parts[0]);
  if (!ip) return { ok: false, reason: 'invalid_forwarded_for', peer, ip: null };
  return { ok: true, ip, peer, viaProxy: true };
}

// Key for per-client counters (rate limits, brute-force blocks, challenge caps). IPv6 clients
// are grouped by /64, because a single host can trivially use many addresses within its /64.
export function clientKey(ip) {
  const addr = normalizeIp(ip);
  if (!addr) return 'invalid';
  if (net.isIP(addr) === 4) return addr;
  return `${(ipv6ToBigInt(addr) >> 64n).toString(16)}::/64`;
}
