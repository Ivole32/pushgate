import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { ConfigError, loadConfig } from '../src/config.js';
import { ipInCidrs, normalizeIp, parseCidr, parseCidrList, resolveClient } from '../src/netacl.js';
import { baseEnv, tempDir, writeSecrets } from './helpers.js';

const cidrs = (s) => parseCidrList(s);

test('CIDR matching for IPv4, IPv6 and IPv4-mapped addresses', () => {
  const list = cidrs('192.168.1.0/24,10.0.0.0/8,fd00:1234::/32');
  assert.equal(ipInCidrs('192.168.1.77', list), true);
  assert.equal(ipInCidrs('192.168.2.1', list), false);
  assert.equal(ipInCidrs('::ffff:10.20.30.40', list), true);
  assert.equal(ipInCidrs('fd00:1234:abcd::1', list), true);
  assert.equal(ipInCidrs('fd00:1235::1', list), false);
  assert.equal(ipInCidrs('::1', list), false);
  assert.equal(ipInCidrs('not-an-ip', list), false);
  assert.equal(ipInCidrs('fe80::1%eth0', cidrs('fe80::/10')), false, 'zone ids are rejected');
  assert.equal(ipInCidrs('::1', cidrs('::1/128')), true);
  assert.equal(normalizeIp('::FFFF:127.0.0.1'), '127.0.0.1');
});

test('invalid CIDR configuration fails closed', () => {
  for (const bad of ['', ' , ', '192.168.1.0', '192.168.1.0/33', '192.168.1.1/24', '0.0.0.0/0', '::/0', 'abc/8',
    '10.0.0.0/8,foo', '::ffff:10.0.0.0/104', '10.0.0.0/-1', '10.0.0.0/08x']) {
    assert.throws(() => parseCidrList(bad), Error, `should reject "${bad}"`);
  }
  assert.equal(parseCidr('10.0.0.0/8').prefix, 8);
});

test('configuration refuses to start without trusted networks, secrets or HTTPS', () => {
  const dir = tempDir();
  const secrets = writeSecrets(dir);
  const ok = baseEnv(dir, secrets);
  assert.ok(loadConfig(ok));

  const cases = [
    { TRUSTED_CIDRS: undefined },
    { TRUSTED_CIDRS: '' },
    { TRUSTED_CIDRS: '0.0.0.0/0' },
    { TRUSTED_CIDRS: '192.168.1.0/24,192.168.300.0/24' },
    { ADMIN_CIDRS: undefined },
    { TRUSTED_PROXIES: 'garbage' },
    { PUBLIC_ORIGIN: 'http://notify.example.lan' },
    { PUBLIC_ORIGIN: undefined },
    { PUBLIC_ORIGIN: 'https://notify.example.lan/path' },
    { VAPID_SUBJECT: 'admin' },
    { API_KEY_PEPPER_FILE: path.join(dir, 'missing') },
    { VAPID_PRIVATE_KEY_FILE: path.join(dir, 'missing') },
    { NOTIFICATIONS_ENABLED: 'yes' },
    { RATE_LIMIT_PER_KEY_PER_MINUTE: '0' },
  ];
  for (const override of cases) {
    const env = { ...ok, ...override };
    for (const [k, v] of Object.entries(override)) if (v === undefined) delete env[k];
    assert.throws(() => loadConfig(env), ConfigError, JSON.stringify(override));
  }

  fs.writeFileSync(path.join(dir, 'short'), Buffer.alloc(8).toString('base64'));
  assert.throws(() => loadConfig({ ...ok, API_KEY_PEPPER_FILE: path.join(dir, 'short') }), /at least 32/);
  fs.writeFileSync(path.join(dir, 'notkey'), 'hello');
  assert.throws(() => loadConfig({ ...ok, VAPID_PRIVATE_KEY_FILE: path.join(dir, 'notkey') }), /VAPID/);
});

test('configuration errors never echo secret file contents', () => {
  const dir = tempDir();
  const secrets = writeSecrets(dir);
  const secretText = 'TOP-SECRET-PEPPER-VALUE!!';
  fs.writeFileSync(path.join(dir, 'badpepper'), secretText);
  try {
    loadConfig({ ...baseEnv(dir, secrets), API_KEY_PEPPER_FILE: path.join(dir, 'badpepper') });
    assert.fail('should throw');
  } catch (err) {
    assert.ok(!err.message.includes(secretText));
  }
});

test('forwarding headers are ignored unless the peer is a trusted proxy', () => {
  const proxies = cidrs('172.31.250.2/32');
  // No proxy configured: header is ignored entirely.
  assert.deepEqual(resolveClient('192.168.1.50', { 'x-forwarded-for': '10.0.0.1' }, []).ip, '192.168.1.50');
  // Proxy configured, request not from the proxy: direct access refused.
  assert.equal(resolveClient('192.168.1.50', { 'x-forwarded-for': '10.0.0.1' }, proxies).ok, false);
  // From the proxy: exactly one address is required.
  assert.equal(resolveClient('172.31.250.2', { 'x-forwarded-for': '10.0.0.1' }, proxies).ip, '10.0.0.1');
  assert.equal(resolveClient('172.31.250.2', { 'x-forwarded-for': '10.0.0.1, 192.168.1.5' }, proxies).ok, false);
  assert.equal(resolveClient('172.31.250.2', {}, proxies).ok, false);
  assert.equal(resolveClient('172.31.250.2', { 'x-forwarded-for': 'unknown' }, proxies).ok, false);
  assert.equal(resolveClient('172.31.250.2', { forwarded: 'for=10.0.0.1' }, proxies).ok, false, 'Forwarded header is never used');
});

test('per-client counters group IPv6 addresses by /64', async () => {
  const { clientKey } = await import('../src/netacl.js');
  assert.equal(clientKey('192.168.1.5'), '192.168.1.5');
  assert.equal(clientKey('::ffff:192.168.1.5'), '192.168.1.5');
  assert.equal(clientKey('2001:db8:1:2::1'), clientKey('2001:db8:1:2:ffff:ffff:ffff:fffe'));
  assert.notEqual(clientKey('2001:db8:1:2::1'), clientKey('2001:db8:1:3::1'));
});
