'use strict';

// TOTP (RFC 6238, SHA-1, 6 digits, 30 s steps) for admin two-factor sign-in.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const totp = require('../src/lib/totp');

// RFC 6238 appendix B: ASCII secret "12345678901234567890", SHA-1. The RFC
// lists 8-digit codes; a 6-digit code is the same value mod 10^6.
const RFC_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
const RFC_VECTORS = [
  [59, '94287082'],
  [1111111109, '07081804'],
  [1111111111, '14050471'],
  [1234567890, '89005924'],
  [2000000000, '69279037'],
  [20000000000, '65353130'],
];

describe('TOTP', () => {
  it('uses the RFC 4648 base32 encoding of the RFC test secret', () => {
    assert.equal(totp.base32Encode(Buffer.from('12345678901234567890', 'ascii')), RFC_SECRET);
    assert.equal(totp.base32Decode(RFC_SECRET).toString('ascii'), '12345678901234567890');
  });

  for (const [seconds, code8] of RFC_VECTORS) {
    it(`matches the RFC 6238 vector at T=${seconds}`, () => {
      const step = Math.floor(seconds / 30);
      const expected = code8.slice(-6);
      assert.equal(totp.totpAt(RFC_SECRET, step), expected);
      assert.deepEqual(totp.verifyTotp(RFC_SECRET, expected, seconds * 1000), { ok: true, step });
    });
  }

  it('accepts the neighbouring steps within the window and nothing further', () => {
    const nowMs = 1_800_000_015_000;
    const step = Math.floor(nowMs / 30000);
    for (const offset of [-1, 0, 1]) {
      const result = totp.verifyTotp(RFC_SECRET, totp.totpAt(RFC_SECRET, step + offset), nowMs);
      assert.deepEqual(result, { ok: true, step: step + offset }, `offset ${offset}`);
    }
    for (const offset of [-3, -2, 2, 3]) {
      assert.equal(totp.verifyTotp(RFC_SECRET, totp.totpAt(RFC_SECRET, step + offset), nowMs).ok, false, `offset ${offset}`);
    }
    const strict = { window: 0 };
    assert.equal(totp.verifyTotp(RFC_SECRET, totp.totpAt(RFC_SECRET, step), nowMs, strict).ok, true);
    assert.equal(totp.verifyTotp(RFC_SECRET, totp.totpAt(RFC_SECRET, step - 1), nowMs, strict).ok, false);
  });

  it('refuses a code whose step was already used (replay)', () => {
    const nowMs = 1_800_000_015_000;
    const step = Math.floor(nowMs / 30000);
    const code = totp.totpAt(RFC_SECRET, step);
    assert.equal(totp.verifyTotp(RFC_SECRET, code, nowMs, { lastStep: step }).ok, false);
    assert.equal(totp.verifyTotp(RFC_SECRET, code, nowMs, { lastStep: step + 1 }).ok, false);
    assert.deepEqual(totp.verifyTotp(RFC_SECRET, code, nowMs, { lastStep: step - 1 }), { ok: true, step });
    const previous = totp.totpAt(RFC_SECRET, step - 1);
    assert.equal(totp.verifyTotp(RFC_SECRET, previous, nowMs, { lastStep: step - 1 }).ok, false);
  });

  it('refuses malformed codes', () => {
    const nowMs = 59 * 1000;
    for (const bad of ['', '28708', '2870820', '28708a', ' 287082', '287 082', 287082, null, undefined]) {
      assert.equal(totp.verifyTotp(RFC_SECRET, bad, nowMs).ok, false, `accepted ${JSON.stringify(bad)}`);
    }
    assert.equal(totp.verifyTotp('not base32!', '287082', nowMs).ok, false);
  });

  it('generates 160-bit base32 secrets', () => {
    const a = totp.generateSecret();
    const b = totp.generateSecret();
    assert.match(a, /^[A-Z2-7]{32}$/);
    assert.notEqual(a, b);
    assert.equal(totp.base32Decode(a).length, 20);
  });

  it('builds an otpauth URL for authenticator apps', () => {
    const url = totp.otpauthUrl({ secret: RFC_SECRET, accountName: 'admin@example.com' });
    assert.ok(url.startsWith('otpauth://totp/'));
    const parsed = new URL(url);
    assert.equal(parsed.searchParams.get('secret'), RFC_SECRET);
    assert.equal(parsed.searchParams.get('issuer'), 'Relay');
    assert.ok(decodeURIComponent(parsed.pathname).includes('admin@example.com'));
  });
});
