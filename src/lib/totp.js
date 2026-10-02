'use strict';

// TOTP (RFC 6238) with the parameters every authenticator app supports by
// default: HMAC-SHA1, 6 digits, 30-second steps. Secrets are base32 (RFC 4648,
// upper case, no padding), which is what otpauth:// URLs and manual entry use.

const crypto = require('node:crypto');

const STEP_SECONDS = 30;
const DIGITS = 6;
const SECRET_BYTES = 20;
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const CODE_PATTERN = /^\d{6}$/;

function base32Encode(buf) {
  let out = '';
  let bits = 0;
  let value = 0;
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
    value &= (1 << bits) - 1;
  }
  if (bits > 0) out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

// Accepts lower case, spaces and '=' padding (people retype secrets by hand).
// Throws on any other character.
function base32Decode(text) {
  if (typeof text !== 'string') throw new TypeError('base32 secret must be a string');
  const clean = text.replace(/[\s=]+/g, '').toUpperCase();
  const out = [];
  let bits = 0;
  let value = 0;
  for (const ch of clean) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx === -1) throw new Error('invalid base32 character');
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
    value &= (1 << bits) - 1;
  }
  return Buffer.from(out);
}

function generateSecret() {
  return base32Encode(crypto.randomBytes(SECRET_BYTES));
}

function hotp(key, counter) {
  const msg = Buffer.alloc(8);
  // Two 32-bit halves: Node 20 has writeBigUInt64BE, but counters are plain
  // numbers and this avoids BigInt conversions.
  msg.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  msg.writeUInt32BE(counter % 0x100000000, 4);
  const mac = crypto.createHmac('sha1', key).update(msg).digest();
  const offset = mac[mac.length - 1] & 0x0f;
  const bin =
    ((mac[offset] & 0x7f) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
  return String(bin % 10 ** DIGITS).padStart(DIGITS, '0');
}

// The 6-digit code for time step `step` (= floor(unixSeconds / 30)).
function totpAt(secret, step) {
  if (!Number.isSafeInteger(step) || step < 0) throw new RangeError('TOTP step must be a non-negative integer');
  return hotp(base32Decode(secret), step);
}

// Checks `code` against the steps around nowMs. Every candidate step is
// compared (no early exit) with a constant-time comparison. Steps at or before
// `lastStep` are refused so a code cannot be used twice.
// Returns { ok: true, step } or { ok: false, step: null }.
function verifyTotp(secret, code, nowMs, { window = 1, lastStep = null } = {}) {
  if (typeof code !== 'string' || !CODE_PATTERN.test(code)) return { ok: false, step: null };
  let key;
  try {
    key = base32Decode(secret);
  } catch {
    return { ok: false, step: null };
  }
  if (key.length === 0) return { ok: false, step: null };
  const current = Math.floor(nowMs / 1000 / STEP_SECONDS);
  const span = Math.max(0, Math.floor(Number(window) || 0));
  const floor = lastStep === null || lastStep === undefined ? -1 : Number(lastStep);
  const given = Buffer.from(code, 'utf8');
  let matched = null;
  for (let step = current - span; step <= current + span; step++) {
    if (step < 0) continue;
    const equal = crypto.timingSafeEqual(Buffer.from(hotp(key, step), 'utf8'), given);
    if (equal && step > floor && matched === null) matched = step;
  }
  return matched === null ? { ok: false, step: null } : { ok: true, step: matched };
}

function otpauthUrl({ secret, accountName, issuer = 'Relay' }) {
  // encodeURIComponent rather than URLSearchParams: some authenticator apps show
  // a '+' (URLSearchParams' encoding of a space) literally.
  const enc = encodeURIComponent;
  return (
    `otpauth://totp/${enc(issuer)}:${enc(accountName)}` +
    `?secret=${enc(secret)}&issuer=${enc(issuer)}&algorithm=SHA1&digits=${DIGITS}&period=${STEP_SECONDS}`
  );
}

module.exports = {
  generateSecret,
  totpAt,
  verifyTotp,
  otpauthUrl,
  base32Encode,
  base32Decode,
  STEP_SECONDS,
};
