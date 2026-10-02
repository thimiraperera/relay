'use strict';

// Secret handling primitives.
//
// encrypt/decrypt: AES-256-GCM with a 32-byte master key. Ciphertext format:
//   "v1:" + base64( iv[12] || tag[16] || ciphertext )
// The additional authenticated data is "relay:<purpose>[:<context>]", so a
// ciphertext only decrypts for the purpose and context it was written for: an
// SMTP password copied to another app, or left behind after someone edits the
// app's SMTP host directly in the database, fails to decrypt instead of being
// sent to a different server. See src/lib/secrets.js for the contexts used.

const crypto = require('node:crypto');

const FORMAT = 'v1:';
const IV_LEN = 12;
const TAG_LEN = 16;
const PURPOSES = new Set(['smtp_password', 'api_key', 'totp_secret']);

function checkKey(masterKey) {
  if (!Buffer.isBuffer(masterKey) || masterKey.length !== 32) {
    throw new Error('master key must be a 32-byte Buffer');
  }
}

function aad(purpose, context) {
  if (!PURPOSES.has(purpose)) throw new Error(`unknown encryption purpose: ${purpose}`);
  if (typeof context !== 'string') throw new TypeError('encryption context must be a string');
  return Buffer.from(context ? `relay:${purpose}:${context}` : `relay:${purpose}`, 'utf8');
}

function encrypt(masterKey, plaintext, purpose, context = '') {
  checkKey(masterKey);
  const ad = aad(purpose, context);
  if (typeof plaintext !== 'string') throw new TypeError('plaintext must be a string');
  const iv = crypto.randomBytes(IV_LEN);
  const cipher = crypto.createCipheriv('aes-256-gcm', masterKey, iv, { authTagLength: TAG_LEN });
  cipher.setAAD(ad);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return FORMAT + Buffer.concat([iv, tag, ct]).toString('base64');
}

// Throws if the payload is malformed, was encrypted with another key, purpose or
// context, or was tampered with.
function decrypt(masterKey, payload, purpose, context = '') {
  checkKey(masterKey);
  const ad = aad(purpose, context);
  if (typeof payload !== 'string' || !payload.startsWith(FORMAT)) {
    throw new Error('unsupported ciphertext format');
  }
  const raw = Buffer.from(payload.slice(FORMAT.length), 'base64');
  if (raw.length < IV_LEN + TAG_LEN) throw new Error('ciphertext too short');
  const iv = raw.subarray(0, IV_LEN);
  const tag = raw.subarray(IV_LEN, IV_LEN + TAG_LEN);
  const ct = raw.subarray(IV_LEN + TAG_LEN);
  const decipher = crypto.createDecipheriv('aes-256-gcm', masterKey, iv, { authTagLength: TAG_LEN });
  decipher.setAAD(ad);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
}

// Tries each key in order (current master key first, then MASTER_KEY_PREVIOUS
// during a rotation). Returns { plaintext, keyIndex }; throws the first error if
// no key works.
function decryptWithAnyKey(keys, payload, purpose, context = '') {
  let firstErr = null;
  for (let i = 0; i < keys.length; i++) {
    if (!keys[i]) continue;
    try {
      return { plaintext: decrypt(keys[i], payload, purpose, context), keyIndex: i };
    } catch (err) {
      if (!firstErr) firstErr = err;
    }
  }
  throw firstErr || new Error('no decryption key available');
}

function sha256Hex(input) {
  return crypto.createHash('sha256').update(input).digest('hex');
}

function hmacSha256(key, data) {
  return crypto.createHmac('sha256', key).update(data).digest();
}

// Constant-time comparison of two Buffers of possibly different lengths.
function timingSafeEqualBuffers(a, b) {
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) return false;
  if (a.length !== b.length) {
    // Still do a comparison of equal work so the length check is not a shortcut.
    crypto.timingSafeEqual(a, a);
    return false;
  }
  return crypto.timingSafeEqual(a, b);
}

// Constant-time comparison of two strings (compares SHA-256 digests, so the
// running time does not depend on where the strings differ or on their lengths).
function timingSafeEqualStrings(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const da = crypto.createHash('sha256').update(a, 'utf8').digest();
  const db = crypto.createHash('sha256').update(b, 'utf8').digest();
  return crypto.timingSafeEqual(da, db);
}

function randomBase64Url(bytes) {
  return crypto.randomBytes(bytes).toString('base64url');
}

function randomHex(bytes) {
  return crypto.randomBytes(bytes).toString('hex');
}

module.exports = {
  encrypt,
  decrypt,
  decryptWithAnyKey,
  sha256Hex,
  hmacSha256,
  timingSafeEqualBuffers,
  timingSafeEqualStrings,
  randomBase64Url,
  randomHex,
};
