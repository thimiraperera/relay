'use strict';

// /send.php request signing, as the existing PHP app does it:
//   X-Relay-Timestamp: <unix seconds>
//   X-Relay-Signature: sha256=<hex HMAC-SHA256(api_key, timestamp + "." + raw body)>
// The timestamp is signed exactly as the header text was sent (after trimming),
// so "0001700000000" and "1700000000" are different signatures.

const crypto = require('node:crypto');
const { timingSafeEqualBuffers } = require('./crypto');

// WebCrypto runs HMAC as an async job on libuv's thread pool; node:crypto's
// createHmac hashes on the main thread. Node 20 has the global.
const subtle = (globalThis.crypto && globalThis.crypto.subtle) || crypto.webcrypto.subtle;
const HMAC_SHA256 = Object.freeze({ name: 'HMAC', hash: 'SHA-256' });

const SIGNATURE_HEADER = /^sha256=([0-9a-fA-F]{64})$/;
const TIMESTAMP_HEADER = /^\d{1,12}$/;

function parseSignatureHeader(v) {
  if (typeof v !== 'string') return null;
  const m = SIGNATURE_HEADER.exec(v.trim());
  return m ? Buffer.from(m[1], 'hex') : null;
}

function parseTimestampHeader(v) {
  if (typeof v !== 'string') return null;
  const text = v.trim();
  if (!TIMESTAMP_HEADER.test(text)) return null;
  return { text, seconds: Number(text) };
}

function isTimestampFresh(seconds, nowMs, maxSkewSeconds) {
  if (!Number.isFinite(seconds) || !Number.isFinite(nowMs)) return false;
  return Math.abs(nowMs / 1000 - seconds) <= maxSkewSeconds;
}

function bodyBuffer(rawBody) {
  return Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(rawBody || '', 'utf8');
}

// HMAC-SHA256(utf8 key, timestamp + '.' + body), synchronously, on the calling
// thread. The prefix and the body are fed to the HMAC one after the other: the
// same digest as hashing their concatenation, without a copy. The request path
// uses matchSignatureKeys; this stays for tests, snippets and small inputs.
function computeSignature(key, timestampText, rawBody) {
  return crypto
    .createHmac('sha256', Buffer.from(key, 'utf8'))
    .update(Buffer.from(timestampText + '.', 'utf8'))
    .update(bodyBuffer(rawBody))
    .digest();
}

function signatureMatches(key, timestampText, rawBody, sigBuf) {
  return timingSafeEqualBuffers(computeSignature(key, timestampText, rawBody), sigBuf);
}

// The same digest as computeSignature, from bytes already joined by
// signedBytes, computed off the main thread.
async function hmacOffThread(key, data) {
  const cryptoKey = await subtle.importKey('raw', Buffer.from(key, 'utf8'), HMAC_SHA256, false, ['sign']);
  return Buffer.from(await subtle.sign('HMAC', cryptoKey, data));
}

// timestamp + '.' + body as one buffer: WebCrypto has no incremental update.
function signedBytes(timestampText, rawBody) {
  return Buffer.concat([Buffer.from(timestampText + '.', 'utf8'), bodyBuffer(rawBody)]);
}

async function computeSignatureAsync(key, timestampText, rawBody) {
  return hmacOffThread(key, signedBytes(timestampText, rawBody));
}

// /send.php tries every valid legacy key. Hashing a body of up to
// bodyLimitBytes once per key on the main thread stalled every other request
// for the whole time (65-100 ms for a forged 8 MB request with three keys), so
// the digests are computed as WebCrypto jobs on the thread pool, all at once
// (about 16 ms of main-thread copying remains). The signed bytes are built once
// and shared by every key; Node itself copies them into each job. Every digest
// is compared with the header signature in constant time; there is no early
// exit. → Promise<boolean[]>, one entry per key, in order.
async function matchSignatureKeys(keys, timestampText, rawBody, sigBuf) {
  if (!keys.length) return [];
  const data = signedBytes(timestampText, rawBody);
  const digests = await Promise.all(
    // A key WebCrypto refuses (e.g. an empty one) is still checked, the old way.
    keys.map((key) => hmacOffThread(key, data).catch(() => computeSignature(key, timestampText, rawBody)))
  );
  return digests.map((digest) => timingSafeEqualBuffers(digest, sigBuf));
}

function formatSignature(buf) {
  return 'sha256=' + buf.toString('hex');
}

module.exports = {
  parseSignatureHeader,
  parseTimestampHeader,
  isTimestampFresh,
  computeSignature,
  signatureMatches,
  computeSignatureAsync,
  matchSignatureKeys,
  formatSignature,
};
