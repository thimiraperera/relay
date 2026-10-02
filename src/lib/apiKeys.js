'use strict';

// API key format: "rly_" + 32 random bytes as base64url (43 chars) = 47 chars.
// Normal keys are stored only as their SHA-256 hash (the key has 256 bits of
// entropy, so a fast unsalted hash is enough); the first 12 characters are kept
// as a display prefix so admins can tell keys apart.

const { randomBase64Url, sha256Hex } = require('./crypto');

const KEY_PREFIX = 'rly_';
const KEY_PATTERN = /^rly_[A-Za-z0-9_-]{43}$/;
const DISPLAY_PREFIX_LENGTH = 12;

function hashApiKey(key) {
  return sha256Hex(key);
}

function generateApiKey() {
  const key = KEY_PREFIX + randomBase64Url(32);
  return { key, prefix: key.slice(0, DISPLAY_PREFIX_LENGTH), hash: hashApiKey(key) };
}

function looksLikeApiKey(s) {
  return typeof s === 'string' && KEY_PATTERN.test(s);
}

module.exports = { generateApiKey, looksLikeApiKey, hashApiKey, KEY_PREFIX };
