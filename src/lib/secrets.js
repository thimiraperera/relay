'use strict';

// High-level helpers for every secret the relay stores encrypted. Each one binds
// the ciphertext to the row it belongs to (see crypto.js for why).
//
//   smtp_password  context "<appId>:<host lowercased>:<port>:<encryption>:<username>"
//                  -> changing any SMTP server setting invalidates the stored password
//   api_key        context "<appId>"   (legacy-signing keys only)
//   totp_secret    context "<adminId>"
//
// Decryption accepts the current MASTER_KEY or MASTER_KEY_PREVIOUS (rotation).

const { encrypt, decryptWithAnyKey } = require('./crypto');

function keys(config) {
  return [config.masterKey, config.masterKeyPrevious || null];
}

function smtpContext(app) {
  return [
    app.id,
    String(app.smtpHost || '').toLowerCase(),
    app.smtpPort,
    app.smtpEncryption,
    app.smtpUsername || '',
  ].join(':');
}

function encryptSmtpPassword(config, app, password) {
  return encrypt(config.masterKey, password, 'smtp_password', smtpContext(app));
}

// Returns the plaintext password, or null when none is stored or it cannot be
// decrypted (wrong key, tampered row, SMTP settings changed without re-entering it).
function decryptSmtpPassword(config, app) {
  if (!app.smtpPasswordEnc) return null;
  try {
    return decryptWithAnyKey(keys(config), app.smtpPasswordEnc, 'smtp_password', smtpContext(app)).plaintext;
  } catch {
    return null;
  }
}

function encryptApiKey(config, appId, key) {
  return encrypt(config.masterKey, key, 'api_key', String(appId));
}

// Throws on failure; callers decide whether to skip or surface it.
function decryptApiKey(config, appId, enc) {
  return decryptWithAnyKey(keys(config), enc, 'api_key', String(appId)).plaintext;
}

function encryptTotpSecret(config, adminId, secret) {
  return encrypt(config.masterKey, secret, 'totp_secret', String(adminId));
}

function decryptTotpSecret(config, adminId, enc) {
  return decryptWithAnyKey(keys(config), enc, 'totp_secret', String(adminId)).plaintext;
}

module.exports = {
  smtpContext,
  encryptSmtpPassword,
  decryptSmtpPassword,
  encryptApiKey,
  decryptApiKey,
  encryptTotpSecret,
  decryptTotpSecret,
};
