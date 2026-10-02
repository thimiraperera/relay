'use strict';

// Secrets at rest: AES-256-GCM with purpose/context binding (src/lib/crypto.js)
// and the per-secret helpers in src/lib/secrets.js, including master key
// rotation and the rule that an SMTP password stops decrypting when the app's
// SMTP server settings change.

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const nodeCrypto = require('node:crypto');
const c = require('../src/lib/crypto');
const secrets = require('../src/lib/secrets');
const h = require('./support/helpers');
const appsRepo = require('../src/repos/apps');

const KEY_A = nodeCrypto.randomBytes(32);
const KEY_B = nodeCrypto.randomBytes(32);

function tamper(payload, index) {
  const raw = Buffer.from(payload.slice(3), 'base64');
  raw[index] ^= 0x01;
  return 'v1:' + raw.toString('base64');
}

describe('crypto.encrypt / decrypt', () => {
  it('round-trips text, including non-ASCII and empty strings', () => {
    for (const text of ['smtp-password', 'pässwörd ✓ අ', '', 'x'.repeat(5000)]) {
      const enc = c.encrypt(KEY_A, text, 'smtp_password', 'ctx');
      assert.match(enc, /^v1:[A-Za-z0-9+/]+=*$/);
      assert.ok(!enc.includes(text) || text === '');
      assert.equal(c.decrypt(KEY_A, enc, 'smtp_password', 'ctx'), text);
    }
  });

  it('uses a fresh IV for every encryption', () => {
    const a = c.encrypt(KEY_A, 'same', 'api_key', '1');
    const b = c.encrypt(KEY_A, 'same', 'api_key', '1');
    assert.notEqual(a, b);
  });

  it('detects tampering with the IV, tag or ciphertext', () => {
    const enc = c.encrypt(KEY_A, 'secret value', 'totp_secret', '7');
    for (const index of [0, 11, 12, 27, 28, 30]) {
      assert.throws(() => c.decrypt(KEY_A, tamper(enc, index), 'totp_secret', '7'), `byte ${index}`);
    }
    assert.throws(() => c.decrypt(KEY_A, enc.slice(0, 20), 'totp_secret', '7'));
    assert.throws(() => c.decrypt(KEY_A, enc.replace('v1:', 'v2:'), 'totp_secret', '7'));
    assert.throws(() => c.decrypt(KEY_A, null, 'totp_secret', '7'));
  });

  it('only decrypts for the purpose and context it was written for', () => {
    const enc = c.encrypt(KEY_A, 'pw', 'smtp_password', '1:mail.example.com:465:ssl:user');
    assert.throws(() => c.decrypt(KEY_A, enc, 'api_key', '1:mail.example.com:465:ssl:user'));
    assert.throws(() => c.decrypt(KEY_A, enc, 'smtp_password', '2:mail.example.com:465:ssl:user'));
    assert.throws(() => c.decrypt(KEY_A, enc, 'smtp_password', ''));
    assert.throws(() => c.encrypt(KEY_A, 'pw', 'something_else', ''), /unknown encryption purpose/);
  });

  it('refuses the wrong key and malformed keys', () => {
    const enc = c.encrypt(KEY_A, 'pw', 'api_key', '9');
    assert.throws(() => c.decrypt(KEY_B, enc, 'api_key', '9'));
    assert.throws(() => c.encrypt(Buffer.alloc(16), 'pw', 'api_key', '9'), /32-byte/);
    assert.throws(() => c.encrypt('not a buffer', 'pw', 'api_key', '9'), /32-byte/);
  });

  it('decrypts with the previous master key during a rotation', () => {
    const enc = c.encrypt(KEY_A, 'old secret', 'api_key', '5');
    const result = c.decryptWithAnyKey([KEY_B, KEY_A], enc, 'api_key', '5');
    assert.deepEqual(result, { plaintext: 'old secret', keyIndex: 1 });
    assert.deepEqual(c.decryptWithAnyKey([KEY_A, null], enc, 'api_key', '5'), { plaintext: 'old secret', keyIndex: 0 });
    assert.throws(() => c.decryptWithAnyKey([KEY_B, null], enc, 'api_key', '5'));
  });

  it('compares secrets in constant time helpers correctly', () => {
    assert.equal(c.timingSafeEqualStrings('abc', 'abc'), true);
    assert.equal(c.timingSafeEqualStrings('abc', 'abd'), false);
    assert.equal(c.timingSafeEqualStrings('abc', 'abcd'), false);
    assert.equal(c.timingSafeEqualStrings('abc', undefined), false);
    assert.equal(c.timingSafeEqualBuffers(Buffer.from('ab'), Buffer.from('ab')), true);
    assert.equal(c.timingSafeEqualBuffers(Buffer.from('ab'), Buffer.from('abc')), false);
    assert.equal(c.timingSafeEqualBuffers(Buffer.from('ab'), 'ab'), false);
    assert.equal(c.sha256Hex('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });
});

describe('secrets helpers', () => {
  const config = { masterKey: KEY_A, masterKeyPrevious: null };
  const app = {
    id: 42,
    smtpHost: 'mail.example.com',
    smtpPort: 465,
    smtpEncryption: 'ssl',
    smtpUsername: 'noreply@example.com',
    smtpPasswordEnc: null,
  };

  function withPassword(target, password) {
    return { ...target, smtpPasswordEnc: secrets.encryptSmtpPassword(config, target, password) };
  }

  it('round-trips an SMTP password for unchanged settings', () => {
    const stored = withPassword(app, 'mailbox-password');
    assert.ok(!stored.smtpPasswordEnc.includes('mailbox-password'));
    assert.equal(secrets.decryptSmtpPassword(config, stored), 'mailbox-password');
    assert.equal(secrets.decryptSmtpPassword(config, app), null, 'nothing stored');
  });

  it('makes the SMTP password undecryptable after an SMTP server change', () => {
    const stored = withPassword(app, 'mailbox-password');
    for (const change of [
      { smtpHost: 'evil.example.net' },
      { smtpPort: 587 },
      { smtpEncryption: 'none' },
      { smtpUsername: 'someone@example.com' },
      { id: 43 },
    ]) {
      assert.equal(secrets.decryptSmtpPassword(config, { ...stored, ...change }), null, JSON.stringify(change));
    }
    // The host is compared lowercased, so a case-only edit keeps the password.
    assert.equal(secrets.decryptSmtpPassword(config, { ...stored, smtpHost: 'MAIL.Example.COM' }), 'mailbox-password');
  });

  it('reads secrets written with the previous master key', () => {
    const oldConfig = { masterKey: KEY_B, masterKeyPrevious: null };
    const rotating = { masterKey: KEY_A, masterKeyPrevious: KEY_B };
    const stored = { ...app, smtpPasswordEnc: secrets.encryptSmtpPassword(oldConfig, app, 'pw-1') };
    assert.equal(secrets.decryptSmtpPassword(config, stored), null);
    assert.equal(secrets.decryptSmtpPassword(rotating, stored), 'pw-1');

    const apiKeyEnc = secrets.encryptApiKey(oldConfig, 7, 'rly_key');
    assert.equal(secrets.decryptApiKey(rotating, 7, apiKeyEnc), 'rly_key');
    assert.throws(() => secrets.decryptApiKey(config, 7, apiKeyEnc));
    assert.throws(() => secrets.decryptApiKey(rotating, 8, apiKeyEnc), 'bound to the app id');

    const totpEnc = secrets.encryptTotpSecret(oldConfig, 3, 'JBSWY3DPEHPK3PXP');
    assert.equal(secrets.decryptTotpSecret(rotating, 3, totpEnc), 'JBSWY3DPEHPK3PXP');
    assert.throws(() => secrets.decryptTotpSecret(rotating, 4, totpEnc), 'bound to the admin id');
  });
});

describe('SMTP password after a server change (send path)', () => {
  let deps;
  let smtp;
  let httpApp;

  before(async () => {
    if (!h.dbAvailable()) return;
    smtp = await h.startSmtpServer();
    deps = h.createTestDeps({ clock: h.createFakeClock() });
    httpApp = h.createHttpApp(deps);
  });

  after(async () => {
    if (smtp) await smtp.close();
    if (deps) await deps.db.close();
  });

  it('refuses to send with a password stored for other SMTP settings', { timeout: 30000 }, async (t) => {
    if (!h.requireDb(t)) return;
    const { app, key } = await h.insertTestApp(deps, {
      smtp,
      smtpUsername: 'mailer@relay-test.example.com',
      smtpPassword: 'mailbox-password',
    });
    assert.equal(secrets.decryptSmtpPassword(deps.config, app), 'mailbox-password');

    // Someone edits the host directly in the database, bypassing the admin form.
    await appsRepo.updateApp(deps.db, app.id, { smtpHost: 'localhost' }, deps.clock.now());
    const to = h.uniqueEmail();
    const res = await h.postV1(httpApp, key, { to, subject: 'S', text: 'T' });
    assert.equal(res.status, 502);
    assert.deepEqual(res.body, { ok: false, error: 'smtp password not configured' });
    assert.equal(smtp.messagesTo(to).length, 0);
    const last = (await h.listMessages(deps, app.id)).at(-1);
    assert.equal(last.status, 'failed');
    assert.equal(last.error, 'smtp password not configured');
  });
});
