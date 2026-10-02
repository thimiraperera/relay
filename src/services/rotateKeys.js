'use strict';

// Master key rotation. Procedure: set MASTER_KEY to a new key and
// MASTER_KEY_PREVIOUS to the old one (the app keeps working, decrypting with
// either), run scripts/rotate-master-key.js, then remove MASTER_KEY_PREVIOUS.
//
// Every stored secret is decrypted with whichever key works and re-encrypted
// with the current MASTER_KEY in one transaction. Rows that decrypt with neither
// key are left untouched and counted in `failed` (they must be re-entered).

const {
  decryptSmtpPassword,
  encryptSmtpPassword,
  decryptApiKey,
  encryptApiKey,
  decryptTotpSecret,
  encryptTotpSecret,
} = require('../lib/secrets');
const appsRepo = require('../repos/apps');
const keysRepo = require('../repos/apiKeys');
const adminsRepo = require('../repos/admins');
const { recordAudit, SYSTEM_ACTOR } = require('./audit');

async function rotateAll(deps, tx) {
  const { config, logger } = deps;
  const counts = { smtpPasswords: 0, apiKeys: 0, totpSecrets: 0, failed: 0 };

  for (const app of await appsRepo.listApps(tx, { forUpdate: true })) {
    if (!app.smtpPasswordEnc) continue;
    const password = decryptSmtpPassword(config, app);
    if (password === null) {
      counts.failed++;
      logger.warn('master key rotation: smtp password not decryptable', { appId: app.id });
      continue;
    }
    await appsRepo.setAppSmtpPasswordEnc(tx, app.id, encryptSmtpPassword(config, app, password));
    counts.smtpPasswords++;
  }

  for (const key of await keysRepo.listEncryptedKeys(tx, { forUpdate: true })) {
    let plain;
    try {
      plain = decryptApiKey(config, key.appId, key.keyEnc);
    } catch {
      counts.failed++;
      logger.warn('master key rotation: api key not decryptable', { keyId: key.id, appId: key.appId });
      continue;
    }
    await keysRepo.setKeyEnc(tx, key.id, encryptApiKey(config, key.appId, plain));
    counts.apiKeys++;
  }

  for (const admin of await adminsRepo.listAdmins(tx, { forUpdate: true })) {
    if (!admin.totpSecretEnc) continue;
    let secret;
    try {
      secret = decryptTotpSecret(config, admin.id, admin.totpSecretEnc);
    } catch {
      counts.failed++;
      logger.warn('master key rotation: totp secret not decryptable', { adminId: admin.id });
      continue;
    }
    await adminsRepo.setTotpSecretEnc(tx, admin.id, encryptTotpSecret(config, admin.id, secret));
    counts.totpSecrets++;
  }

  return counts;
}

async function rotateMasterKey(deps, { actor = SYSTEM_ACTOR } = {}) {
  if (!deps.config.masterKeyPrevious) {
    throw new Error('MASTER_KEY_PREVIOUS is not set; set it to the old key and MASTER_KEY to the new one first');
  }
  const { acquired, result } = await deps.db.withNamedLock('rotate', 30, () =>
    deps.db.transaction(async (tx) => {
      const counts = await rotateAll(deps, tx);
      await recordAudit(
        tx,
        actor,
        'system.master_key_rotate',
        { targetType: 'system', targetId: null, details: counts },
        deps.clock.now()
      );
      return counts;
    })
  );
  if (!acquired) throw new Error('could not acquire the rotation lock (another rotation is running)');
  deps.logger.info('master key rotation finished', result);
  return result;
}

module.exports = { rotateMasterKey };
