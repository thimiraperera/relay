'use strict';

// Re-encrypts every stored secret with the current MASTER_KEY.
//
// 1. Generate a new key (`npm run gen-secrets`).
// 2. In .env set MASTER_KEY=<new key> and MASTER_KEY_PREVIOUS=<old key>; restart the app.
// 3. Run `node scripts/rotate-master-key.js`.
// 4. When it reports no failures, remove MASTER_KEY_PREVIOUS and restart again.

const { loadConfig, ConfigError } = require('../src/config');
const { createDb } = require('../src/db');
const { createLogger, describeError } = require('../src/lib/logger');
const { systemClock } = require('../src/lib/time');
const { rotateMasterKey } = require('../src/services/rotateKeys');

async function main() {
  let config;
  try {
    config = loadConfig();
  } catch (err) {
    if (err instanceof ConfigError) {
      process.stderr.write(err.message + '\n');
      process.exitCode = 1;
      return;
    }
    throw err;
  }
  if (!config.masterKeyPrevious) {
    process.stderr.write(
      'MASTER_KEY_PREVIOUS is not set. Put the old key in MASTER_KEY_PREVIOUS and the new key in MASTER_KEY, then run this again.\n'
    );
    process.exitCode = 1;
    return;
  }

  const logger = createLogger({ file: config.logFile });
  const db = createDb(config.db);
  try {
    const result = await rotateMasterKey({ config, db, clock: systemClock, logger });
    process.stdout.write(JSON.stringify(result) + '\n');
    if (result.failed > 0) {
      process.stderr.write(
        `${result.failed} stored secret(s) could not be decrypted with MASTER_KEY or MASTER_KEY_PREVIOUS ` +
          'and were left unchanged (see the log for which rows). Re-enter those SMTP passwords, ' +
          'regenerate those API keys or reset those admins\' 2FA.\n'
      );
      process.exitCode = 1;
    } else {
      process.stdout.write('Done. You can now remove MASTER_KEY_PREVIOUS from .env and restart the app.\n');
    }
  } catch (err) {
    process.stderr.write(`Master key rotation failed: ${describeError(err)}\n`);
    process.exitCode = 1;
  } finally {
    await db.close().catch(() => {});
  }
}

main().catch((err) => {
  process.stderr.write(`Master key rotation failed: ${describeError(err)}\n${err && err.stack ? `${err.stack}\n` : ''}`);
  process.exitCode = 1;
});
