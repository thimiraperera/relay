'use strict';

// Housekeeping for the hourly cPanel cron job (`npm run cleanup`): marks
// interrupted sends as unknown and deletes expired sessions, idempotency keys,
// old log rows and rate counters. Prints the result as JSON; exit code 1 on failure.
//
// It then records kv cleanup.last_cron_run (also when the run was skipped
// because another cleanup held the lock: the cron itself fired). Admin > System
// warns from that key, which the in-process timer never writes, so a broken
// cron job is not hidden by the cleanup that runs a minute after each start.

const { loadConfig, ConfigError } = require('../src/config');
const { createDb } = require('../src/db');
const { createLogger, describeError } = require('../src/lib/logger');
const { systemClock } = require('../src/lib/time');
const { runCleanup, recordCronRun } = require('../src/services/cleanup');

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

  const logger = createLogger({ file: config.logFile });
  const db = createDb(config.db);
  const deps = { config, db, clock: systemClock, logger };
  try {
    let result;
    try {
      result = await runCleanup(deps);
    } catch (err) {
      process.stderr.write(`Cleanup failed: ${describeError(err)}\n`);
      process.exitCode = 1;
      return;
    }
    process.stdout.write(JSON.stringify(result) + '\n');
    try {
      await recordCronRun(deps);
    } catch (err) {
      process.stderr.write(`Cleanup finished, but recording the cron run failed: ${describeError(err)}\n`);
      process.exitCode = 1;
    }
  } finally {
    await db.close().catch(() => {});
  }
}

main().catch((err) => {
  process.stderr.write(`Cleanup failed: ${describeError(err)}\n${err && err.stack ? `${err.stack}\n` : ''}`);
  process.exitCode = 1;
});
