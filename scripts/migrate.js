'use strict';

// Applies pending database migrations: `npm run migrate` (or `node scripts/migrate.js`
// from cPanel "Run JS script" / SSH). Exit code 1 on failure.

const path = require('node:path');
const { loadConfig, ConfigError } = require('../src/config');
const { createDb } = require('../src/db');
const { createLogger, describeError } = require('../src/lib/logger');
const { runMigrations } = require('../src/services/migrate');

// runMigrations wraps a failing statement's server error (kept in .cause) as
// "migration <v> failed at statement i of n: <message>". Make sure the cause's
// code, or its whole reason when its message is empty, reaches the output.
function failureReason(err) {
  const text = describeError(err);
  const cause = err && typeof err === 'object' ? err.cause : null;
  if (!cause || typeof cause !== 'object') return text;
  const inner = describeError(cause);
  if (text.includes(inner)) return text;
  if (cause.message && text.includes(cause.message)) {
    return cause.code && !text.includes(cause.code) ? `${text} (${cause.code})` : text;
  }
  return `${text.replace(/[:\s]+$/, '')}: ${inner}`;
}

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
  try {
    const applied = await runMigrations(db, { logger, dir: path.join(__dirname, '..', 'migrations') });
    if (applied.length) process.stdout.write(`Applied migrations: ${applied.join(', ')}\n`);
    else process.stdout.write('Database is up to date (no pending migrations).\n');
  } catch (err) {
    process.stderr.write(`Migration failed: ${failureReason(err)}\n`);
    process.exitCode = 1;
  } finally {
    await db.close().catch(() => {});
  }
}

main().catch((err) => {
  process.stderr.write(`Migration failed: ${describeError(err)}\n${err && err.stack ? `${err.stack}\n` : ''}`);
  process.exitCode = 1;
});
