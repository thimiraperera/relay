'use strict';

// Recreates the test database from scratch: `npm test` runs this before
// `node --test`. Settings come from .env.test (TEST_DB_HOST, TEST_DB_PORT,
// TEST_DB_SOCKET, TEST_DB_USER, TEST_DB_PASSWORD, TEST_DB_NAME); variables already
// set in the environment win. Without TEST_DB_NAME the database tests skip
// themselves, so this exits 0 after a warning instead of failing the run.

const path = require('node:path');
const mysql = require('mysql2/promise');
const { createDb } = require('../src/db');
const { createLogger, describeError } = require('../src/lib/logger');
const { runMigrations } = require('../src/services/migrate');

const ROOT = path.join(__dirname, '..');

// The name is interpolated into DROP/CREATE DATABASE, so only plain identifiers.
// Requiring "test" in it keeps a mistyped .env.test from dropping a real database.
const SAFE_NAME = /^[A-Za-z0-9_]{1,64}$/;

function warnSkipped() {
  const bar = '='.repeat(72);
  process.stderr.write(
    [
      bar,
      '  DB TESTS WILL BE SKIPPED: TEST_DB_NAME is not set.',
      '  Set TEST_DB_HOST, TEST_DB_PORT, TEST_DB_USER, TEST_DB_PASSWORD and',
      '  TEST_DB_NAME in .env.test (or the environment) to run them.',
      bar,
      '',
    ].join('\n')
  );
}

function connectionOptions(env) {
  const opts = env.TEST_DB_SOCKET
    ? { socketPath: env.TEST_DB_SOCKET }
    : { host: env.TEST_DB_HOST || '127.0.0.1', port: Number(env.TEST_DB_PORT || 3306) };
  return { ...opts, user: env.TEST_DB_USER, password: env.TEST_DB_PASSWORD || '' };
}

async function main() {
  require('dotenv').config({ path: path.join(ROOT, '.env.test'), quiet: true });
  const env = process.env;
  const name = (env.TEST_DB_NAME || '').trim();
  if (!name) {
    warnSkipped();
    return;
  }
  if (!SAFE_NAME.test(name) || !/test/i.test(name)) {
    throw new Error(
      `TEST_DB_NAME "${name}" refused: use letters, digits and underscores only, and include "test" in the name`
    );
  }
  if (!env.TEST_DB_USER) throw new Error('TEST_DB_USER is required when TEST_DB_NAME is set');

  const conn = await mysql.createConnection({ ...connectionOptions(env), connectTimeout: 10000 });
  try {
    await conn.query(`DROP DATABASE IF EXISTS \`${name}\``);
    await conn.query(`CREATE DATABASE \`${name}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
  } finally {
    await conn.end().catch(() => {});
  }

  // runMigrations holds a named lock on one connection while it migrates on
  // another, so the pool needs at least two.
  const db = createDb({ ...connectionOptions(env), database: name, connectionLimit: 2 });
  try {
    const applied = await runMigrations(db, { logger: createLogger({ silent: true }), dir: path.join(ROOT, 'migrations') });
    process.stdout.write(`Test database ${name} recreated; applied migrations: ${applied.join(', ') || '(none)'}\n`);
  } finally {
    await db.close().catch(() => {});
  }
}

main().catch((err) => {
  // describeError: a refused connection to "localhost" is an AggregateError with
  // an empty message.
  process.stderr.write(`reset-test-db failed: ${describeError(err)}\n`);
  process.exitCode = 1;
});
