'use strict';

// Minimal migration runner: applies migrations/*.sql in filename order, one
// statement at a time, and records each file in schema_migrations. MySQL DDL
// commits implicitly, so a file that fails halfway is not recorded and must be
// fixed by hand; keep each migration small. Runs under a named lock so two
// processes (e.g. AUTO_MIGRATE on several workers) never migrate concurrently.

const fs = require('node:fs/promises');
const path = require('node:path');
const { systemClock } = require('../lib/time');
const { describeError } = require('../lib/logger');

const DEFAULT_DIR = path.join(__dirname, '..', '..', 'migrations');

const CREATE_TABLE = `CREATE TABLE IF NOT EXISTS schema_migrations (
  version VARCHAR(100) NOT NULL,
  applied_at DATETIME NOT NULL,
  PRIMARY KEY (version)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin`;

function isOnlyComments(chunk) {
  const withoutBlocks = chunk.replace(/\/\*[\s\S]*?\*\//g, '');
  return withoutBlocks.split(/\r?\n/).every((line) => {
    const t = line.trim();
    return t === '' || t.startsWith('--') || t.startsWith('#');
  });
}

function splitStatements(sql) {
  return sql
    .replace(/^﻿/, '')
    .split(/;\s*$/m)
    .filter((chunk) => !isOnlyComments(chunk));
}

async function listMigrationFiles(dir) {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  return entries
    .filter((e) => e.isFile() && e.name.toLowerCase().endsWith('.sql'))
    .map((e) => e.name)
    .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

async function applyPending(db, { logger, dir, clock }) {
  await db.query(CREATE_TABLE);
  const rows = await db.query('SELECT version FROM schema_migrations');
  const done = new Set(rows.map((r) => r.version));
  const applied = [];
  for (const file of await listMigrationFiles(dir)) {
    const version = file.replace(/\.sql$/i, '');
    if (done.has(version)) continue;
    if (version.length > 100) throw new Error(`migration name too long: ${file}`);
    const statements = splitStatements(await fs.readFile(path.join(dir, file), 'utf8'));
    for (let i = 0; i < statements.length; i++) {
      try {
        await db.query(statements[i]);
      } catch (err) {
        const wrapped = new Error(
          `migration ${version} failed at statement ${i + 1} of ${statements.length}: ${describeError(err)}`
        );
        wrapped.cause = err;
        throw wrapped;
      }
    }
    await db.query('INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)', [version, clock.now()]);
    if (logger) logger.info('migration applied', { version, statements: statements.length });
    applied.push(version);
  }
  return applied;
}

// Returns the versions applied by this run (empty when up to date).
async function runMigrations(db, { logger, dir = DEFAULT_DIR, clock = systemClock } = {}) {
  const { acquired, result } = await db.withNamedLock('migrate', 60, () =>
    applyPending(db, { logger, dir, clock })
  );
  if (!acquired) throw new Error('could not acquire the migration lock (another migration is running)');
  return result;
}

module.exports = { runMigrations, splitStatements };
