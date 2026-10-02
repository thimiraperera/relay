'use strict';

// Thin wrapper around a mysql2/promise pool.
//
// Every repo function takes a "queryable" `q` as its first argument: either the
// object returned by createDb() or the `tx` object passed into db.transaction().
// Both expose `q.query(sql, params)` which resolves to the rows array for SELECTs
// and to the ResultSetHeader ({ affectedRows, insertId, ... }) for writes.
//
// All DATETIME columns are UTC (pool option timezone 'Z'). DATE columns come back
// as 'YYYY-MM-DD' strings.

const mysql = require('mysql2/promise');

function createDb(dbConfig) {
  const conn = dbConfig.socketPath
    ? { socketPath: dbConfig.socketPath }
    : { host: dbConfig.host, port: dbConfig.port };
  const pool = mysql.createPool({
    ...conn,
    user: dbConfig.user,
    password: dbConfig.password,
    database: dbConfig.database,
    connectionLimit: dbConfig.connectionLimit || 5,
    // Shared MySQL servers often have a short wait_timeout; drop idle connections
    // ourselves instead of finding them dead.
    maxIdle: Math.min(2, dbConfig.connectionLimit || 5),
    idleTimeout: 30000,
    waitForConnections: true,
    queueLimit: 0,
    timezone: 'Z',
    dateStrings: ['DATE'],
    charset: 'utf8mb4',
    supportBigNumbers: true,
    bigNumberStrings: false,
    decimalNumbers: true,
    enableKeepAlive: true,
    connectTimeout: 10000,
  });

  async function query(sql, params) {
    const [result] = await pool.query(sql, params);
    return result;
  }

  const ISOLATION_LEVELS = new Set(['READ COMMITTED', 'REPEATABLE READ', 'SERIALIZABLE']);

  // Runs fn(tx) inside a transaction on a dedicated connection. Commits when fn
  // resolves, rolls back and rethrows when it rejects.
  //
  // { isolation: 'READ COMMITTED' } is for transactions that lock a parent row and
  // then read-and-update children that other requests touch without that lock
  // (e.g. api_keys.last_used_at): under REPEATABLE READ with MariaDB 11.6+'s
  // innodb_snapshot_isolation=ON such an UPDATE fails with ER_CHECKREAD.
  async function transaction(fn, { isolation } = {}) {
    if (isolation !== undefined && !ISOLATION_LEVELS.has(isolation)) {
      throw new Error(`unsupported isolation level: ${isolation}`);
    }
    const conn = await pool.getConnection();
    try {
      // Without GLOBAL/SESSION this applies to the next transaction only.
      if (isolation) await conn.query(`SET TRANSACTION ISOLATION LEVEL ${isolation}`);
      await conn.beginTransaction();
      const tx = {
        query: async (sql, params) => {
          const [result] = await conn.query(sql, params);
          return result;
        },
      };
      const out = await fn(tx);
      await conn.commit();
      return out;
    } catch (err) {
      try {
        await conn.rollback();
      } catch {
        // ignore rollback failures; the original error is more useful
      }
      throw err;
    } finally {
      conn.release();
    }
  }

  // GET_LOCK names are server-wide on MySQL/MariaDB, i.e. shared with every other
  // database on a shared host, so namespace them by database name (max 64 chars).
  function lockName(name) {
    return `${dbConfig.database}:${name}`.slice(0, 64);
  }

  // MySQL named lock held on one connection for the duration of fn.
  // Returns { acquired: false } without running fn if the lock is busy.
  async function withNamedLock(name, timeoutSeconds, fn) {
    const conn = await pool.getConnection();
    const full = lockName(name);
    try {
      const [rows] = await conn.query('SELECT GET_LOCK(?, ?) AS ok', [full, timeoutSeconds]);
      if (!rows[0] || rows[0].ok !== 1) return { acquired: false };
      try {
        return { acquired: true, result: await fn() };
      } finally {
        await conn.query('SELECT RELEASE_LOCK(?)', [full]).catch(() => {});
      }
    } finally {
      conn.release();
    }
  }

  async function close() {
    await pool.end();
  }

  return { pool, query, transaction, withNamedLock, lockName, close };
}

function isDuplicateKeyError(err) {
  return Boolean(err && (err.code === 'ER_DUP_ENTRY' || err.errno === 1062));
}

module.exports = { createDb, isDuplicateKeyError };
