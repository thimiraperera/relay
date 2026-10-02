'use strict';

// rate_counters: fixed-window counters shared by every Node process.

const DELETE_BATCH = 10000;

// Atomic increment that returns the new count in a single statement.
// LAST_INSERT_ID(expr) on the update path makes the OK packet's insertId carry
// count + 1; a fresh insert reports insertId 0 (the table has no AUTO_INCREMENT)
// and affectedRows 1. A separate SELECT LAST_INSERT_ID() is deliberately avoided:
// on a pooled connection it can return a value from an earlier statement.
async function incrementCounter(q, key, expiresAt) {
  const res = await q.query(
    `INSERT INTO rate_counters (k, count, expires_at) VALUES (?, 1, ?)
     ON DUPLICATE KEY UPDATE count = LAST_INSERT_ID(count + 1)`,
    [String(key), expiresAt]
  );
  const id = Number(res.insertId);
  if (res.affectedRows === 1 || !id) return 1;
  return id;
}

async function getCounter(q, key) {
  const rows = await q.query('SELECT count FROM rate_counters WHERE k = ?', [String(key)]);
  return rows.length ? Number(rows[0].count) : 0;
}

// Deletes in batches so a large backlog never holds long row locks.
async function deleteExpiredCounters(q, now) {
  let total = 0;
  for (;;) {
    const res = await q.query('DELETE FROM rate_counters WHERE expires_at < ? LIMIT ?', [now, DELETE_BATCH]);
    total += res.affectedRows;
    if (res.affectedRows < DELETE_BATCH) return total;
  }
}

module.exports = { incrementCounter, getCounter, deleteExpiredCounters };
