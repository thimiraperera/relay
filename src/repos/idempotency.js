'use strict';

// idempotency_keys: (app_id, idem_key) -> the message row that currently owns the
// caller's message_id. The send service decides what an existing entry means.

const { isDuplicateKeyError } = require('../db');

function toId(v) {
  const n = typeof v === 'string' && /^\d+$/.test(v) ? Number(v) : v;
  return Number.isSafeInteger(n) && n > 0 ? n : null;
}

async function findIdempotency(q, appId, key) {
  const rows = await q.query(
    `SELECT i.app_id, i.idem_key, i.message_id, i.created_at,
       m.id AS m_id, m.public_id AS m_public_id, m.status AS m_status, m.created_at AS m_created_at
     FROM idempotency_keys i LEFT JOIN messages m ON m.id = i.message_id
     WHERE i.app_id = ? AND i.idem_key = ?`,
    [toId(appId), String(key)]
  );
  const r = rows[0];
  if (!r) return null;
  return {
    appId: r.app_id,
    key: r.idem_key,
    messageId: r.message_id,
    createdAt: r.created_at,
    message:
      r.m_id === null || r.m_id === undefined
        ? null
        : { id: r.m_id, publicId: r.m_public_id, status: r.m_status, createdAt: r.m_created_at },
  };
}

// true when inserted, false when the (app, key) pair already exists.
async function insertIdempotency(q, appId, key, messageId, now) {
  try {
    await q.query('INSERT INTO idempotency_keys (app_id, idem_key, message_id, created_at) VALUES (?, ?, ?, ?)', [
      toId(appId),
      String(key),
      toId(messageId),
      now,
    ]);
    return true;
  } catch (err) {
    if (isDuplicateKeyError(err)) return false;
    throw err;
  }
}

// Compare-and-swap: moves the key to toMessageId only if it still points at
// fromMessageId. The window restarts with the new attempt.
async function reassignIdempotency(q, appId, key, fromMessageId, toMessageId, now) {
  const res = await q.query(
    `UPDATE idempotency_keys SET message_id = ?, created_at = ?
     WHERE app_id = ? AND idem_key = ? AND message_id = ?`,
    [toId(toMessageId), now, toId(appId), String(key), toId(fromMessageId)]
  );
  return res.affectedRows === 1;
}

async function deleteIdempotencyBefore(q, cutoff) {
  const res = await q.query('DELETE FROM idempotency_keys WHERE created_at < ?', [cutoff]);
  return res.affectedRows;
}

module.exports = { findIdempotency, insertIdempotency, reassignIdempotency, deleteIdempotencyBefore };
