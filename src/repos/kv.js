'use strict';

// kv: small operational values (last cleanup run, auth-failure notes, ...).

async function getKv(q, k) {
  const rows = await q.query('SELECT v FROM kv WHERE k = ?', [String(k)]);
  if (!rows.length || rows[0].v === null) return null;
  return String(rows[0].v);
}

async function setKv(q, k, v, now) {
  const value = v === null || v === undefined ? null : String(v);
  await q.query('INSERT INTO kv (k, v, updated_at) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE v = ?, updated_at = ?', [
    String(k),
    value,
    now,
    value,
    now,
  ]);
}

module.exports = { getKv, setKv };
