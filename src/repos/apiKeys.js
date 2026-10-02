'use strict';

// api_keys table. A key is valid at t when revoked_at IS NULL AND (expires_at IS
// NULL OR expires_at > t); "active" = valid with no expiry (at most one per app),
// "grace" = valid with an expiry. Legacy keys carry key_enc instead of key_hash.

const FULL_COLUMNS = `id, app_id, prefix, key_hash, key_enc, created_by, created_at, last_used_at,
  expires_at, revoked_at`;

function toId(v) {
  const n = typeof v === 'string' && /^\d+$/.test(v) ? Number(v) : v;
  return Number.isSafeInteger(n) && n > 0 ? n : null;
}

function mapKey(r) {
  if (!r) return null;
  return {
    id: r.id,
    appId: r.app_id,
    prefix: r.prefix,
    legacy: r.key_enc !== null && r.key_enc !== undefined,
    keyHash: r.key_hash,
    keyEnc: r.key_enc,
    createdBy: r.created_by,
    createdAt: r.created_at,
    lastUsedAt: r.last_used_at,
    expiresAt: r.expires_at,
    revokedAt: r.revoked_at,
  };
}

// For display: never includes the hash or the ciphertext.
function mapPublicKey(r) {
  return {
    id: r.id,
    appId: r.app_id,
    prefix: r.prefix,
    legacy: Boolean(r.legacy),
    createdBy: r.created_by,
    createdAt: r.created_at,
    lastUsedAt: r.last_used_at,
    expiresAt: r.expires_at,
    revokedAt: r.revoked_at,
  };
}

async function listKeysForApp(q, appId) {
  const id = toId(appId);
  if (id === null) return [];
  const rows = await q.query(
    `SELECT id, app_id, prefix, (key_enc IS NOT NULL) AS legacy, created_by, created_at, last_used_at,
       expires_at, revoked_at
     FROM api_keys WHERE app_id = ? ORDER BY created_at DESC, id DESC`,
    [id]
  );
  return rows.map(mapPublicKey);
}

async function getKey(q, id) {
  const keyId = toId(id);
  if (keyId === null) return null;
  const rows = await q.query(`SELECT ${FULL_COLUMNS} FROM api_keys WHERE id = ?`, [keyId]);
  return mapKey(rows[0]);
}

async function findKeyByHash(q, hash) {
  if (typeof hash !== 'string' || hash === '') return null;
  const rows = await q.query(`SELECT ${FULL_COLUMNS} FROM api_keys WHERE key_hash = ?`, [hash]);
  return mapKey(rows[0]);
}

// Every currently valid legacy key of every legacy-signing app (enabled or not:
// a disabled app must still be identified so it gets 403 rather than 401).
async function listValidLegacyKeys(q, now) {
  const rows = await q.query(
    `SELECT k.id, k.app_id, k.key_enc
     FROM api_keys k JOIN apps a ON a.id = k.app_id
     WHERE k.key_enc IS NOT NULL AND k.revoked_at IS NULL
       AND (k.expires_at IS NULL OR k.expires_at > ?) AND a.legacy_signing = 1
     ORDER BY k.id`,
    [now]
  );
  return rows.map((r) => ({ id: r.id, appId: r.app_id, keyEnc: r.key_enc }));
}

// `now` is accepted for symmetry with the other validity queries; an active key
// has no expiry, so only revocation matters.
async function listActiveKeys(q, appId, now, { forUpdate = false } = {}) {
  const id = toId(appId);
  if (id === null) return [];
  const rows = await q.query(
    `SELECT ${FULL_COLUMNS} FROM api_keys
     WHERE app_id = ? AND revoked_at IS NULL AND expires_at IS NULL
     ORDER BY id DESC${forUpdate ? ' FOR UPDATE' : ''}`,
    [id]
  );
  return rows.map(mapKey);
}

async function listGraceKeys(q, appId, now) {
  const id = toId(appId);
  if (id === null) return [];
  const rows = await q.query(
    `SELECT ${FULL_COLUMNS} FROM api_keys
     WHERE app_id = ? AND revoked_at IS NULL AND expires_at IS NOT NULL AND expires_at > ?
     ORDER BY id DESC`,
    [id, now]
  );
  return rows.map(mapKey);
}

async function insertKey(q, { appId, prefix, keyHash, keyEnc, createdBy, now }) {
  const hasHash = typeof keyHash === 'string' && keyHash !== '';
  const hasEnc = typeof keyEnc === 'string' && keyEnc !== '';
  if (hasHash === hasEnc) throw new Error('insertKey: exactly one of keyHash or keyEnc is required');
  const res = await q.query(
    `INSERT INTO api_keys (app_id, prefix, key_hash, key_enc, created_by, created_at)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [toId(appId), String(prefix), hasHash ? keyHash : null, hasEnc ? keyEnc : null, toId(createdBy), now]
  );
  return Number(res.insertId);
}

async function setKeyExpiry(q, id, expiresAt) {
  const res = await q.query('UPDATE api_keys SET expires_at = ? WHERE id = ?', [expiresAt, toId(id)]);
  return res.affectedRows;
}

async function revokeKey(q, id, now) {
  const res = await q.query('UPDATE api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL', [
    now,
    toId(id),
  ]);
  return res.affectedRows;
}

// Revokes the app's keys that are still valid at `now` (already expired grace
// keys keep their "expired" history instead of turning into "revoked").
async function revokeAllKeysForApp(q, appId, now) {
  const res = await q.query(
    `UPDATE api_keys SET revoked_at = ?
     WHERE app_id = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)`,
    [now, toId(appId), now]
  );
  return res.affectedRows;
}

async function touchKeyLastUsed(q, id, now) {
  const res = await q.query(
    'UPDATE api_keys SET last_used_at = ? WHERE id = ? AND (last_used_at IS NULL OR last_used_at < ?)',
    [now, toId(id), now]
  );
  return res.affectedRows;
}

// Master key rotation: every stored ciphertext, valid or not.
async function listEncryptedKeys(q, { forUpdate = false } = {}) {
  const rows = await q.query(
    `SELECT id, app_id, key_enc FROM api_keys WHERE key_enc IS NOT NULL ORDER BY id${forUpdate ? ' FOR UPDATE' : ''}`
  );
  return rows.map((r) => ({ id: r.id, appId: r.app_id, keyEnc: r.key_enc }));
}

async function setKeyEnc(q, id, enc) {
  const res = await q.query('UPDATE api_keys SET key_enc = ? WHERE id = ? AND key_enc IS NOT NULL', [enc, toId(id)]);
  return res.affectedRows;
}

module.exports = {
  listKeysForApp,
  getKey,
  findKeyByHash,
  listValidLegacyKeys,
  listActiveKeys,
  listGraceKeys,
  insertKey,
  setKeyExpiry,
  revokeKey,
  revokeAllKeysForApp,
  touchKeyLastUsed,
  listEncryptedKeys,
  setKeyEnc,
};
