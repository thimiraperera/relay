'use strict';

// admin_users table. Emails are stored and looked up lowercased (binary
// collation, see the migration). updateAdmin writes only whitelisted fields.

const COLUMNS = `id, email, name, password_hash, totp_secret_enc, totp_enabled, totp_last_step,
  session_epoch, disabled, last_login_at, created_at, updated_at`;

const FIELDS = Object.freeze({
  name: { col: 'name', type: 'textOrEmpty' },
  passwordHash: { col: 'password_hash', type: 'text' },
  totpSecretEnc: { col: 'totp_secret_enc', type: 'nullableText' },
  totpEnabled: { col: 'totp_enabled', type: 'bool' },
  totpLastStep: { col: 'totp_last_step', type: 'nullableInt' },
  disabled: { col: 'disabled', type: 'bool' },
  lastLoginAt: { col: 'last_login_at', type: 'nullableDate' },
});

function toId(v) {
  const n = typeof v === 'string' && /^\d+$/.test(v) ? Number(v) : v;
  return Number.isSafeInteger(n) && n > 0 ? n : null;
}

function convert(key, spec, value) {
  switch (spec.type) {
    case 'text':
      if (value === null) throw new TypeError(`admin field ${key} cannot be null`);
      return String(value);
    case 'textOrEmpty':
      return value === null ? '' : String(value);
    case 'nullableText':
      return value === null ? null : String(value);
    case 'bool':
      return value ? 1 : 0;
    case 'nullableInt': {
      if (value === null) return null;
      const n = Number(value);
      if (!Number.isSafeInteger(n)) throw new TypeError(`admin field ${key} must be an integer`);
      return n;
    }
    case 'nullableDate':
      if (value === null) return null;
      if (!(value instanceof Date) || Number.isNaN(value.getTime())) {
        throw new TypeError(`admin field ${key} must be a Date`);
      }
      return value;
    default:
      throw new Error(`unhandled field type ${spec.type}`);
  }
}

function mapAdmin(r) {
  if (!r) return null;
  return {
    id: r.id,
    email: r.email,
    name: r.name,
    passwordHash: r.password_hash,
    totpSecretEnc: r.totp_secret_enc,
    totpEnabled: Boolean(r.totp_enabled),
    totpLastStep: r.totp_last_step === null || r.totp_last_step === undefined ? null : Number(r.totp_last_step),
    sessionEpoch: r.session_epoch,
    disabled: Boolean(r.disabled),
    lastLoginAt: r.last_login_at,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  };
}

async function countAdmins(q) {
  const rows = await q.query('SELECT COUNT(*) AS n FROM admin_users');
  return Number(rows[0].n);
}

async function countEnabledAdmins(q) {
  const rows = await q.query('SELECT COUNT(*) AS n FROM admin_users WHERE disabled = 0');
  return Number(rows[0].n);
}

async function getAdmin(q, id, { forUpdate = false } = {}) {
  const adminId = toId(id);
  if (adminId === null) return null;
  const rows = await q.query(`SELECT ${COLUMNS} FROM admin_users WHERE id = ?${forUpdate ? ' FOR UPDATE' : ''}`, [
    adminId,
  ]);
  return mapAdmin(rows[0]);
}

async function getAdminByEmail(q, email) {
  if (typeof email !== 'string' || email === '') return null;
  const rows = await q.query(`SELECT ${COLUMNS} FROM admin_users WHERE email = ?`, [email.toLowerCase()]);
  return mapAdmin(rows[0]);
}

async function listAdmins(q, { forUpdate = false } = {}) {
  const rows = await q.query(`SELECT ${COLUMNS} FROM admin_users ORDER BY email, id${forUpdate ? ' FOR UPDATE' : ''}`);
  return rows.map(mapAdmin);
}

async function createAdmin(q, { email, name, passwordHash, now }) {
  if (typeof email !== 'string' || email.trim() === '') throw new TypeError('admin email is required');
  if (typeof passwordHash !== 'string' || passwordHash === '') throw new TypeError('passwordHash is required');
  const res = await q.query(
    `INSERT INTO admin_users (email, name, password_hash, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?)`,
    [email.trim().toLowerCase(), name === null || name === undefined ? '' : String(name), passwordHash, now, now]
  );
  return Number(res.insertId);
}

// Updates only the whitelisted keys present in `fields`; returns affectedRows.
async function updateAdmin(q, id, fields, now) {
  if (!fields || typeof fields !== 'object') throw new TypeError('admin fields must be an object');
  const sets = [];
  const params = [];
  for (const key of Object.keys(fields)) {
    const value = fields[key];
    if (value === undefined) continue;
    const spec = Object.prototype.hasOwnProperty.call(FIELDS, key) ? FIELDS[key] : null;
    if (!spec) throw new Error(`unknown admin field: ${key}`);
    sets.push(`${spec.col} = ?`);
    params.push(convert(key, spec, value));
  }
  if (!sets.length) return 0;
  sets.push('updated_at = ?');
  params.push(now, toId(id));
  const res = await q.query(`UPDATE admin_users SET ${sets.join(', ')} WHERE id = ?`, params);
  return res.affectedRows;
}

// Returns the new epoch (LAST_INSERT_ID(expr) reports it in the OK packet, so no
// second query is needed), or null when the admin does not exist.
async function bumpSessionEpoch(q, id, now) {
  const res = await q.query(
    'UPDATE admin_users SET session_epoch = LAST_INSERT_ID(session_epoch + 1), updated_at = ? WHERE id = ?',
    [now, toId(id)]
  );
  if (res.affectedRows !== 1) return null;
  return Number(res.insertId);
}

// Atomically records a used TOTP step; false if this or a later step was already
// used (replay, or a concurrent login with the same code).
async function claimTotpStep(q, id, step, now) {
  const res = await q.query(
    `UPDATE admin_users SET totp_last_step = ?, updated_at = ?
     WHERE id = ? AND (totp_last_step IS NULL OR totp_last_step < ?)`,
    [Number(step), now, toId(id), Number(step)]
  );
  return res.affectedRows === 1;
}

// Master key rotation: replaces the ciphertext without touching updated_at.
async function setTotpSecretEnc(q, id, enc) {
  const res = await q.query('UPDATE admin_users SET totp_secret_enc = ? WHERE id = ?', [enc, toId(id)]);
  return res.affectedRows;
}

module.exports = {
  countAdmins,
  countEnabledAdmins,
  getAdmin,
  getAdminByEmail,
  listAdmins,
  createAdmin,
  updateAdmin,
  bumpSessionEpoch,
  claimTotpStep,
  setTotpSecretEnc,
};
