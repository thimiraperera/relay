'use strict';

// apps table. Writes are built only from the fixed FIELDS map below: the
// camelCase key picks a fixed column name and a value converter, so caller
// supplied keys never reach the SQL text. Unknown keys are a programming error
// and throw (a silently dropped setting is worse than a loud failure).

const COLUMNS = `id, name, notes, enabled, legacy_signing, smtp_host, smtp_port, smtp_encryption,
  smtp_username, smtp_password_enc, from_email, from_name, allowed_from, reply_to_default,
  limit_per_minute, limit_per_day, max_message_bytes, max_recipients, ip_allowlist,
  last_used_at, created_at, updated_at`;

// type: text (NOT NULL, null rejected), textOrEmpty (NOT NULL, null stored as ''),
// nullableText, uint (NOT NULL unsigned integer), bool, jsonArray (NULL or JSON array).
const FIELDS = Object.freeze({
  name: { col: 'name', type: 'text' },
  notes: { col: 'notes', type: 'nullableText' },
  enabled: { col: 'enabled', type: 'bool' },
  legacySigning: { col: 'legacy_signing', type: 'bool' },
  smtpHost: { col: 'smtp_host', type: 'text' },
  smtpPort: { col: 'smtp_port', type: 'uint' },
  smtpEncryption: { col: 'smtp_encryption', type: 'text' },
  smtpUsername: { col: 'smtp_username', type: 'textOrEmpty' },
  smtpPasswordEnc: { col: 'smtp_password_enc', type: 'nullableText' },
  fromEmail: { col: 'from_email', type: 'text' },
  fromName: { col: 'from_name', type: 'textOrEmpty' },
  allowedFrom: { col: 'allowed_from', type: 'jsonArray' },
  replyToDefault: { col: 'reply_to_default', type: 'nullableText' },
  limitPerMinute: { col: 'limit_per_minute', type: 'uint' },
  limitPerDay: { col: 'limit_per_day', type: 'uint' },
  maxMessageBytes: { col: 'max_message_bytes', type: 'uint' },
  maxRecipients: { col: 'max_recipients', type: 'uint' },
  ipAllowlist: { col: 'ip_allowlist', type: 'jsonArray' },
});

const REQUIRED_ON_CREATE = ['name', 'smtpHost', 'smtpPort', 'smtpEncryption', 'fromEmail'];

function toId(v) {
  const n = typeof v === 'string' && /^\d+$/.test(v) ? Number(v) : v;
  return Number.isSafeInteger(n) && n > 0 ? n : null;
}

function toBool(v) {
  if (typeof v === 'string') return ['1', 'true', 'on', 'yes'].includes(v.toLowerCase());
  return Boolean(v);
}

function parseJsonArray(text) {
  if (text === null || text === undefined || text === '') return [];
  try {
    const v = JSON.parse(text);
    return Array.isArray(v) ? v : [];
  } catch {
    return [];
  }
}

function convert(key, spec, value) {
  switch (spec.type) {
    case 'text':
      if (value === null) throw new TypeError(`app field ${key} cannot be null`);
      return String(value);
    case 'textOrEmpty':
      return value === null ? '' : String(value);
    case 'nullableText':
      return value === null ? null : String(value);
    case 'uint': {
      const n = typeof value === 'string' && value.trim() !== '' ? Number(value) : value;
      if (!Number.isSafeInteger(n) || n < 0) throw new TypeError(`app field ${key} must be a non-negative integer`);
      return n;
    }
    case 'bool':
      return toBool(value) ? 1 : 0;
    case 'jsonArray':
      if (value === null) return null;
      if (!Array.isArray(value)) throw new TypeError(`app field ${key} must be an array`);
      return JSON.stringify(value);
    default:
      throw new Error(`unhandled field type ${spec.type}`);
  }
}

// Returns [[column, value], ...] for the keys present (undefined = absent).
function toColumns(fields) {
  if (!fields || typeof fields !== 'object') throw new TypeError('app fields must be an object');
  const out = [];
  for (const key of Object.keys(fields)) {
    const value = fields[key];
    if (value === undefined) continue;
    const spec = Object.prototype.hasOwnProperty.call(FIELDS, key) ? FIELDS[key] : null;
    if (!spec) throw new Error(`unknown app field: ${key}`);
    out.push([spec.col, convert(key, spec, value)]);
  }
  return out;
}

function mapApp(r) {
  if (!r) return null;
  return {
    id: r.id,
    name: r.name,
    notes: r.notes,
    enabled: Boolean(r.enabled),
    legacySigning: Boolean(r.legacy_signing),
    smtpHost: r.smtp_host,
    smtpPort: r.smtp_port,
    smtpEncryption: r.smtp_encryption,
    smtpUsername: r.smtp_username,
    smtpPasswordEnc: r.smtp_password_enc,
    hasSmtpPassword: Boolean(r.smtp_password_enc),
    fromEmail: r.from_email,
    fromName: r.from_name,
    allowedFrom: parseJsonArray(r.allowed_from),
    replyToDefault: r.reply_to_default,
    limitPerMinute: r.limit_per_minute,
    limitPerDay: r.limit_per_day,
    maxMessageBytes: r.max_message_bytes,
    maxRecipients: r.max_recipients,
    ipAllowlist: parseJsonArray(r.ip_allowlist),
    lastUsedAt: r.last_used_at,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  };
}

async function listApps(q, { forUpdate = false } = {}) {
  const rows = await q.query(`SELECT ${COLUMNS} FROM apps ORDER BY name, id${forUpdate ? ' FOR UPDATE' : ''}`);
  return rows.map(mapApp);
}

async function getApp(q, id, { forUpdate = false } = {}) {
  const appId = toId(id);
  if (appId === null) return null;
  const rows = await q.query(`SELECT ${COLUMNS} FROM apps WHERE id = ?${forUpdate ? ' FOR UPDATE' : ''}`, [appId]);
  return mapApp(rows[0]);
}

async function createApp(q, fields, now) {
  const cols = toColumns(fields);
  const present = new Set(cols.map(([c]) => c));
  const missing = REQUIRED_ON_CREATE.filter((k) => !present.has(FIELDS[k].col));
  if (missing.length) throw new Error(`createApp: missing required field(s): ${missing.join(', ')}`);
  cols.push(['created_at', now], ['updated_at', now]);
  const sql = `INSERT INTO apps (${cols.map(([c]) => c).join(', ')}) VALUES (${cols.map(() => '?').join(', ')})`;
  const res = await q.query(sql, cols.map(([, v]) => v));
  return Number(res.insertId);
}

// Updates only the keys present in `fields`; returns affectedRows (0 if none given).
async function updateApp(q, id, fields, now) {
  const appId = toId(id);
  if (appId === null) return 0;
  const cols = toColumns(fields);
  if (!cols.length) return 0;
  cols.push(['updated_at', now]);
  const sql = `UPDATE apps SET ${cols.map(([c]) => `${c} = ?`).join(', ')} WHERE id = ?`;
  const res = await q.query(sql, [...cols.map(([, v]) => v), appId]);
  return res.affectedRows;
}

// Monotonic: concurrent requests never move last_used_at backwards.
async function touchAppLastUsed(q, id, now) {
  const appId = toId(id);
  if (appId === null) return 0;
  const res = await q.query(
    'UPDATE apps SET last_used_at = ? WHERE id = ? AND (last_used_at IS NULL OR last_used_at < ?)',
    [now, appId, now]
  );
  return res.affectedRows;
}

// Used by master key rotation: replaces the ciphertext only, without touching
// updated_at (re-encryption is not a settings change).
async function setAppSmtpPasswordEnc(q, id, enc) {
  const res = await q.query('UPDATE apps SET smtp_password_enc = ? WHERE id = ?', [enc, toId(id)]);
  return res.affectedRows;
}

module.exports = {
  listApps,
  getApp,
  createApp,
  updateApp,
  touchAppLastUsed,
  setAppSmtpPasswordEnc,
  APP_FIELDS: Object.keys(FIELDS),
};
