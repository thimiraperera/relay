'use strict';

// audit_log table. `details` is stored as JSON text; oversized details are
// replaced by { truncated: true } rather than failing the audited operation.

const MAX_DETAILS_BYTES = 60000;

function clampInt(v, min, max, def) {
  const n = Number(v);
  if (v === null || v === undefined || v === '' || !Number.isFinite(n)) return def;
  return Math.min(max, Math.max(min, Math.trunc(n)));
}

function optText(v, max) {
  if (v === null || v === undefined) return null;
  const s = String(v);
  return s.length > max ? s.slice(0, max) : s;
}

function serializeDetails(details) {
  if (details === null || details === undefined) return null;
  let json;
  try {
    json = JSON.stringify(details);
  } catch {
    json = JSON.stringify({ unserializable: true });
  }
  if (json === undefined) return null;
  if (Buffer.byteLength(json, 'utf8') > MAX_DETAILS_BYTES) return JSON.stringify({ truncated: true });
  return json;
}

function parseDetails(text) {
  if (text === null || text === undefined || text === '') return {};
  try {
    const v = JSON.parse(text);
    return v !== null && typeof v === 'object' ? v : {};
  } catch {
    return {};
  }
}

function mapAudit(r) {
  return {
    id: r.id,
    createdAt: r.created_at,
    adminUserId: r.admin_user_id,
    adminEmail: r.admin_email,
    action: r.action,
    targetType: r.target_type,
    targetId: r.target_id,
    details: parseDetails(r.details),
    ip: r.ip,
  };
}

async function insertAudit(q, { createdAt, adminUserId, adminEmail, action, targetType, targetId, details, ip }) {
  if (typeof action !== 'string' || action === '') throw new TypeError('audit action is required');
  const res = await q.query(
    `INSERT INTO audit_log (created_at, admin_user_id, admin_email, action, target_type, target_id, details, ip)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      createdAt,
      adminUserId === null || adminUserId === undefined ? null : Number(adminUserId),
      optText(adminEmail, 191),
      optText(action, 64),
      optText(targetType, 32),
      optText(targetId, 64),
      serializeDetails(details),
      optText(ip, 45),
    ]
  );
  return Number(res.insertId);
}

async function listAudit(q, { targetType, targetId, limit, offset } = {}) {
  const where = [];
  const params = [];
  if (targetType !== null && targetType !== undefined && targetType !== '') {
    where.push('target_type = ?');
    params.push(String(targetType));
  }
  if (targetId !== null && targetId !== undefined && targetId !== '') {
    where.push('target_id = ?');
    params.push(String(targetId));
  }
  const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';
  const lim = clampInt(limit, 1, 1000, 50);
  const off = clampInt(offset, 0, Number.MAX_SAFE_INTEGER, 0);
  const countRows = await q.query(`SELECT COUNT(*) AS n FROM audit_log ${whereSql}`, params);
  const rows = await q.query(
    `SELECT id, created_at, admin_user_id, admin_email, action, target_type, target_id, details, ip
     FROM audit_log ${whereSql} ORDER BY id DESC LIMIT ? OFFSET ?`,
    [...params, lim, off]
  );
  return { rows: rows.map(mapAudit), total: Number(countRows[0].n) };
}

module.exports = { insertAudit, listAudit };
