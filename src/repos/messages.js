'use strict';

// messages table: one row per send attempt (never bodies or attachments).
// insertMessage/completeMessage enforce these storage rules so a log
// row can always be written, whatever the request contained: address lists are
// bare addresses joined with ", " and cut to 65,000 bytes, counts are clamped to
// SMALLINT UNSIGNED, subject is cut to 255 characters, error/SMTP response are
// made single-line and cut to 1000 characters.

const { isDayString } = require('../lib/time');

const STATUSES = new Set(['sending', 'sent', 'failed', 'rejected', 'unknown']);
const SOURCES = new Set(['api', 'legacy', 'test']);
const FAILED_STATUSES = ['failed', 'rejected', 'unknown'];

const MAX_ADDR_BYTES = 65000;
const MAX_SMALLINT = 65535;
const MAX_UINT = 4294967295;

// C0 controls, DEL, NEL and the Unicode line/paragraph separators. Built from char
// codes so the source file never contains raw line terminators inside a regex.
const LINE_BREAKS_AND_CONTROLS = new RegExp(
  '[\\u0000-\\u001f\\u007f' + String.fromCharCode(0x85, 0x2028, 0x2029) + ']+',
  'g'
);

const COLUMNS = `m.id, m.public_id, m.app_id, m.api_key_id, m.source, m.client_message_id, m.status,
  m.day, m.created_at, m.completed_at, m.from_email, m.to_addrs, m.cc_addrs, m.bcc_addrs,
  m.recipient_count, m.subject, m.size_bytes, m.attachment_count, m.smtp_message_id,
  m.smtp_response, m.error, m.http_status, m.client_ip, m.duration_ms`;

function toId(v) {
  const n = typeof v === 'string' && /^\d+$/.test(v) ? Number(v) : v;
  return Number.isSafeInteger(n) && n > 0 ? n : null;
}

function clampInt(v, min, max) {
  const n = Number(v);
  if (!Number.isFinite(n)) return min;
  return Math.min(max, Math.max(min, Math.trunc(n)));
}

// Cuts to `max` code points (never splits a surrogate pair).
function truncateChars(s, max) {
  if (s.length <= max) return s;
  let out = '';
  let n = 0;
  for (const ch of s) {
    if (n === max) break;
    out += ch;
    n++;
  }
  return out;
}

// Cuts to at most `maxBytes` UTF-8 bytes on a character boundary.
function truncateBytes(s, maxBytes) {
  if (s.length * 3 <= maxBytes) return s;
  const buf = Buffer.from(s, 'utf8');
  if (buf.length <= maxBytes) return s;
  let end = maxBytes;
  while (end > 0 && (buf[end] & 0xc0) === 0x80) end--;
  return buf.subarray(0, end).toString('utf8');
}

function optText(v, max) {
  if (v === null || v === undefined) return null;
  return truncateChars(String(v), max);
}

function singleLine(v, max) {
  if (v === null || v === undefined) return null;
  const s = String(v).replace(LINE_BREAKS_AND_CONTROLS, ' ').trim();
  return truncateChars(s, max);
}

// Accepts a ready string, or an array of addresses / { address } objects.
function addressList(v) {
  if (v === null || v === undefined) return null;
  let s;
  if (Array.isArray(v)) {
    s = v
      .map((item) => (item && typeof item === 'object' ? item.address : item))
      .filter((a) => a !== null && a !== undefined && a !== '')
      .map(String)
      .join(', ');
  } else {
    s = String(v);
  }
  return s === '' ? null : truncateBytes(s, MAX_ADDR_BYTES);
}

function checkStatus(status) {
  if (!STATUSES.has(status)) throw new Error(`invalid message status: ${status}`);
  return status;
}

function checkDate(v, name) {
  if (!(v instanceof Date) || Number.isNaN(v.getTime())) throw new TypeError(`${name} must be a valid Date`);
  return v;
}

function mapMessage(r) {
  if (!r) return null;
  const m = {
    id: r.id,
    publicId: r.public_id,
    appId: r.app_id,
    apiKeyId: r.api_key_id,
    source: r.source,
    clientMessageId: r.client_message_id,
    status: r.status,
    day: r.day,
    createdAt: r.created_at,
    completedAt: r.completed_at,
    fromEmail: r.from_email,
    toAddrs: r.to_addrs,
    ccAddrs: r.cc_addrs,
    bccAddrs: r.bcc_addrs,
    recipientCount: r.recipient_count,
    subject: r.subject,
    sizeBytes: r.size_bytes,
    attachmentCount: r.attachment_count,
    smtpMessageId: r.smtp_message_id,
    smtpResponse: r.smtp_response,
    error: r.error,
    httpStatus: r.http_status,
    clientIp: r.client_ip,
    durationMs: r.duration_ms,
  };
  if (r.app_name !== undefined) m.appName = r.app_name;
  return m;
}

async function insertMessage(q, row) {
  if (!row || typeof row !== 'object') throw new TypeError('message row must be an object');
  if (typeof row.publicId !== 'string' || row.publicId === '') throw new TypeError('publicId is required');
  const appId = toId(row.appId);
  if (appId === null) throw new TypeError('appId is required');
  if (!SOURCES.has(row.source)) throw new Error(`invalid message source: ${row.source}`);
  if (!isDayString(row.day)) throw new TypeError('day must be a YYYY-MM-DD string');
  const res = await q.query(
    `INSERT INTO messages (public_id, app_id, api_key_id, source, client_message_id, status, day,
       created_at, from_email, to_addrs, cc_addrs, bcc_addrs, recipient_count, subject, size_bytes,
       attachment_count, error, http_status, client_ip)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      row.publicId,
      appId,
      toId(row.apiKeyId),
      row.source,
      optText(row.clientMessageId, 191),
      checkStatus(row.status),
      row.day,
      checkDate(row.createdAt, 'createdAt'),
      optText(row.fromEmail, 254),
      addressList(row.toAddrs),
      addressList(row.ccAddrs),
      addressList(row.bccAddrs),
      clampInt(row.recipientCount, 0, MAX_SMALLINT),
      optText(row.subject, 255),
      clampInt(row.sizeBytes, 0, MAX_UINT),
      clampInt(row.attachmentCount, 0, MAX_SMALLINT),
      singleLine(row.error, 1000),
      row.httpStatus === null || row.httpStatus === undefined ? null : clampInt(row.httpStatus, 0, MAX_SMALLINT),
      optText(row.clientIp, 45),
    ]
  );
  return Number(res.insertId);
}

// status and completedAt are required; the other columns are only written when
// the key is present, so completing never wipes what insertMessage stored.
async function completeMessage(q, id, fields) {
  const f = fields || {};
  const sets = ['status = ?', 'completed_at = ?'];
  const params = [checkStatus(f.status), checkDate(f.completedAt, 'completedAt')];
  const optional = [
    ['smtpMessageId', 'smtp_message_id', (v) => singleLine(v, 255)],
    ['smtpResponse', 'smtp_response', (v) => singleLine(v, 1000)],
    ['error', 'error', (v) => singleLine(v, 1000)],
    ['httpStatus', 'http_status', (v) => (v === null ? null : clampInt(v, 0, MAX_SMALLINT))],
    ['durationMs', 'duration_ms', (v) => (v === null ? null : clampInt(v, 0, MAX_UINT))],
  ];
  for (const [key, col, conv] of optional) {
    if (f[key] === undefined) continue;
    sets.push(`${col} = ?`);
    params.push(conv(f[key]));
  }
  params.push(toId(id));
  const res = await q.query(`UPDATE messages SET ${sets.join(', ')} WHERE id = ?`, params);
  return res.affectedRows;
}

async function deleteMessage(q, id) {
  const res = await q.query('DELETE FROM messages WHERE id = ?', [toId(id)]);
  return res.affectedRows;
}

async function getMessage(q, id) {
  const msgId = toId(id);
  if (msgId === null) return null;
  const rows = await q.query(
    `SELECT ${COLUMNS}, a.name AS app_name FROM messages m LEFT JOIN apps a ON a.id = m.app_id WHERE m.id = ?`,
    [msgId]
  );
  return mapMessage(rows[0]);
}

function escapeLike(s) {
  return s.replace(/[\\%_]/g, (c) => '\\' + c);
}

function present(v) {
  return v !== null && v !== undefined && v !== '';
}

async function searchMessages(q, { appId, status, fromDay, toDay, recipient, limit, offset } = {}) {
  const where = [];
  const params = [];
  if (present(appId)) {
    const id = toId(appId);
    if (id === null) return { rows: [], total: 0 };
    where.push('m.app_id = ?');
    params.push(id);
  }
  if (present(status) && status !== 'all') {
    if (status === 'failed') {
      where.push('m.status IN (?)');
      params.push(FAILED_STATUSES);
    } else {
      where.push('m.status = ?');
      params.push(String(status));
    }
  }
  if (present(fromDay)) {
    where.push('m.day >= ?');
    params.push(String(fromDay));
  }
  if (present(toDay)) {
    where.push('m.day <= ?');
    params.push(String(toDay));
  }
  if (present(recipient) && String(recipient).trim() !== '') {
    const pattern = '%' + escapeLike(String(recipient).trim()) + '%';
    where.push('(m.to_addrs LIKE ? OR m.cc_addrs LIKE ? OR m.bcc_addrs LIKE ?)');
    params.push(pattern, pattern, pattern);
  }
  const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';
  const lim = clampInt(present(limit) ? limit : 50, 1, 1000);
  const off = clampInt(present(offset) ? offset : 0, 0, Number.MAX_SAFE_INTEGER);

  const countRows = await q.query(`SELECT COUNT(*) AS n FROM messages m ${whereSql}`, params);
  const rows = await q.query(
    `SELECT ${COLUMNS}, a.name AS app_name
     FROM messages m LEFT JOIN apps a ON a.id = m.app_id
     ${whereSql}
     ORDER BY m.id DESC LIMIT ? OFFSET ?`,
    [...params, lim, off]
  );
  return { rows: rows.map(mapMessage), total: Number(countRows[0].n) };
}

// Map(appId -> { sent, failed }) where failed = failed + rejected + unknown.
async function countsForDay(q, day) {
  const rows = await q.query(
    `SELECT app_id, SUM(status = 'sent') AS sent, SUM(status IN ('failed', 'rejected', 'unknown')) AS failed
     FROM messages WHERE day = ? GROUP BY app_id`,
    [day]
  );
  const out = new Map();
  for (const r of rows) out.set(r.app_id, { sent: Number(r.sent) || 0, failed: Number(r.failed) || 0 });
  return out;
}

async function statsByDay(q, { fromDay, toDay, appId } = {}) {
  const where = ["m.status <> 'sending'"];
  const params = [];
  if (present(fromDay)) {
    where.push('m.day >= ?');
    params.push(String(fromDay));
  }
  if (present(toDay)) {
    where.push('m.day <= ?');
    params.push(String(toDay));
  }
  if (present(appId)) {
    const id = toId(appId);
    if (id === null) return [];
    where.push('m.app_id = ?');
    params.push(id);
  }
  const rows = await q.query(
    `SELECT m.day, m.app_id, a.name AS app_name,
       SUM(m.status = 'sent') AS sent, SUM(m.status = 'failed') AS failed,
       SUM(m.status = 'rejected') AS rejected, SUM(m.status = 'unknown') AS unknown_count
     FROM messages m LEFT JOIN apps a ON a.id = m.app_id
     WHERE ${where.join(' AND ')}
     GROUP BY m.day, m.app_id, a.name
     ORDER BY m.day DESC, a.name, m.app_id`,
    params
  );
  return rows.map((r) => ({
    day: r.day,
    appId: r.app_id,
    appName: r.app_name,
    sent: Number(r.sent) || 0,
    failed: Number(r.failed) || 0,
    rejected: Number(r.rejected) || 0,
    unknown: Number(r.unknown_count) || 0,
  }));
}

// A row still 'sending' long after the SMTP deadline belongs to a process that
// died mid-send; nobody knows whether the mail went out.
async function markStaleSending(q, olderThan, now) {
  const res = await q.query(
    `UPDATE messages SET status = 'unknown', error = 'interrupted: outcome unknown', completed_at = ?
     WHERE status = 'sending' AND created_at < ?`,
    [checkDate(now, 'now'), checkDate(olderThan, 'olderThan')]
  );
  return res.affectedRows;
}

// Deletes one batch; callers loop until it returns less than batchSize.
async function deleteMessagesBefore(q, cutoff, batchSize = 5000) {
  const res = await q.query('DELETE FROM messages WHERE created_at < ? ORDER BY created_at, id LIMIT ?', [
    checkDate(cutoff, 'cutoff'),
    clampInt(batchSize, 1, 100000),
  ]);
  return res.affectedRows;
}

module.exports = {
  insertMessage,
  completeMessage,
  deleteMessage,
  getMessage,
  searchMessages,
  countsForDay,
  statsByDay,
  markStaleSending,
  deleteMessagesBefore,
  STATUSES,
  FAILED_STATUSES,
};
