'use strict';

// Audit trail for every configuration change and security event. Callers pass
// the actor ({ id, email, ip }) and `now` from deps.clock; details must never
// contain secrets (diffFields masks anything that looks like one).

const { insertAudit } = require('../repos/audit');

const SYSTEM_ACTOR = Object.freeze({ id: null, email: 'system', ip: null });

const SENSITIVE_FIELD = /password|secret|key|token/i;
const MAX_STRING = 200;

async function recordAudit(q, actor, action, { targetType, targetId, details } = {}, now) {
  if (!(now instanceof Date) || Number.isNaN(now.getTime())) {
    throw new TypeError('recordAudit: now must be a valid Date');
  }
  const a = actor || {};
  return insertAudit(q, {
    createdAt: now,
    adminUserId: a.id === undefined ? null : a.id,
    adminEmail: a.email === undefined ? null : a.email,
    action,
    targetType: targetType === undefined ? null : targetType,
    targetId: targetId === null || targetId === undefined ? null : String(targetId),
    details: details === undefined ? null : details,
    ip: a.ip === undefined ? null : a.ip,
  });
}

// Primitives compare by their text so a form value '25' equals a stored 25;
// arrays/objects compare by JSON.
function comparable(v) {
  if (v === null || v === undefined) return 'null';
  if (v instanceof Date) return `date:${v.getTime()}`;
  if (typeof v === 'object') return `json:${JSON.stringify(v)}`;
  return `p:${String(v)}`;
}

function display(v) {
  if (typeof v === 'string' && v.length > MAX_STRING) return v.slice(0, MAX_STRING) + '…';
  return v === undefined ? null : v;
}

// { field: { from, to } } for the fields whose value differs. A field missing
// from `after` (undefined) is not part of the change and is skipped. Sensitive
// fields only record that they changed: { field: '[changed]' }.
function diffFields(before, after, fields) {
  const b = before || {};
  const a = after || {};
  const out = {};
  for (const field of fields) {
    if (a[field] === undefined) continue;
    const from = b[field] === undefined ? null : b[field];
    const to = a[field];
    if (comparable(from) === comparable(to)) continue;
    out[field] = SENSITIVE_FIELD.test(field) ? '[changed]' : { from: display(from), to: display(to) };
  }
  return out;
}

module.exports = { recordAudit, diffFields, SYSTEM_ACTOR };
