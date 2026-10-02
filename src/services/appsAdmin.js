'use strict';

// App settings as the admin UI edits them: form validation, create/update with
// audit records, and the small helpers the app pages need. Form field names are
// the snake_case column names; `values` use the camelCase names of repos/apps.

const net = require('node:net');
const appsRepo = require('../repos/apps');
const { recordAudit, diffFields } = require('./audit');
const { revokeAllKeys } = require('./keys');
const { encryptSmtpPassword, smtpContext } = require('../lib/secrets');
const { isValidEmail } = require('../lib/addresses');
const { stripCrlf } = require('../lib/headers');
const { parseAllowlist } = require('../lib/ipAllow');
const { notFound, conflict } = require('../lib/errors');

const MIB = 1024 * 1024;
const ENCRYPTIONS = ['ssl', 'starttls', 'none'];
const MAX_ALLOWED_FROM = 20;
const MAX_IP_ENTRIES = 50;
const HOST_LABEL = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;
const CONTROL_CHARS = new RegExp('[\\x00-\\x1F\\x7F]');

// Every app setting the form edits, in form order (the SMTP password is separate).
const SETTINGS_FIELDS = Object.freeze([
  'name',
  'notes',
  'enabled',
  'legacySigning',
  'smtpHost',
  'smtpPort',
  'smtpEncryption',
  'smtpUsername',
  'fromEmail',
  'fromName',
  'allowedFrom',
  'replyToDefault',
  'limitPerMinute',
  'limitPerDay',
  'maxMessageBytes',
  'maxRecipients',
  'ipAllowlist',
]);

// Enabled/disabled has its own audit actions, so app.update leaves it out.
const UPDATE_DIFF_FIELDS = SETTINGS_FIELDS.filter((f) => f !== 'enabled');

// urlencoded bodies (extended: false) and Express 5 query strings give
// string | string[]; a repeated field takes its last value.
function field(source, name) {
  const v = source ? source[name] : undefined;
  const s = Array.isArray(v) ? v[v.length - 1] : v;
  return typeof s === 'string' ? s : '';
}

// Route/query ids: a positive integer within INT UNSIGNED, else null.
function parseId(v) {
  if (typeof v !== 'string' || !/^[1-9]\d{0,9}$/.test(v)) return null;
  const n = Number(v);
  return n <= 4294967295 ? n : null;
}

const MAX_PAGE = 100000;

function parsePage(v) {
  const s = typeof v === 'string' ? v.trim() : '';
  if (!/^\d{1,6}$/.test(s)) return 1;
  return Math.min(MAX_PAGE, Math.max(1, Number(s)));
}

function checked(body, name) {
  const v = field(body, name).toLowerCase();
  return v === '1' || v === 'on' || v === 'true' || v === 'yes';
}

// Length in characters as MySQL counts them (code points, not UTF-16 units).
function charLength(s) {
  let n = 0;
  for (const _ of s) n++;
  return n;
}

function parseIntInRange(raw, min, max) {
  const s = raw.trim();
  if (!/^\d{1,10}$/.test(s)) return null;
  const n = Number(s);
  return n >= min && n <= max ? n : null;
}

// Host name (letters, digits, hyphens; dot-separated labels) or an IP address.
// Returns the lowercased host, or null.
function normalizeHost(raw) {
  let h = raw.trim();
  if (h.startsWith('[') && h.endsWith(']')) h = h.slice(1, -1);
  if (h === '' || h.includes('%')) return null;
  if (net.isIP(h)) return h.toLowerCase();
  if (h.length > 253) return null;
  const labels = h.split('.');
  if (!labels.every((label) => HOST_LABEL.test(label))) return null;
  // An all-digit last label is a mistyped IPv4 address, not a host name.
  if (/^\d+$/.test(labels[labels.length - 1])) return null;
  return h.toLowerCase();
}

function splitList(raw) {
  return raw
    .split(/[\r\n,]+/)
    .map((s) => s.trim())
    .filter((s) => s !== '');
}

// Shown and parsed with up to 6 decimals, which round-trips any whole byte count
// that came from the form.
function formatMb(bytes) {
  const n = Number(bytes);
  if (!Number.isFinite(n)) return '';
  return String(Number((n / MIB).toFixed(6)));
}

// The form's size bounds as displayed: 0.1 MB (or the relay limit if lower) to
// the relay-wide MAX_MESSAGE_BYTES.
function messageSizeLimitsMb(config) {
  return {
    minMb: formatMb(Math.min(0.1 * MIB, config.maxMessageBytes)),
    maxMb: formatMb(config.maxMessageBytes),
  };
}

// Returns { values, errors, form }: `values` are ready for createAppFromInput /
// updateAppFromInput (valid only when `errors` is empty), `errors` maps form
// field names to messages, and `form` echoes what was entered (never the
// password) so the page can be shown again with the errors.
//
// `options.isCreate` is accepted for the callers' clarity only: create and update
// validate the same fields. A blank password means "none yet" on create and
// "keep the stored one" on update; both are `smtpPassword: null` here.
function validateAppInput(body, config, options = {}) {
  const errors = {};
  const values = {};
  const form = {
    name: field(body, 'name'),
    notes: field(body, 'notes'),
    enabled: checked(body, 'enabled'),
    legacy_signing: checked(body, 'legacy_signing'),
    smtp_host: field(body, 'smtp_host'),
    smtp_port: field(body, 'smtp_port'),
    smtp_encryption: field(body, 'smtp_encryption'),
    smtp_username: field(body, 'smtp_username'),
    from_email: field(body, 'from_email'),
    from_name: field(body, 'from_name'),
    allowed_from: field(body, 'allowed_from'),
    reply_to_default: field(body, 'reply_to_default'),
    limit_per_minute: field(body, 'limit_per_minute'),
    limit_per_day: field(body, 'limit_per_day'),
    max_message_mb: field(body, 'max_message_mb'),
    max_recipients: field(body, 'max_recipients'),
    ip_allowlist: field(body, 'ip_allowlist'),
  };

  const name = stripCrlf(form.name);
  if (name === '') errors.name = 'Name is required.';
  else if (charLength(name) > 150) errors.name = 'Name must be at most 150 characters.';
  values.name = name;

  const notes = form.notes.trim();
  if (charLength(notes) > 2000) errors.notes = 'Notes must be at most 2000 characters.';
  values.notes = notes === '' ? null : notes;

  values.enabled = form.enabled;
  values.legacySigning = form.legacy_signing;

  if (form.smtp_host.trim() === '') errors.smtp_host = 'SMTP host is required.';
  else {
    const host = normalizeHost(form.smtp_host);
    if (!host) errors.smtp_host = 'Enter a host name such as mail.example.com, or an IP address.';
    else values.smtpHost = host;
  }

  const port = parseIntInRange(form.smtp_port, 1, 65535);
  if (port === null) errors.smtp_port = 'Port must be a whole number from 1 to 65535.';
  else values.smtpPort = port;

  if (!ENCRYPTIONS.includes(form.smtp_encryption)) errors.smtp_encryption = 'Choose SSL, STARTTLS or none.';
  else values.smtpEncryption = form.smtp_encryption;

  const username = form.smtp_username.trim();
  if (charLength(username) > 255) errors.smtp_username = 'Username must be at most 255 characters.';
  else if (CONTROL_CHARS.test(username)) errors.smtp_username = 'Username must not contain control characters.';
  values.smtpUsername = username;

  // Taken exactly as typed: spaces can be part of a password.
  const password = field(body, 'smtp_password');
  if (charLength(password) > 500) errors.smtp_password = 'Password must be at most 500 characters.';
  values.smtpPassword = password === '' ? null : password;

  const fromEmail = form.from_email.trim();
  if (fromEmail === '') errors.from_email = 'From address is required.';
  else if (!isValidEmail(fromEmail)) errors.from_email = 'Enter a valid email address.';
  values.fromEmail = fromEmail;

  const fromName = stripCrlf(form.from_name);
  if (charLength(fromName) > 150) errors.from_name = 'From name must be at most 150 characters.';
  values.fromName = fromName;

  const allowed = [];
  const seen = new Set();
  const badAllowed = [];
  for (const entry of splitList(form.allowed_from)) {
    if (!isValidEmail(entry)) {
      badAllowed.push(entry);
      continue;
    }
    const lower = entry.toLowerCase();
    if (!seen.has(lower)) {
      seen.add(lower);
      allowed.push(entry);
    }
  }
  if (badAllowed.length) {
    errors.allowed_from = `Not a valid email address: ${badAllowed.slice(0, 3).map((s) => `"${s.slice(0, 60)}"`).join(', ')}${badAllowed.length > 3 ? ' …' : ''}`;
  } else if (allowed.length > MAX_ALLOWED_FROM) {
    errors.allowed_from = `At most ${MAX_ALLOWED_FROM} addresses.`;
  }
  values.allowedFrom = allowed;

  const replyTo = form.reply_to_default.trim();
  if (replyTo !== '' && !isValidEmail(replyTo)) {
    errors.reply_to_default = 'Enter a valid email address, or leave it empty.';
  }
  values.replyToDefault = replyTo === '' ? null : replyTo;

  const perMinute = parseIntInRange(form.limit_per_minute, 1, 10000);
  if (perMinute === null) errors.limit_per_minute = 'Enter a whole number from 1 to 10000.';
  else values.limitPerMinute = perMinute;

  const perDay = parseIntInRange(form.limit_per_day, 1, 1000000);
  if (perDay === null) errors.limit_per_day = 'Enter a whole number from 1 to 1000000.';
  else values.limitPerDay = perDay;

  const mbText = form.max_message_mb.trim();
  const mb = /^\d{1,6}(\.\d{1,6})?$/.test(mbText) ? Number(mbText) : NaN;
  // Compared with the bounds as displayed (6 decimals), then clamped in bytes, so
  // typing the maximum shown always works.
  const { minMb, maxMb } = messageSizeLimitsMb(config);
  if (!(mb >= Number(minMb) && mb <= Number(maxMb))) {
    errors.max_message_mb = `Enter a size in MB from ${minMb} to ${maxMb}.`;
  } else {
    values.maxMessageBytes = Math.min(config.maxMessageBytes, Math.max(1, Math.round(mb * MIB)));
  }

  const maxRecipients = parseIntInRange(form.max_recipients, 1, 1000);
  if (maxRecipients === null) errors.max_recipients = 'Enter a whole number from 1 to 1000.';
  else values.maxRecipients = maxRecipients;

  const allow = parseAllowlist(form.ip_allowlist);
  if (allow.errors.length) {
    errors.ip_allowlist = allow.errors.slice(0, 3).join('; ') + (allow.errors.length > 3 ? ' …' : '');
  } else if (allow.entries.length > MAX_IP_ENTRIES) {
    errors.ip_allowlist = `At most ${MAX_IP_ENTRIES} entries.`;
  }
  values.ipAllowlist = allow.entries;

  return { values, errors, form };
}

function settingsOf(values) {
  const out = {};
  for (const f of SETTINGS_FIELDS) {
    if (values[f] !== undefined) out[f] = values[f];
  }
  return out;
}

// "SMTP server changed" means exactly "the stored password's encryption context
// (secrets.smtpContext: host lowercased, port, encryption, username) no longer
// matches", so the two can never drift apart: a password that could not be
// decrypted after the save is always cleared (docs/SPEC.md decision 7). `after` carries
// the same id as `before`.
function smtpServerChanged(before, after) {
  return smtpContext(before) !== smtpContext(after);
}

const STALE_SETTINGS = 'settings changed since you loaded this page; reload and try again';

// The settings form's version token: apps.updated_at as an ISO string ('' when
// missing). Only a settings save writes updated_at, and updateAppFromInput always
// moves it forward (see nextUpdatedAt), so an equal token means the row still
// holds the settings the form was rendered from.
function settingsVersion(app) {
  const v = app ? app.updatedAt : null;
  if (v === null || v === undefined || v === '') return '';
  const d = v instanceof Date ? v : new Date(v);
  return Number.isNaN(d.getTime()) ? '' : d.toISOString();
}

// updated_at for a settings save: `now` in whole seconds (the DATETIME column's
// precision), but at least one second after the stored value, so two saves in
// the same second (or with a clock that stands still) still get different
// version tokens.
function nextUpdatedAt(previous, now) {
  const nowMs = Math.floor(now.getTime() / 1000) * 1000;
  const prev = previous instanceof Date ? previous.getTime() : new Date(previous).getTime();
  if (previous === null || previous === undefined || !Number.isFinite(prev)) return new Date(nowMs);
  return new Date(Math.max(nowMs, Math.floor(prev / 1000) * 1000 + 1000));
}

// Creates the app (and stores its SMTP password, if one was entered) in one
// transaction and audits app.create. Returns the new app id.
async function createAppFromInput(deps, values, actor) {
  const now = deps.clock.now();
  const settings = settingsOf(values);
  return deps.db.transaction(async (tx) => {
    const id = await appsRepo.createApp(tx, settings, now);
    const hasPassword = typeof values.smtpPassword === 'string' && values.smtpPassword !== '';
    if (hasPassword) {
      // The ciphertext is bound to the app id, so it can only be written after the insert.
      const smtpPasswordEnc = encryptSmtpPassword(deps.config, { id, ...settings }, values.smtpPassword);
      await appsRepo.updateApp(tx, id, { smtpPasswordEnc }, now);
    }
    const details = {};
    for (const [k, d] of Object.entries(diffFields({}, settings, SETTINGS_FIELDS))) {
      details[k] = d && typeof d === 'object' ? d.to : d;
    }
    details.smtpPassword = hasPassword ? '[set]' : '[not set]';
    await recordAudit(tx, actor, 'app.create', { targetType: 'app', targetId: id, details }, now);
    return id;
  });
}

// Applies the validated form to an existing app. Returns { legacyChanged,
// passwordCleared, passwordChanged, changed }.
//
// `options.expectedUpdatedAt` is the form's version token (settingsVersion of the
// row it was rendered from). When given, it must match the locked row, or the
// save is refused with 409 before anything is written: a form loaded before
// someone else's save would otherwise write the old values back (and, through
// an old host or username, clear a password set meanwhile). An empty token is
// refused too. The admin route always passes it; leaving it out (undefined)
// skips the check for callers that are not a form.
async function updateAppFromInput(deps, id, values, actor, options = {}) {
  const now = deps.clock.now();
  const { expectedUpdatedAt } = options || {};
  return deps.db.transaction(async (tx) => {
    const before = await appsRepo.getApp(tx, id, { forUpdate: true });
    if (!before) throw notFound('app not found');
    if (expectedUpdatedAt !== undefined) {
      const expected = typeof expectedUpdatedAt === 'string' ? expectedUpdatedAt.trim() : '';
      if (expected === '' || expected !== settingsVersion(before)) throw conflict(STALE_SETTINGS);
    }

    const after = settingsOf(values);
    // The form shows the size in MB; re-saving the displayed value must not
    // nudge a byte count that was set some other way.
    if (after.maxMessageBytes !== undefined && formatMb(after.maxMessageBytes) === formatMb(before.maxMessageBytes)) {
      after.maxMessageBytes = before.maxMessageBytes;
    }

    const diff = diffFields(before, after, UPDATE_DIFF_FIELDS);
    const changes = {};
    for (const f of Object.keys(diff)) changes[f] = after[f];

    const enabledChanged = after.enabled !== undefined && Boolean(after.enabled) !== before.enabled;
    if (enabledChanged) changes.enabled = Boolean(after.enabled);
    const legacyChanged = after.legacySigning !== undefined && Boolean(after.legacySigning) !== before.legacySigning;

    const merged = { ...before, ...after, id: before.id };
    const serverChanged = smtpServerChanged(before, merged);
    const newPassword = typeof values.smtpPassword === 'string' && values.smtpPassword !== '' ? values.smtpPassword : null;
    let passwordCleared = false;
    let passwordChanged = false;

    if (newPassword !== null) {
      // Encrypted for the settings being saved: the context includes host, port,
      // encryption and username.
      changes.smtpPasswordEnc = encryptSmtpPassword(deps.config, merged, newPassword);
      passwordChanged = true;
      if (serverChanged) diff.smtpPassword = '[changed]';
    } else if (serverChanged && before.smtpPasswordEnc) {
      // A password typed for one server is never sent to another (docs/SPEC.md decision 7).
      changes.smtpPasswordEnc = null;
      passwordCleared = true;
      diff.smtpPassword = '[cleared]';
    }

    if (Object.keys(changes).length) {
      await appsRepo.updateApp(tx, before.id, changes, nextUpdatedAt(before.updatedAt, now));
    }

    if (Object.keys(diff).length) {
      await recordAudit(tx, actor, 'app.update', { targetType: 'app', targetId: before.id, details: diff }, now);
    }
    if (passwordChanged && !serverChanged) {
      await recordAudit(
        tx,
        actor,
        'app.smtp_password_change',
        { targetType: 'app', targetId: before.id, details: { smtpPassword: '[changed]' } },
        now
      );
    }
    if (enabledChanged) {
      await recordAudit(tx, actor, after.enabled ? 'app.enable' : 'app.disable', { targetType: 'app', targetId: before.id }, now);
    }
    if (legacyChanged) {
      // Keys are hashed for /v1/send and encrypted for /send.php; neither kind
      // works for the other endpoint, so every key of the app is revoked.
      await revokeAllKeys(deps, tx, {
        appId: before.id,
        actor,
        reason: after.legacySigning ? 'legacy signing enabled' : 'legacy signing disabled',
      });
    }

    const changed = Object.keys(diff).length > 0 || enabledChanged || passwordChanged;
    return { legacyChanged, passwordCleared, passwordChanged, changed };
  });
}

// Form values for an existing app (the password is never part of the form).
function appToForm(app) {
  return {
    name: app.name || '',
    notes: app.notes || '',
    enabled: Boolean(app.enabled),
    legacy_signing: Boolean(app.legacySigning),
    smtp_host: app.smtpHost || '',
    smtp_port: app.smtpPort === null || app.smtpPort === undefined ? '' : String(app.smtpPort),
    smtp_encryption: app.smtpEncryption || '',
    smtp_username: app.smtpUsername || '',
    from_email: app.fromEmail || '',
    from_name: app.fromName || '',
    allowed_from: (app.allowedFrom || []).join('\n'),
    reply_to_default: app.replyToDefault || '',
    limit_per_minute: String(app.limitPerMinute),
    limit_per_day: String(app.limitPerDay),
    max_message_mb: formatMb(app.maxMessageBytes),
    max_recipients: String(app.maxRecipients),
    ip_allowlist: (app.ipAllowlist || []).join('\n'),
  };
}

// Form values for a new app (the column defaults of migrations/001_initial.sql,
// capped by the relay-wide limits).
function defaultForm(config) {
  return {
    name: '',
    notes: '',
    enabled: true,
    legacy_signing: false,
    smtp_host: '',
    smtp_port: '465',
    smtp_encryption: 'ssl',
    smtp_username: '',
    from_email: '',
    from_name: '',
    allowed_from: '',
    reply_to_default: '',
    limit_per_minute: '30',
    limit_per_day: '1000',
    max_message_mb: formatMb(Math.min(config.maxMessageBytes, 10 * MIB)),
    max_recipients: String(config.defaultMaxRecipients),
    ip_allowlist: '',
  };
}

// 'active' | 'grace' | 'revoked' | 'expired' at `now`. A key is valid while it is
// not revoked and its expiry (if any) is in the future; only a key without an
// expiry is the app's active key.
function keyStatus(key, now) {
  if (key.revokedAt) return 'revoked';
  if (key.expiresAt) {
    const t = key.expiresAt instanceof Date ? key.expiresAt.getTime() : new Date(key.expiresAt).getTime();
    return t > now.getTime() ? 'grace' : 'expired';
  }
  return 'active';
}

function describeValue(v) {
  if (v === null || v === undefined) return '—';
  if (v === '') return '(empty)';
  if (Array.isArray(v)) return v.length ? v.map(describeValue).join(', ') : '(none)';
  if (v instanceof Date) return v.toISOString();
  if (typeof v === 'object') {
    try {
      return JSON.stringify(v);
    } catch {
      return '[object]';
    }
  }
  return String(v);
}

// One line for the audit tables: "field: from → to; other: value".
function summarizeAuditDetails(details) {
  if (!details || typeof details !== 'object') return '';
  const parts = [];
  for (const [k, v] of Object.entries(details)) {
    if (v && typeof v === 'object' && !Array.isArray(v) && 'from' in v && 'to' in v) {
      parts.push(`${k}: ${describeValue(v.from)} → ${describeValue(v.to)}`);
    } else {
      parts.push(`${k}: ${describeValue(v)}`);
    }
  }
  return parts.join('; ');
}

// Who did it, for the audit tables. The stored admin email wins, so 'system'
// shows only for SYSTEM_ACTOR rows (CLI, bootstrap, key rotation), which store
// the email 'system'. A row with neither an email nor an admin id was written
// before anyone signed in (failed or throttled sign-ins): 'anonymous', with the
// email that was used, when the details have one.
function describeActor(row) {
  if (row && row.adminEmail) return { label: String(row.adminEmail), anonymous: false, email: null };
  if (row && row.adminUserId) return { label: `admin #${row.adminUserId}`, anonymous: false, email: null };
  const details = row && row.details;
  const email = details && typeof details === 'object' && typeof details.email === 'string' ? details.email.trim() : '';
  return { label: 'anonymous', anonymous: true, email: email === '' ? null : email };
}

module.exports = {
  validateAppInput,
  createAppFromInput,
  updateAppFromInput,
  settingsVersion,
  appToForm,
  defaultForm,
  keyStatus,
  summarizeAuditDetails,
  describeActor,
  formatMb,
  messageSizeLimitsMb,
  formField: field,
  parseId,
  parsePage,
  SETTINGS_FIELDS,
  ENCRYPTIONS,
};
