'use strict';

// The send pipeline shared by POST /v1/send, POST /send.php and the admin "send
// test email" button: validate the request into a normalised message, apply
// idempotency and per-app limits, log a messages row, send synchronously through
// the app's SMTP mailbox and record the outcome.

const {
  HttpError,
  badRequest,
  forbidden,
  conflict,
  tooLarge,
  tooManyRequests,
  badGateway,
} = require('../lib/errors');
const { randomHex } = require('../lib/crypto');
const { decryptSmtpPassword } = require('../lib/secrets');
const { localDay, localDateTime } = require('../lib/time');
const { stripCrlf } = require('../lib/headers');
const { parseAddressList, parseSingleAddress } = require('../lib/addresses');
const { normalizeAttachments, totalAttachmentBytes, attachmentCharge } = require('../lib/attachments');
const { htmlToText } = require('../lib/htmlText');
const { isIpAllowed } = require('../lib/ipAllow');
const { insertMessage, completeMessage, deleteMessage } = require('../repos/messages');
const { findIdempotency, insertIdempotency, reassignIdempotency } = require('../repos/idempotency');
const { incrementCounter } = require('../repos/rateCounters');
const { hitWindow, hitDaily } = require('./rateLimit');
const { touchKeyUsage } = require('./keys');
const { recordAudit } = require('./audit');
const { sendMail } = require('./mailer');

// Same value as config.staleSendingMs (which is not configurable), for callers
// that have no config at hand. The pipeline itself reads deps.config.
const STALE_SENDING_MS = 10 * 60 * 1000;

const DAY_MS = 24 * 60 * 60 * 1000;
const MAX_SUBJECT_CHARS = 998;
const MAX_LEGACY_NAME_CHARS = 998;
const MAX_MESSAGE_ID_CHARS = 191;
const MAX_ERROR_CHARS = 1000;
const IDEMPOTENCY_CLAIM_TRIES = 3;
const OUTCOME_UNKNOWN_SUFFIX = ' (after message data; outcome unknown)';

// Rejected rows keep only a diagnostic excerpt of the raw request, and at most
// max(REJECTED_ROWS_PER_MINUTE, app.limitPerMinute) of them are written per app
// per minute: the per-app send limits never run for a rejected request, so
// without this a key holder (even of a disabled or IP-restricted app) could
// fill the log with large rows.
const REJECTED_LIST_ITEMS = 20;
const REJECTED_ITEM_CHARS = 254;
const REJECTED_TEXT_CHARS = 1000;
const REJECTED_ROWS_PER_MINUTE = 60;
const DROP_WARN_INTERVAL_MS = 60 * 1000;
const DROP_WARN_MAX_ENTRIES = 10000;

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function absent(v) {
  return v === undefined || v === null;
}

// Optional single-address fields also treat an empty string as "not given": form
// based callers often send every field, filled or not.
function blank(v) {
  return absent(v) || (typeof v === 'string' && v.trim() === '');
}

function newPublicId() {
  return 'msg_' + randomHex(12);
}

function utf8Bytes(s) {
  return typeof s === 'string' ? Buffer.byteLength(s, 'utf8') : 0;
}

// message_id: a string or a non-negative safe integer; 1-191 characters after
// stripCrlf. /send.php treats '' as "no message_id" (it then gets replay protection).
function parseMessageId(v, { emptyIsAbsent = false } = {}) {
  if (absent(v)) return null;
  let s;
  if (typeof v === 'string') s = stripCrlf(v);
  else if (typeof v === 'number' && Number.isSafeInteger(v) && v >= 0) s = String(v);
  else throw badRequest('invalid message_id');
  if (s === '' && emptyIsAbsent) return null;
  if (s.length < 1 || s.length > MAX_MESSAGE_ID_CHARS) throw badRequest('invalid message_id');
  return s;
}

function maxRecipientsOf(app, config) {
  const n = Number(app.maxRecipients);
  return Number.isInteger(n) && n > 0 ? n : config.defaultMaxRecipients;
}

function messageLimitOf(app, config) {
  const n = Number(app.maxMessageBytes);
  return Number.isFinite(n) && n > 0 ? Math.min(n, config.maxMessageBytes) : config.maxMessageBytes;
}

function uniqueRecipientCount(lists) {
  const unique = new Set();
  for (const list of lists) for (const r of list) unique.add(r.address.toLowerCase());
  return unique.size;
}

// to, cc and bcc de-duplicated together, case-insensitively: the first spelling
// (and display name) wins, to before cc before bcc. nodemailer only folds the
// domain's case, so "Ab@x.com" and "ab@x.com" would otherwise each get their own
// RCPT TO while the recipient cap counted them once.
function dedupeRecipients(lists) {
  const seen = new Set();
  return lists.map((list) =>
    list.filter((r) => {
      const k = r.address.toLowerCase();
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    })
  );
}

function checkRecipientCap(lists, max) {
  if (uniqueRecipientCount(lists) > max) throw badRequest(`too many recipients (max ${max})`);
}

function displayNames(lists, replyTo) {
  const names = [];
  for (const list of lists) for (const r of list) if (r.name) names.push(r.name);
  if (replyTo && replyTo.name) names.push(replyTo.name);
  return names;
}

// Cuts to at most max UTF-16 units without leaving half a surrogate pair.
function capChars(s, max) {
  if (s.length <= max) return s;
  let out = s.slice(0, max);
  const last = out.charCodeAt(out.length - 1);
  if (last >= 0xd800 && last <= 0xdbff) out = out.slice(0, -1);
  return out.trimEnd();
}

// Size = UTF-8 bytes of subject + html + text as the caller sent them + every
// caller-supplied display name, plus each attachment's attachmentCharge (decoded
// bytes + MIME_PART_OVERHEAD + 6 per filename byte; see lib/attachments). The
// generated text alternative is not counted, so a caller staying under the
// limit is never refused because of text the relay added. This charged figure
// is also what size_bytes stores.
function sizeAndAttachments(body, { subject, html, text, names = [] }, app, config) {
  const limit = messageLimitOf(app, config);
  let textBytes = utf8Bytes(subject) + utf8Bytes(html) + utf8Bytes(text);
  for (const name of names) textBytes += utf8Bytes(name);
  if (textBytes > limit) throw tooLarge('message too large');
  const attachments = normalizeAttachments(body.attachments, { maxBytes: limit - textBytes });
  const sizeBytes = textBytes + totalAttachmentBytes(attachments);
  if (sizeBytes > limit) throw tooLarge('message too large');
  return { attachments, sizeBytes };
}

function optionalBodyPart(v, field) {
  if (absent(v)) return null;
  if (typeof v !== 'string') throw badRequest(`${field} must be a string`);
  return v === '' ? null : v;
}

// /v1: required, non-empty, at most 998 characters (one header line).
// /send.php: any string, empty allowed, as the PHP app has always sent it.
function subjectFrom(v, { legacy }) {
  if (absent(v)) throw badRequest('subject is required');
  if (typeof v !== 'string') throw badRequest('subject must be a string');
  if (!legacy && v.length > MAX_SUBJECT_CHARS) throw badRequest('subject too long');
  const subject = stripCrlf(v);
  if (!subject && !legacy) throw badRequest('subject is required');
  return subject;
}

// Decision 2: the caller may pick the app's From address or one of its allowed
// alternatives (case-insensitive); the configured spelling is used. The From name
// always comes from the app settings.
function chooseFromAddress(v, app) {
  const { address } = parseSingleAddress(v, 'from');
  const wanted = address.toLowerCase();
  const candidates = [app.fromEmail].concat(Array.isArray(app.allowedFrom) ? app.allowedFrom : []);
  const match = candidates.find((c) => typeof c === 'string' && c.toLowerCase() === wanted);
  if (!match) throw badRequest('from not allowed');
  return match;
}

function normalizeV1(body, app, config) {
  if (!isPlainObject(body)) throw badRequest('invalid json body');
  const maxRecipients = maxRecipientsOf(app, config);

  const clientMessageId = parseMessageId(body.message_id);
  const parsedTo = parseAddressList(body.to, 'to', { max: maxRecipients });
  if (parsedTo.length === 0) throw badRequest('to is required');
  const parsedCc = parseAddressList(body.cc, 'cc', { max: maxRecipients });
  const parsedBcc = parseAddressList(body.bcc, 'bcc', { max: maxRecipients });
  // `to` comes first, so it keeps at least its first address.
  const [to, cc, bcc] = dedupeRecipients([parsedTo, parsedCc, parsedBcc]);
  checkRecipientCap([to, cc, bcc], maxRecipients);

  const replyTo = blank(body.reply_to) ? null : parseSingleAddress(body.reply_to, 'reply_to');
  const fromAddress = blank(body.from) ? null : chooseFromAddress(body.from, app);
  const subject = subjectFrom(body.subject, { legacy: false });
  const html = optionalBodyPart(body.html, 'html');
  let text = optionalBodyPart(body.text, 'text');
  if (!html && !text) throw badRequest('html or text is required');

  const names = displayNames([to, cc, bcc], replyTo);
  const { attachments, sizeBytes } = sizeAndAttachments(body, { subject, html, text, names }, app, config);
  if (!text) text = htmlToText(html);
  return { to, cc, bcc, fromAddress, replyTo, subject, html, text, attachments, clientMessageId, sizeBytes };
}

function legacyRecipient(toValue, toName) {
  let raw;
  if (typeof toValue === 'string') raw = toValue;
  else if (Array.isArray(toValue) && toValue.length === 1 && typeof toValue[0] === 'string') raw = toValue[0];
  else throw badRequest('exactly one recipient required');
  const list = parseAddressList(raw, 'to');
  if (list.length !== 1) throw badRequest('exactly one recipient required');
  const recipient = list[0];
  if (!recipient.name && typeof toName === 'string') recipient.name = stripCrlf(toName);
  // One header line at most; cut rather than refused, as the PHP app's request
  // format cannot change.
  recipient.name = capChars(recipient.name || '', MAX_LEGACY_NAME_CHARS);
  return recipient;
}

// The existing PHP app's format: one recipient, html only; cc, bcc, from,
// reply_to and text are ignored.
function normalizeLegacy(body, app, config) {
  if (!isPlainObject(body)) throw badRequest('invalid json body');

  const clientMessageId = parseMessageId(body.message_id, { emptyIsAbsent: true });
  const to = [legacyRecipient(body.to, body.to_name)];
  checkRecipientCap([to], maxRecipientsOf(app, config));
  const subject = subjectFrom(body.subject, { legacy: true });
  if (typeof body.html !== 'string' || body.html === '') throw badRequest('html is required');
  const html = body.html;

  const names = displayNames([to], null);
  const { attachments, sizeBytes } = sizeAndAttachments(body, { subject, html, text: null, names }, app, config);
  return {
    to,
    cc: [],
    bcc: [],
    fromAddress: null,
    replyTo: null,
    subject,
    html,
    text: htmlToText(html),
    attachments,
    clientMessageId,
    sizeBytes,
  };
}

// No envelope, sender or caller-supplied headers: nodemailer derives MAIL FROM
// from `from` and RCPT TO from to + cc + bcc.
function buildMail(app, message, publicId) {
  const fromAddress = message.fromAddress || app.fromEmail;
  const domain = fromAddress.slice(fromAddress.lastIndexOf('@') + 1);
  const mail = {
    from: { name: stripCrlf(app.fromName), address: fromAddress },
    to: message.to,
    cc: message.cc,
    bcc: message.bcc,
    replyTo: message.replyTo || (app.replyToDefault ? { address: app.replyToDefault } : undefined),
    subject: message.subject,
    attachments: message.attachments.map((a) => ({
      filename: a.filename,
      content: a.content,
      contentType: a.contentType,
    })),
    messageId: `<${publicId}@${domain}>`,
    disableFileAccess: true,
    disableUrlAccess: true,
  };
  if (message.html) mail.html = message.html;
  if (message.text) mail.text = message.text;
  return mail;
}

function lockedError(message) {
  return conflict(message, { logRejection: false });
}

// What an existing idempotency entry means for a new request with the same
// message_id (docs/SPEC.md decisions 1 and 5):
//   free         no entry
//   reassignable entry expired, message gone, failed or rejected -> may retry
//   duplicate    first attempt was sent -> answer with its id, never resend
//   locked       still sending, or outcome unknown -> 409
function classify(deps, existing) {
  if (!existing) return { outcome: 'free' };
  const nowMs = deps.clock.now().getTime();
  const windowMs = deps.config.idempotencyDays * DAY_MS;
  if (existing.createdAt instanceof Date && nowMs - existing.createdAt.getTime() > windowMs) {
    return { outcome: 'reassignable', existing };
  }
  const msg = existing.message;
  if (!msg || msg.status === 'failed' || msg.status === 'rejected') return { outcome: 'reassignable', existing };
  if (msg.status === 'sent') return { outcome: 'duplicate', publicId: msg.publicId };
  if (msg.status === 'sending' && msg.createdAt instanceof Date) {
    if (nowMs - msg.createdAt.getTime() < deps.config.staleSendingMs) {
      return { outcome: 'locked', error: lockedError('message_id is already being sent') };
    }
  }
  // 'unknown', a stale 'sending' row, or anything unexpected: the first attempt
  // may have been delivered, so the id stays locked for the whole window.
  return { outcome: 'locked', error: lockedError('message_id outcome unknown') };
}

function duplicateResult(verdict) {
  return { publicId: verdict.publicId, duplicate: true, smtpResponse: null, partial: false };
}

// Points the app's message_id at our new row: insert, or take over an entry
// whose first attempt may be retried (compare-and-swap, so of several
// concurrent retries exactly one wins).
async function claimIdempotency(deps, appId, key, messageRowId) {
  const { db } = deps;
  for (let attempt = 0; attempt < IDEMPOTENCY_CLAIM_TRIES; attempt++) {
    if (await insertIdempotency(db, appId, key, messageRowId, deps.clock.now())) return { won: true };
    const existing = await findIdempotency(db, appId, key);
    if (!existing) continue;
    const verdict = classify(deps, existing);
    if (verdict.outcome !== 'reassignable') return { won: false, verdict };
    if (await reassignIdempotency(db, appId, key, existing.messageId, messageRowId, deps.clock.now())) {
      return { won: true };
    }
  }
  return { won: false, verdict: { outcome: 'locked', error: lockedError('message_id is already being sent') } };
}

async function enforceAppLimits(deps, app) {
  const perMinute = await hitWindow(deps, `app:${app.id}:min`, app.limitPerMinute, 60);
  if (!perMinute.allowed) throw tooManyRequests('rate limit exceeded (per minute)', perMinute.retryAfterSeconds);
  const perDay = await hitDaily(deps, `app:${app.id}:day`, app.limitPerDay);
  if (!perDay.allowed) throw tooManyRequests('rate limit exceeded (per day)', perDay.retryAfterSeconds);
}

// Records the outcome of a send. Never throws: the SMTP result is what the
// caller must see, even if the log row cannot be updated.
async function finishRow(deps, row, fields) {
  const completedAt = deps.clock.now();
  try {
    await completeMessage(deps.db, row.id, {
      ...fields,
      completedAt,
      durationMs: Math.max(0, completedAt.getTime() - row.createdAt.getTime()),
    });
  } catch (err) {
    deps.logger.error('could not record message outcome', { publicId: row.publicId, status: fields.status, err });
  }
}

async function discardRow(deps, row) {
  try {
    await deleteMessage(deps.db, row.id);
  } catch (err) {
    deps.logger.error('could not delete superseded message row', { publicId: row.publicId, err });
  }
}

function markLogged(err, publicId) {
  err.messageLogged = true;
  if (publicId && !err.publicId) err.publicId = publicId;
  return err;
}

function partialRejectionText(info) {
  const parts = info.rejectedErrors.length
    ? info.rejectedErrors.map((e) => (e.response ? `${e.recipient} (${e.response})` : e.recipient))
    : info.rejected;
  return 'partially rejected: ' + parts.join(', ');
}

// SMTP sends in progress in this process, from just before the connection is
// opened until the outcome is recorded. Graceful shutdown waits on it so a
// restart does not cut a send off midway (which would leave an 'unknown' row
// that locks the message_id).
let inFlight = 0;
const idleWaiters = new Set();

function inFlightSends() {
  return inFlight;
}

function sendFinished() {
  inFlight = Math.max(0, inFlight - 1);
  if (inFlight === 0) for (const notify of Array.from(idleWaiters)) notify();
}

// → true once no send is in flight, false when timeoutMs passes first (no
// timeout when it is not a finite number).
function waitForSendsIdle(timeoutMs) {
  if (inFlight === 0) return Promise.resolve(true);
  return new Promise((resolve) => {
    let timer = null;
    function settle(idle) {
      idleWaiters.delete(onIdle);
      clearTimeout(timer);
      resolve(idle);
    }
    function onIdle() {
      settle(true);
    }
    idleWaiters.add(onIdle);
    const ms = Number(timeoutMs);
    if (Number.isFinite(ms)) timer = setTimeout(() => settle(inFlight === 0), Math.max(0, ms));
  });
}

// A failure after the message data started to flow, with no SMTP reply (dropped
// connection, socket timeout, deadline), may still have been delivered: the row
// becomes 'unknown', which keeps the message_id locked (docs/SPEC.md decisions 1 and 5).
// Every other failure is 'failed' and may be retried.
async function recordSendFailure(deps, row, err) {
  const code = err.smtpCode || 'ESEND';
  const detail = err.detail || `${code}: ${err.message}`;
  const unknown = err.outcomeUnknown === true;
  const error = unknown
    ? detail.slice(0, MAX_ERROR_CHARS - OUTCOME_UNKNOWN_SUFFIX.length) + OUTCOME_UNKNOWN_SUFFIX
    : detail;
  await finishRow(deps, row, {
    status: unknown ? 'unknown' : 'failed',
    error,
    smtpResponse: err.smtpResponse || null,
    httpStatus: 502,
  });
  const out = badGateway(
    unknown
      ? `smtp error: ${code} (outcome unknown)`
      : 'smtp error: ' + code + (err.responseCode ? ' ' + err.responseCode : '')
  );
  out.detail = error;
  out.smtpResponse = err.smtpResponse || '';
  return markLogged(out, row.publicId);
}

// Steps 5-6: SMTP password, then the send itself. Every error leaving here has
// messageLogged set and the row completed.
async function sendAndRecord(deps, { app, message, row }) {
  let smtpPassword = null;
  if (app.smtpUsername) {
    smtpPassword = decryptSmtpPassword(deps.config, app);
    if (smtpPassword === null) {
      await finishRow(deps, row, { status: 'failed', error: 'smtp password not configured', httpStatus: 502 });
      throw markLogged(badGateway('smtp password not configured'), row.publicId);
    }
  }

  const mail = buildMail(app, message, row.publicId);
  inFlight++;
  try {
    let info;
    try {
      info = await sendMail(deps, { app, smtpPassword, mail });
    } catch (err) {
      throw await recordSendFailure(deps, row, err);
    }

    const partial = info.rejected.length > 0;
    await finishRow(deps, row, {
      status: 'sent',
      smtpMessageId: info.messageId || null,
      smtpResponse: info.response || null,
      error: partial ? partialRejectionText(info) : null,
      httpStatus: 200,
    });
    return { publicId: row.publicId, duplicate: false, smtpResponse: info.response, partial };
  } finally {
    sendFinished();
  }
}

async function deliver(deps, { app, apiKey, source, message, clientIp, skipLimits = false }) {
  const { db, config } = deps;
  const key = message.clientMessageId;

  // 1. A repeated message_id: answer from the first attempt where we can.
  if (key) {
    const verdict = classify(deps, await findIdempotency(db, app.id, key));
    if (verdict.outcome === 'duplicate') return duplicateResult(verdict);
    if (verdict.outcome === 'locked') throw verdict.error;
  }

  // 2. Per-app limits (the admin test email skips them).
  if (!skipLimits) await enforceAppLimits(deps, app);

  // 3. The log row exists before any SMTP traffic, so a crash mid-send leaves a
  //    'sending' row that cleanup turns into 'unknown'.
  const createdAt = deps.clock.now();
  const publicId = newPublicId();
  const rowId = await insertMessage(db, {
    publicId,
    appId: app.id,
    apiKeyId: apiKey ? apiKey.id : null,
    source,
    clientMessageId: key,
    status: 'sending',
    day: localDay(createdAt, config.timezone),
    createdAt,
    fromEmail: message.fromAddress || app.fromEmail,
    toAddrs: message.to,
    ccAddrs: message.cc,
    bccAddrs: message.bcc,
    recipientCount: uniqueRecipientCount([message.to, message.cc, message.bcc]),
    subject: message.subject,
    sizeBytes: message.sizeBytes,
    attachmentCount: message.attachments.length,
    error: null,
    httpStatus: null,
    clientIp: clientIp || null,
  });
  const row = { id: rowId, publicId, createdAt };

  // 4. Claim the message_id. A concurrent request may have taken it since step 1.
  if (key) {
    let claim;
    try {
      claim = await claimIdempotency(deps, app.id, key, rowId);
    } catch (err) {
      await discardRow(deps, row);
      throw markLogged(err);
    }
    if (!claim.won) {
      await discardRow(deps, row);
      if (claim.verdict.outcome === 'duplicate') return duplicateResult(claim.verdict);
      throw markLogged(claim.verdict.error);
    }
  }

  // 5-6. Errors from sendAndRecord are already logged. Anything else happened
  //      before the SMTP send started, so the row is completed as failed (which
  //      also keeps the message_id retryable).
  try {
    return await sendAndRecord(deps, { app, message, row });
  } catch (err) {
    if (!err.messageLogged) {
      deps.logger.error('send pipeline error', { publicId, err });
      await finishRow(deps, row, { status: 'failed', error: 'internal error', httpStatus: 500 });
      markLogged(err, publicId);
    }
    throw err;
  }
}

// Rejected rows are built from the raw request without running the validators
// again (they may be what failed).
function rawText(v, maxChars) {
  if (absent(v)) return null;
  const s = String(v);
  return s.length > maxChars ? s.slice(0, maxChars) : s;
}

function rawList(v) {
  if (absent(v)) return null;
  if (!Array.isArray(v)) return rawText(v, REJECTED_TEXT_CHARS);
  const items = v.slice(0, REJECTED_LIST_ITEMS).map((x) => String(x).slice(0, REJECTED_ITEM_CHARS));
  return rawText(items.join(', '), REJECTED_TEXT_CHARS);
}

function rawCount(v) {
  if (Array.isArray(v)) return v.length;
  return typeof v === 'string' && v.trim() !== '' ? 1 : 0;
}

function rawMessageId(v) {
  if (absent(v)) return null;
  const s = stripCrlf(String(v)).slice(0, MAX_MESSAGE_ID_CHARS);
  return s === '' ? null : s;
}

// An estimate of the charged size (see sizeAndAttachments) without parsing:
// display names inside address strings are not counted, and each attachment is
// charged with its filename as sent (not cleaned; the body limit bounds it).
function rawSize(b, legacy) {
  let size = utf8Bytes(b.subject) + utf8Bytes(b.html) + (legacy ? utf8Bytes(b.to_name) : utf8Bytes(b.text));
  if (Array.isArray(b.attachments)) {
    for (const a of b.attachments) {
      if (isPlainObject(a) && typeof a.content_base64 === 'string') {
        size += attachmentCharge(Math.floor((a.content_base64.length * 3) / 4), a.filename);
      }
    }
  }
  return size;
}

// One warning per app per minute when rejected rows are being dropped.
const dropWarnedAt = new Map();
function shouldWarnDrop(appId, nowMs) {
  const last = dropWarnedAt.get(appId);
  if (last !== undefined && nowMs - last < DROP_WARN_INTERVAL_MS) return false;
  if (dropWarnedAt.size >= DROP_WARN_MAX_ENTRIES) dropWarnedAt.clear();
  dropWarnedAt.set(appId, nowMs);
  return true;
}

// → true when this rejection may be written as a row. Over the per-app ceiling
// it is only counted (rate_counters 'rejdrop:<appId>:<local day>'). A database
// error in the check keeps the old behaviour: the row is written.
async function rejectionRowAllowed(deps, app) {
  const limit = Math.max(REJECTED_ROWS_PER_MINUTE, Number(app.limitPerMinute) || 0);
  try {
    const hit = await hitWindow(deps, `app:${app.id}:rej`, limit, 60);
    if (hit.allowed) return true;
  } catch (err) {
    deps.logger.error('rejected-row limit check failed; recording the row', { appId: app.id, err });
    return true;
  }
  const now = deps.clock.now();
  try {
    const day = localDay(now, deps.config.timezone);
    await incrementCounter(deps.db, `rejdrop:${app.id}:${day}`, new Date(now.getTime() + 3 * DAY_MS));
  } catch (err) {
    deps.logger.error('could not count a dropped rejected row', { appId: app.id, err });
  }
  if (shouldWarnDrop(app.id, now.getTime())) {
    deps.logger.warn('too many rejected requests for app; not logging them', { appId: app.id, perMinute: limit });
  }
  return false;
}

// Writes the 'rejected' row for an authenticated request that was refused, from
// the raw body (null when it could not be parsed). err: an HttpError or a plain
// { status, message }; on success it gets messageLogged and publicId. Never
// throws. sizeBytes overrides the estimate (e.g. a 413's Content-Length).
// Exported for the routes, which log body-parse rejections after authentication.
async function recordRejection(deps, { app, apiKey, source, body, clientIp, err, sizeBytes }) {
  const b = isPlainObject(body) ? body : {};
  const legacy = source === 'legacy';
  if (!(await rejectionRowAllowed(deps, app))) return;
  const now = deps.clock.now();
  const publicId = newPublicId();
  try {
    await insertMessage(deps.db, {
      publicId,
      appId: app.id,
      apiKeyId: apiKey ? apiKey.id : null,
      source,
      clientMessageId: rawMessageId(b.message_id),
      status: 'rejected',
      day: localDay(now, deps.config.timezone),
      createdAt: now,
      fromEmail: app.fromEmail,
      toAddrs: rawList(b.to),
      ccAddrs: legacy ? null : rawList(b.cc),
      bccAddrs: legacy ? null : rawList(b.bcc),
      recipientCount: rawCount(b.to) + (legacy ? 0 : rawCount(b.cc) + rawCount(b.bcc)),
      subject: absent(b.subject) ? null : String(b.subject).slice(0, 255),
      sizeBytes: Number.isFinite(sizeBytes) && sizeBytes >= 0 ? sizeBytes : rawSize(b, legacy),
      attachmentCount: Array.isArray(b.attachments) ? b.attachments.length : 0,
      error: err.message,
      httpStatus: err.status,
      clientIp: clientIp || null,
    });
    markLogged(err, publicId);
  } catch (dbErr) {
    deps.logger.error('could not record rejected message', { appId: app.id, status: err.status, err: dbErr });
  }
}

async function handleSend(deps, { app, apiKey, source, body, clientIp }) {
  if (apiKey) {
    Promise.resolve()
      .then(() => touchKeyUsage(deps, { appId: app.id, keyId: apiKey.id }))
      .catch(() => {});
  }
  try {
    if (!app.enabled) throw forbidden('app disabled');
    if (Array.isArray(app.ipAllowlist) && app.ipAllowlist.length > 0 && !isIpAllowed(app.ipAllowlist, clientIp)) {
      throw forbidden('ip not allowed');
    }
    const message = source === 'legacy' ? normalizeLegacy(body, app, deps.config) : normalizeV1(body, app, deps.config);
    return await deliver(deps, { app, apiKey, source, message, clientIp });
  } catch (err) {
    if (err instanceof HttpError && err.logRejection !== false && !err.messageLogged) {
      await recordRejection(deps, { app, apiKey, source, body, clientIp, err });
    }
    throw err;
  }
}

const HTML_ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => HTML_ESCAPES[c]);
}

// Admin "Send test email". Works for disabled apps, ignores the IP allowlist and
// limits; SMTP problems come back as { ok: false, error } instead of throwing.
async function sendTestEmail(deps, { app, to, actor }) {
  let recipient;
  try {
    recipient = parseSingleAddress(typeof to === 'string' ? to.trim() : to, 'to');
  } catch {
    return { ok: false, error: 'invalid to address' };
  }

  const tz = deps.config.timezone;
  const when = localDateTime(deps.clock.now(), tz);
  const appName = stripCrlf(app.name) || `app ${app.id}`;
  const subject = stripCrlf(`Relay test: ${appName}`);
  const text = `This is a test email from Relay for the app "${appName}".\n\nSent ${when} (${tz}).\n`;
  const html =
    `<p>This is a test email from Relay for the app <strong>${escapeHtml(appName)}</strong>.</p>` +
    `<p>Sent ${escapeHtml(when)} (${escapeHtml(tz)}).</p>`;
  const message = {
    to: [recipient],
    cc: [],
    bcc: [],
    fromAddress: null,
    replyTo: null,
    subject,
    html,
    text,
    attachments: [],
    clientMessageId: null,
    sizeBytes: utf8Bytes(subject) + utf8Bytes(html) + utf8Bytes(text),
  };

  let result;
  try {
    const sent = await deliver(deps, {
      app,
      apiKey: null,
      source: 'test',
      message,
      clientIp: actor && actor.ip ? actor.ip : null,
      skipLimits: true,
    });
    result = { ok: true, publicId: sent.publicId, response: sent.smtpResponse };
  } catch (err) {
    if (!(err instanceof HttpError)) throw err;
    result = { ok: false, publicId: err.publicId, error: err.detail || err.message };
  }

  try {
    await recordAudit(
      deps.db,
      actor,
      'app.test_email',
      { targetType: 'app', targetId: app.id, details: { to: recipient.address, ok: result.ok } },
      deps.clock.now()
    );
  } catch (err) {
    deps.logger.error('could not audit test email', { appId: app.id, err });
  }
  return result;
}

module.exports = {
  normalizeV1,
  normalizeLegacy,
  buildMail,
  deliver,
  handleSend,
  recordRejection,
  sendTestEmail,
  parseMessageId,
  classify,
  dedupeRecipients,
  inFlightSends,
  waitForSendsIdle,
  STALE_SENDING_MS,
};
