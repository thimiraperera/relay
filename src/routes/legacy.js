'use strict';

// POST /send.php: the signed endpoint an existing PHP app calls. Only its URL and key change, so the request format is fixed:
//   X-Relay-Timestamp: <unix seconds>
//   X-Relay-Signature: sha256=<hex HMAC-SHA256(key, timestamp + "." + raw body)>
// The body is JSON whatever the Content-Type says (PHP curl posting a string
// sends application/x-www-form-urlencoded, or nothing).

const express = require('express');
const { HttpError, badRequest, conflict } = require('../lib/errors');
const { clientIp } = require('../lib/clientIp');
const { parseSignatureHeader, parseTimestampHeader, isTimestampFresh } = require('../lib/legacySignature');
const { ipRateLimit } = require('../middleware/ipRateLimit');
const { authenticateLegacy } = require('../services/keys');
const { handleSend, parseMessageId, recordRejection } = require('../services/send');
const { incrementCounter } = require('../repos/rateCounters');
const { listValidLegacyKeys } = require('../repos/apiKeys');
const { apiErrorHandler, authFailureRecorder, rejectAuth, noStore, touchKeyInBackground } = require('./api');

const BOM = String.fromCharCode(0xfeff);

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

// Must agree with normalizeLegacy: a request either carries a message_id that
// becomes its idempotency key, or it gets the signature replay check.
function hasUsableMessageId(body) {
  if (!isPlainObject(body)) return false;
  try {
    return parseMessageId(body.message_id, { emptyIsAbsent: true }) !== null;
  } catch {
    return false;
  }
}

function createLegacyRouter(deps) {
  const { config } = deps;
  const router = express.Router();
  const recordAuthFailure = authFailureRecorder(deps, 'legacy');
  const onError = apiErrorHandler(deps, 'legacy');

  function reject(req, res, reason) {
    return rejectAuth(recordAuthFailure, req, res, { reason, format: 'legacy' });
  }

  // Cheap checks on the headers before the body is read.
  function checkSignatureHeaders(req, res, next) {
    const timestamp = parseTimestampHeader(req.get('x-relay-timestamp'));
    const sigBuf = parseSignatureHeader(req.get('x-relay-signature'));
    if (!timestamp || !sigBuf) return reject(req, res, 'missing or malformed signature headers');
    if (!isTimestampFresh(timestamp.seconds, deps.clock.now().getTime(), config.legacyMaxSkewSeconds)) {
      return reject(req, res, 'timestamp out of range');
    }
    res.locals.relaySignature = { timestamp, sigBuf };
    next();
  }

  // With no valid legacy key at all, no signature can match: answer before the
  // body is read, so such requests cost neither the upload nor any HMAC work.
  async function requireLegacyKeys(req, res, next) {
    const keys = await listValidLegacyKeys(deps.db, deps.clock.now());
    if (keys.length === 0) return reject(req, res, 'invalid signature');
    next();
  }

  async function verifySignature(req, res, next) {
    const rawBody = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
    const { timestamp, sigBuf } = res.locals.relaySignature;
    let auth;
    try {
      auth = await authenticateLegacy(deps, { timestamp, sigBuf, rawBody });
    } catch (err) {
      if (err instanceof HttpError && err.status === 401) return reject(req, res, 'invalid signature');
      throw err;
    }
    res.locals.relayAuth = auth;
    res.locals.rawBody = rawBody;
    next();
  }

  async function send(req, res) {
    const { app, apiKey } = res.locals.relayAuth;
    const { timestamp, sigBuf } = res.locals.relaySignature;

    let text = res.locals.rawBody.toString('utf8');
    if (text.startsWith(BOM)) text = text.slice(1);
    let body;
    try {
      body = JSON.parse(text);
    } catch {
      // Signed by a known key, so logged like every authenticated refusal.
      const err = badRequest('invalid json body');
      touchKeyInBackground(deps, res.locals.relayAuth);
      await recordRejection(deps, { app, apiKey, source: 'legacy', body: null, clientIp: clientIp(req), err });
      throw err;
    }

    // Without a message_id there is no idempotency key, so remember the
    // signature itself until its timestamp can no longer pass the freshness check.
    if (!hasUsableMessageId(body)) {
      const expiresAt = new Date((timestamp.seconds + config.legacyMaxSkewSeconds + 60) * 1000);
      const count = await incrementCounter(deps.db, 'legacysig:' + sigBuf.toString('hex'), expiresAt);
      if (count > 1) throw conflict('replayed request', { logRejection: false });
    }

    await handleSend(deps, { app, apiKey, source: 'legacy', body, clientIp: clientIp(req) });
    res.status(200).json({ ok: true });
  }

  router.post(
    '/send.php',
    noStore,
    ipRateLimit(deps, { name: 'legacy', limit: config.ipRateLimitPerMinute, windowSeconds: 60, format: 'legacy' }),
    checkSignatureHeaders,
    requireLegacyKeys,
    express.raw({ type: () => true, limit: config.bodyLimitBytes, inflate: false }),
    verifySignature,
    send,
    onError
  );

  router.all('/send.php', noStore, (req, res) => {
    res.set('Allow', 'POST');
    res.status(405).json({ error: 'method not allowed' });
  });

  return router;
}

module.exports = createLegacyRouter;
module.exports.createLegacyRouter = createLegacyRouter;
