'use strict';

// /v1 API: GET /health and POST /send (Bearer API key, JSON body).
//
// Order on /send matters: IP limit, then authentication, then Content-Type, and
// only then the body is read, so unauthenticated clients cannot make the relay
// buffer a large body. This module also exports the error mapping and
// auth-failure bookkeeping that routes/legacy.js shares.

const express = require('express');
const { HttpError, unsupportedMediaType } = require('../lib/errors');
const { clientIp, ipRateKey } = require('../lib/clientIp');
const { localDay } = require('../lib/time');
const { ipRateLimit } = require('../middleware/ipRateLimit');
const { authenticateBearer, touchKeyUsage } = require('../services/keys');
const { handleSend, recordRejection } = require('../services/send');
const { incrementCounter } = require('../repos/rateCounters');
const { setKv } = require('../repos/kv');

const DAY_MS = 24 * 60 * 60 * 1000;
const AUTH_LOG_INTERVAL_MS = 60 * 1000;
const AUTH_LOG_MAX_ENTRIES = 10000;

const BODY_PARSER_ERRORS = Object.freeze({
  'entity.too.large': [413, 'request too large'],
  'entity.parse.failed': [400, 'invalid json body'],
  'encoding.unsupported': [415, 'content-encoding not supported'],
  'charset.unsupported': [415, 'unsupported charset'],
});

function noStore(req, res, next) {
  res.set('Cache-Control', 'no-store');
  next();
}

function errorBody(format, message) {
  return format === 'v1' ? { ok: false, error: message } : { error: message };
}

// → { status, message, headers?, internal? }
function mapApiError(err) {
  if (err instanceof HttpError) return { status: err.status, message: err.message, headers: err.headers };
  // body-parser (http-errors) failures carry a string `type` and a 4xx status.
  if (err && typeof err.type === 'string' && Number.isInteger(err.status) && err.status >= 400 && err.status < 500) {
    const [status, message] = BODY_PARSER_ERRORS[err.type] || [400, 'invalid request body'];
    return { status, message };
  }
  return { status: 500, message: 'internal error', internal: true };
}

// format: 'v1' -> {"ok":false,"error"}, 'legacy' -> {"error"}.
function apiErrorHandler(deps, format) {
  return function apiError(err, req, res, next) {
    if (res.headersSent) return next(err);
    const mapped = mapApiError(err);
    const route = req.baseUrl + req.path;
    if (mapped.internal) {
      deps.logger.error('api request failed', { route, err });
    } else if (mapped.status === 502) {
      deps.logger.warn('smtp send failed', { route, publicId: err.publicId, detail: err.detail || err.message });
    }
    if (mapped.headers) res.set(mapped.headers);
    // A body that was never read would otherwise be drained for keep-alive.
    if (!req.complete) res.set('Connection', 'close');
    res.set('Cache-Control', 'no-store');
    res.status(mapped.status).json(errorBody(format, mapped.message));
  };
}

// Auth failures are counted per route and day (shown on /admin/system) and
// logged at most once per client IP (IPv6: per /64) per minute.
function authFailureRecorder(deps, route) {
  const lastLogged = new Map();

  function shouldLog(bucket, nowMs) {
    const last = lastLogged.get(bucket);
    if (last !== undefined && nowMs - last < AUTH_LOG_INTERVAL_MS) return false;
    if (lastLogged.size >= AUTH_LOG_MAX_ENTRIES) {
      for (const [k, t] of lastLogged) if (nowMs - t >= AUTH_LOG_INTERVAL_MS) lastLogged.delete(k);
      if (lastLogged.size >= AUTH_LOG_MAX_ENTRIES) lastLogged.clear();
    }
    lastLogged.set(bucket, nowMs);
    return true;
  }

  return async function recordAuthFailure(req, reason) {
    const ip = clientIp(req);
    const now = deps.clock.now();
    if (shouldLog(ipRateKey(ip) || 'unknown', now.getTime())) {
      deps.logger.warn('api auth failed', { route, reason, ip });
    }
    try {
      const day = localDay(now, deps.config.timezone);
      await incrementCounter(deps.db, `authfail:${route}:${day}`, new Date(now.getTime() + 3 * DAY_MS));
      await setKv(deps.db, `authfail.${route}.last`, JSON.stringify({ at: now.toISOString(), reason, ip }), now);
    } catch (err) {
      deps.logger.error('could not record auth failure', { route, err });
    }
  };
}

// Fire-and-forget, like handleSend: requests refused before handleSend runs still
// count as the key being used.
function touchKeyInBackground(deps, auth) {
  if (!auth || !auth.apiKey) return;
  Promise.resolve()
    .then(() => touchKeyUsage(deps, { appId: auth.app.id, keyId: auth.apiKey.id }))
    .catch(() => {});
}

function contentLength(req) {
  const n = Number(req.get('content-length'));
  return Number.isSafeInteger(n) && n >= 0 ? n : undefined;
}

// Sends the 401. Connection: close because the request body (if any) is unread.
async function rejectAuth(recordAuthFailure, req, res, { reason, format, bearer = false }) {
  await recordAuthFailure(req, reason);
  res.set('Connection', 'close');
  res.set('Cache-Control', 'no-store');
  if (bearer) res.set('WWW-Authenticate', 'Bearer');
  res.status(401).json(errorBody(format, reason));
}

function createApiRouter(deps) {
  const { config } = deps;
  const router = express.Router();
  const recordAuthFailure = authFailureRecorder(deps, 'api');
  const onError = apiErrorHandler(deps, 'v1');

  router.get('/health', noStore, (req, res) => {
    res.json({ ok: true });
  });

  async function authenticate(req, res, next) {
    const header = req.get('authorization');
    if (!header) {
      return rejectAuth(recordAuthFailure, req, res, { reason: 'missing api key', format: 'v1', bearer: true });
    }
    const auth = await authenticateBearer(deps, header);
    if (!auth) {
      return rejectAuth(recordAuthFailure, req, res, { reason: 'invalid api key', format: 'v1', bearer: true });
    }
    res.locals.relayAuth = auth;
    next();
  }

  function requireJson(req, res, next) {
    if (req.is('application/json')) return next();
    next(unsupportedMediaType('content-type must be application/json'));
  }

  // Authenticated requests refused while the body is read (415 wrong
  // Content-Type, 400 invalid json, 413 request too large, ...) are logged as
  // 'rejected' rows like any other authenticated refusal. With four arguments
  // this only runs for errors from requireJson and express.json: errors from
  // send() come after it in the chain, and errors before authentication have no
  // relayAuth.
  async function logBodyRejection(err, req, res, next) {
    const auth = res.locals.relayAuth;
    const mapped = mapApiError(err);
    if (auth && !mapped.internal && !(err && (err.messageLogged || err.logRejection === false))) {
      touchKeyInBackground(deps, auth);
      await recordRejection(deps, {
        app: auth.app,
        apiKey: auth.apiKey,
        source: 'api',
        body: null,
        clientIp: clientIp(req),
        err: { status: mapped.status, message: mapped.message },
        sizeBytes: mapped.status === 413 ? contentLength(req) : undefined,
      });
    }
    next(err);
  }

  async function send(req, res) {
    const { app, apiKey } = res.locals.relayAuth;
    const result = await handleSend(deps, { app, apiKey, source: 'api', body: req.body, clientIp: clientIp(req) });
    if (result.duplicate) res.set('Idempotent-Replayed', 'true');
    res.status(200).json({ ok: true, id: result.publicId });
  }

  router.post(
    '/send',
    noStore,
    ipRateLimit(deps, { name: 'api', limit: config.ipRateLimitPerMinute, windowSeconds: 60, format: 'v1' }),
    authenticate,
    requireJson,
    express.json({ limit: config.bodyLimitBytes, strict: true, inflate: false }),
    logBodyRejection,
    send,
    onError
  );

  return router;
}

module.exports = createApiRouter;
module.exports.createApiRouter = createApiRouter;
module.exports.mapApiError = mapApiError;
module.exports.apiErrorHandler = apiErrorHandler;
module.exports.authFailureRecorder = authFailureRecorder;
module.exports.rejectAuth = rejectAuth;
module.exports.noStore = noStore;
module.exports.touchKeyInBackground = touchKeyInBackground;
