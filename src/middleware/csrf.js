'use strict';

// CSRF protection for /admin: a per-session token (synchronizer pattern) on
// every state-changing request, plus an Origin check when the browser sends one.
// The token is created lazily, only when a GET/HEAD page reads it, so requests
// that only redirect, and refused POSTs that render an error page, never create
// a session row. (A non-GET request that legitimately re-renders a form has
// already passed the check, so its session holds a token.)
//
// Refusals carry err.code 'csrf' and err.reason: 'missing' (the session has no
// token: it expired or never existed), 'mismatch' or 'origin'. Only 'missing'
// on the sign-in form gets a friendlier answer (routes/admin/auth.js).

const { forbidden } = require('../lib/errors');
const { randomBase64Url, timingSafeEqualStrings } = require('../lib/crypto');

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
const INVALID_FORM = 'Invalid or expired form. Reload and try again.';

function ensureToken(req) {
  if (!req.session) return '';
  if (typeof req.session.csrfToken !== 'string' || req.session.csrfToken === '') {
    req.session.csrfToken = randomBase64Url(32);
  }
  return req.session.csrfToken;
}

function existingToken(req) {
  const t = req.session && req.session.csrfToken;
  return typeof t === 'string' ? t : '';
}

function refusal(reason) {
  const err = forbidden(INVALID_FORM, { code: 'csrf' });
  err.reason = reason;
  return err;
}

function submittedToken(req) {
  const fromBody = req.body && typeof req.body === 'object' ? req.body._csrf : undefined;
  if (typeof fromBody === 'string') return fromBody;
  const header = req.get('x-csrf-token');
  return typeof header === 'string' ? header : '';
}

function csrf(deps) {
  const { config } = deps;
  const expectedHost = new URL(config.publicBaseUrl).host;

  function originAllowed(req) {
    const origin = req.get('origin');
    // Some privacy settings and redirects send the literal "null"; the token
    // check still applies to those requests.
    if (origin === undefined || origin === 'null') return true;
    let host;
    try {
      host = new URL(origin).host;
    } catch {
      return false;
    }
    if (host === expectedHost) return true;
    return !config.production && host === req.get('host');
  }

  return function csrfMiddleware(req, res, next) {
    // A getter, so the token is generated only when a view renders it
    // (Express copies res.locals into the render data at render time), and
    // only for GET/HEAD pages: an error page for a refused anonymous POST (or
    // OPTIONS) must not store a session just to hold an unused token.
    const mints = req.method === 'GET' || req.method === 'HEAD';
    Object.defineProperty(res.locals, 'csrfToken', {
      configurable: true,
      enumerable: true,
      get: () => (mints ? ensureToken(req) : existingToken(req)),
      // Assigning is pointless (the session holds the token) but must not throw.
      set: () => {},
    });

    if (SAFE_METHODS.has(req.method)) return next();

    if (!originAllowed(req)) return next(refusal('origin'));
    const expected = existingToken(req);
    if (expected === '') return next(refusal('missing'));
    if (!timingSafeEqualStrings(expected, submittedToken(req))) return next(refusal('mismatch'));
    next();
  };
}

module.exports = { csrf, ensureToken, INVALID_FORM };
