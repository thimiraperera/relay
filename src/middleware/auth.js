'use strict';

// Admin authentication for everything under /admin except the login routes.
// A session is valid only while the admin exists, is enabled, still has the
// session epoch the session was issued with (password/TOTP changes and
// disabling bump it) and the sign-in is younger than SESSION_ABSOLUTE_HOURS.

const { unauthorized } = require('../lib/errors');
const { clientIp } = require('../lib/clientIp');
const { getAdmin } = require('../repos/admins');
const { regenerateSession, destroySession, clearSessionCookie } = require('./session');

const SESSION_ENDED = 'Your session has ended. Reload the page and sign in again.';
const UNSAFE_NEXT = new RegExp('[\\\\\\x00-\\x1f\\x7f]');

// Post-login redirect target: only local /admin paths, never "//host" or a
// backslash variant that some browsers treat as a scheme-relative URL.
function safeNext(value) {
  if (typeof value !== 'string' || value.length > 2000) return null;
  if (!value.startsWith('/admin') || value.startsWith('//') || UNSAFE_NEXT.test(value)) return null;
  return value;
}

function loginUrl(req, { expired }) {
  const params = new URLSearchParams();
  const next = safeNext(req.originalUrl);
  if (next && next !== '/admin' && next !== '/admin/') params.set('next', next);
  if (expired) params.set('expired', '1');
  const qs = params.toString();
  return '/admin/login' + (qs ? `?${qs}` : '');
}

// Issues a fresh session id for a signed-in admin (after login, or after the
// admin's own password/TOTP change bumped the epoch).
async function startAdminSession(req, { adminId, epoch, authAt }) {
  await regenerateSession(req);
  req.session.adminId = adminId;
  req.session.epoch = epoch;
  req.session.authAt = authAt;
}

function requireAdmin(deps) {
  const maxAgeMs = deps.config.sessionAbsoluteHours * 60 * 60 * 1000;

  return async function requireAdminMiddleware(req, res, next) {
    res.set('Cache-Control', 'no-store');
    const sess = req.session;
    const adminId = sess ? sess.adminId : undefined;

    let admin = null;
    if (adminId) {
      const found = await getAdmin(deps.db, adminId);
      const nowMs = deps.clock.now().getTime();
      if (
        found &&
        !found.disabled &&
        found.sessionEpoch === sess.epoch &&
        typeof sess.authAt === 'number' &&
        nowMs - sess.authAt <= maxAgeMs
      ) {
        admin = found;
      }
    }

    if (!admin) {
      if (adminId) {
        await destroySession(req);
        clearSessionCookie(res, deps.config);
      }
      if (req.method === 'GET' || req.method === 'HEAD') {
        return res.redirect(302, loginUrl(req, { expired: Boolean(adminId) }));
      }
      return next(unauthorized(SESSION_ENDED));
    }

    req.adminUser = admin;
    req.actor = { id: admin.id, email: admin.email, ip: clientIp(req) };
    res.locals.currentUser = { id: admin.id, email: admin.email, name: admin.name, totpEnabled: admin.totpEnabled };
    next();
  };
}

module.exports = { requireAdmin, safeNext, startAdminSession, SESSION_ENDED };
