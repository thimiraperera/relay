'use strict';

// Admin session cookie. Mounted only inside the /admin router. No `proxy`
// option: express-session then decides "secure" from req.secure, which follows
// Express's trust proxy setting (TRUST_PROXY) instead of trusting any
// X-Forwarded-Proto header a client sends.

const session = require('express-session');
const { MySqlSessionStore } = require('./sessionStore');

const COOKIE_NAME = 'relay_sid';

function sessionMiddleware(deps) {
  const { config } = deps;
  return session({
    name: COOKIE_NAME,
    secret: config.sessionSecret,
    store: new MySqlSessionStore(deps),
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: config.cookieSecure,
      maxAge: config.sessionIdleMinutes * 60 * 1000,
    },
  });
}

// New session id. The store tombstones the old row (data = NULL) so a request
// still in flight cannot bring it back; resolves once that is done.
function regenerateSession(req) {
  return new Promise((resolve, reject) => {
    req.session.regenerate((err) => (err ? reject(err) : resolve()));
  });
}

function destroySession(req) {
  return new Promise((resolve, reject) => {
    if (!req.session) return resolve();
    req.session.destroy((err) => (err ? reject(err) : resolve()));
  });
}

// Tells the browser to drop the cookie (the store row is already tombstoned).
function clearSessionCookie(res, config) {
  res.clearCookie(COOKIE_NAME, { path: '/', httpOnly: true, sameSite: 'lax', secure: config.cookieSecure });
}

module.exports = { sessionMiddleware, regenerateSession, destroySession, clearSessionCookie, COOKIE_NAME };
