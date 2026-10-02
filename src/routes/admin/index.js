'use strict';

// The /admin router. Order matters: the per-IP sign-in limiter runs first (so
// refused and form-expired sign-ins are limited too, before any session row is
// written), then form bodies are parsed (only here, 64 KB), then the session,
// flash and CSRF layers run for every admin request; the login routes come
// before requireAdmin, everything after it needs a valid admin session.

const express = require('express');
const { createFormatter } = require('../../lib/format');
const { ipRateLimit } = require('../../middleware/ipRateLimit');
const { sessionMiddleware } = require('../../middleware/session');
const { flash } = require('../../middleware/flash');
const { csrf } = require('../../middleware/csrf');
const { requireAdmin } = require('../../middleware/auth');
const authRoutes = require('./auth');
const accountRoutes = require('./account');
const usersRoutes = require('./users');
const systemRoutes = require('./system');
const appsRoutes = require('./apps');
const logsRoutes = require('./logs');
const statsRoutes = require('./stats');
const auditRoutes = require('./audit');

function createAdminRouter(deps) {
  const router = express.Router();
  const fmt = createFormatter({ timezone: deps.config.timezone, clock: deps.clock });

  router.use((req, res, next) => {
    res.locals.fmt = fmt;
    res.locals.baseUrl = deps.config.publicBaseUrl;
    res.locals.currentUser = null;
    res.locals.activeNav = '';
    next();
  });
  // All /admin/login* routes, 30 requests per minute per client IP.
  router.use('/login', ipRateLimit(deps, { name: 'admin-login', limit: 30, windowSeconds: 60, format: 'html' }));
  router.use(express.urlencoded({ extended: false, limit: '64kb', inflate: false }));
  router.use(sessionMiddleware(deps));
  router.use(flash);
  router.use(csrf(deps));
  router.use(authRoutes(deps));
  // A sign-in form whose session expired is shown again instead of the 403 page.
  router.use(authRoutes.loginFormExpired);
  router.use(requireAdmin(deps));
  router.use(accountRoutes(deps));
  router.use(usersRoutes(deps));
  router.use(systemRoutes(deps));
  router.use(appsRoutes(deps));
  router.use(logsRoutes(deps));
  router.use(statsRoutes(deps));
  router.use(auditRoutes(deps));
  return router;
}

module.exports = createAdminRouter;
module.exports.createAdminRouter = createAdminRouter;
