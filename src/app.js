'use strict';

// Builds the Express application. No body parser is mounted here: each route
// parses its own body (JSON on /v1/send, raw on /send.php, forms under /admin)
// only after its cheap checks have passed.

const path = require('node:path');
const express = require('express');
const { HttpError } = require('./lib/errors');
const { describeError } = require('./lib/logger');
const { createFormatter } = require('./lib/format');
const { securityHeaders, requireHttps } = require('./middleware/security');
const createApiRouter = require('./routes/api');
const { mapApiError } = require('./routes/api');
const createLegacyRouter = require('./routes/legacy');
const createAdminRouter = require('./routes/admin');

const ERROR_TITLES = Object.freeze({
  400: 'Bad request',
  401: 'Signed out',
  403: 'Forbidden',
  404: 'Not found',
  405: 'Not allowed',
  409: 'Conflict',
  413: 'Too large',
  415: 'Unsupported request',
  429: 'Too many requests',
});

// Which response format a path gets: the two machine APIs answer in JSON,
// everything else is an HTML page.
function surface(req) {
  const p = String(req.originalUrl || req.url || '').split('?')[0];
  if (p === '/v1' || p.startsWith('/v1/')) return 'v1';
  if (p === '/send.php') return 'legacy';
  return 'html';
}

// Server-side log only; the client never sees the stack.
function errorMeta(req, route, err) {
  return { method: req.method, route, error: describeError(err), stack: err && err.stack };
}

// → { status, message } safe to show on an HTML error page.
function describeHtmlError(err) {
  if (err instanceof HttpError) return { status: err.status, message: err.message };
  // body-parser failures: http-errors with a string `type` and a 4xx status.
  if (err && typeof err.type === 'string' && Number.isInteger(err.status) && err.status >= 400 && err.status < 500) {
    if (err.type === 'entity.too.large') return { status: 413, message: 'The submitted form is too large.' };
    return { status: err.status, message: 'The request could not be read. Reload the page and try again.' };
  }
  return { status: 500, message: 'Something went wrong. Try again in a moment.' };
}

function createApp(deps) {
  const { config, logger } = deps;
  const app = express();

  app.set('trust proxy', config.trustProxy);
  app.disable('x-powered-by');
  app.set('views', path.join(__dirname, 'views'));
  app.set('view engine', 'ejs');
  // Defaults for every view, including error pages rendered outside /admin.
  Object.assign(app.locals, {
    title: 'Relay',
    currentUser: null,
    csrfToken: '',
    flash: [],
    activeNav: '',
    fmt: createFormatter({ timezone: config.timezone, clock: deps.clock }),
    baseUrl: config.publicBaseUrl,
  });

  function renderError(res, status, message) {
    res.status(status);
    res.set('Cache-Control', 'no-store');
    const title = ERROR_TITLES[status] || (status >= 500 ? 'Error' : 'Request failed');
    res.render('error', { title, status, message }, (err, html) => {
      if (err) {
        logger.error('error page render failed', { err });
        return res.type('text/plain').send(message);
      }
      res.send(html);
    });
  }

  app.use(securityHeaders(deps));
  app.use(requireHttps(deps));
  app.use('/static', express.static(path.join(__dirname, '..', 'public'), { maxAge: '1h', index: false }));

  app.use('/v1', createApiRouter(deps));
  app.use('/', createLegacyRouter(deps));
  app.use('/admin', createAdminRouter(deps));
  app.get('/', (req, res) => res.redirect(302, '/admin'));

  app.use(function notFoundHandler(req, res) {
    const kind = surface(req);
    if (kind === 'html') return renderError(res, 404, 'Page not found.');
    res.set('Cache-Control', 'no-store');
    res.status(404).json(kind === 'v1' ? { ok: false, error: 'not found' } : { error: 'not found' });
  });

  app.use(function errorHandler(err, req, res, next) {
    if (res.headersSent) return next(err);
    const kind = surface(req);
    const route = String(req.originalUrl || '').split('?')[0];

    if (kind !== 'html') {
      const mapped = mapApiError(err);
      if (mapped.internal) logger.error('request failed', errorMeta(req, route, err));
      if (mapped.headers) res.set(mapped.headers);
      if (!req.complete) res.set('Connection', 'close');
      res.set('Cache-Control', 'no-store');
      return res.status(mapped.status).json(kind === 'v1' ? { ok: false, error: mapped.message } : { error: mapped.message });
    }

    const { status, message } = describeHtmlError(err);
    if (status >= 500) logger.error('request failed', errorMeta(req, route, err));
    if (err instanceof HttpError && err.headers) res.set(err.headers);
    if (!req.complete) res.set('Connection', 'close');
    renderError(res, status, message);
  });

  return app;
}

module.exports = createApp;
module.exports.createApp = createApp;
