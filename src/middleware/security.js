'use strict';

// Response security headers and the HTTPS requirement.

const helmet = require('helmet');

function securityHeaders(deps) {
  const { forceHttps } = deps.config;
  return helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],
        baseUri: ["'none'"],
        objectSrc: ["'none'"],
        ...(forceHttps ? { upgradeInsecureRequests: [] } : {}),
      },
    },
    strictTransportSecurity: forceHttps ? { maxAge: 31536000 } : false,
    // helmet's default (no-referrer) makes browsers send "Origin: null" on
    // same-origin form posts, which would defeat the CSRF Origin check.
    referrerPolicy: { policy: 'same-origin' },
    xFrameOptions: { action: 'deny' },
  });
}

function isHealthCheck(req) {
  return (req.method === 'GET' || req.method === 'HEAD') && req.path === '/v1/health';
}

function firstForwardedProto(req) {
  const raw = req.get('x-forwarded-proto');
  if (raw === undefined) return undefined;
  return raw.split(',')[0].trim().toLowerCase();
}

// With FORCE_HTTPS, plain-HTTP requests are redirected (GET/HEAD) or refused.
// req.secure comes from the trusted X-Forwarded-Proto (TRUST_PROXY). When the
// proxy sends no X-Forwarded-Proto at all there is nothing to decide on, so the
// request is allowed and the misconfiguration is logged once.
function requireHttps(deps) {
  const { config, logger } = deps;
  const httpsOrigin = config.publicBaseUrl ? 'https://' + new URL(config.publicBaseUrl).host : '';
  let warnedMissing = false;
  let warnedUntrusted = false;

  return function requireHttpsMiddleware(req, res, next) {
    if (!config.forceHttps || req.secure || isHealthCheck(req)) return next();

    const proto = firstForwardedProto(req);
    if (proto === undefined) {
      if (!warnedMissing) {
        warnedMissing = true;
        logger.warn('cannot detect HTTPS; check TRUST_PROXY');
      }
      return next();
    }
    if (proto === 'https' && !warnedUntrusted) {
      // The proxy says HTTPS but Express does not trust it: every request will be
      // treated as plain HTTP (redirect loop / 403). Almost always TRUST_PROXY.
      warnedUntrusted = true;
      logger.warn('X-Forwarded-Proto is https but not trusted; check TRUST_PROXY');
    }

    if (req.method === 'GET' || req.method === 'HEAD') {
      return res.redirect(308, httpsOrigin + req.originalUrl);
    }
    // The request body is unread; closing avoids draining it for keep-alive.
    res.set('Connection', 'close');
    res.set('Cache-Control', 'no-store');
    res.status(403);
    if (req.path === '/v1' || req.path.startsWith('/v1/')) return res.json({ ok: false, error: 'https required' });
    if (req.path === '/send.php') return res.json({ error: 'https required' });
    return res.type('text/plain').send('HTTPS required');
  };
}

module.exports = { securityHeaders, requireHttps };
