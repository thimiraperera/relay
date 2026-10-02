'use strict';

// Per-client-IP fixed-window limit, shared across Node processes through
// rate_counters. IPv6 clients are counted per /64 (see ipRateKey).

const { clientIp, ipRateKey } = require('../lib/clientIp');
const { hitWindow } = require('../services/rateLimit');

const HTML_MESSAGE = 'Too many requests. Try again shortly.';
const JSON_MESSAGE = 'too many requests';

let warnedNoIp = false;

// format: 'v1' -> {ok:false,error}, 'legacy' -> {error}, 'html' -> plain text.
function ipRateLimit(deps, { name, limit, windowSeconds, format }) {
  return async function ipRateLimitMiddleware(req, res, next) {
    const key = ipRateKey(clientIp(req));
    if (!key) {
      // Without a client address every visitor would share one bucket; better to
      // skip the limit and make the misconfiguration visible.
      if (!warnedNoIp) {
        warnedNoIp = true;
        deps.logger.warn('client IP unavailable; check TRUST_PROXY', { limiter: name });
      }
      return next();
    }

    let result;
    try {
      result = await hitWindow(deps, `ip:${name}:${key}`, limit, windowSeconds);
    } catch (err) {
      deps.logger.error('ip rate limit check failed; allowing request', { limiter: name, err });
      return next();
    }
    if (result.allowed) return next();

    res.set('Retry-After', String(Math.max(1, Math.ceil(result.retryAfterSeconds || windowSeconds))));
    // The request body has not been read; closing avoids draining it for keep-alive.
    if (!req.complete) res.set('Connection', 'close');
    res.status(429);
    if (format === 'v1') return res.json({ ok: false, error: JSON_MESSAGE });
    if (format === 'legacy') return res.json({ error: JSON_MESSAGE });
    return res.type('text/plain').send(HTML_MESSAGE);
  };
}

// Usable as `require(...)(deps, opts)` and as `const { ipRateLimit } = require(...)`.
module.exports = ipRateLimit;
module.exports.ipRateLimit = ipRateLimit;
