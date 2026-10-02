'use strict';

// HttpError carries a status code and a short, client-safe reason. API routes turn
// it into {"ok": false, "error": message} (or {"error": message} for /send.php).
// Never put secrets or internal details in `message`.
class HttpError extends Error {
  constructor(status, message, opts = {}) {
    super(message);
    this.name = 'HttpError';
    this.status = status;
    this.expose = true;
    if (opts.code) this.code = opts.code;
    if (opts.headers) this.headers = opts.headers;
    // When false, the send pipeline does not write a 'rejected' row for this error
    // (used for idempotent replays / in-flight duplicates).
    this.logRejection = opts.logRejection !== false;
  }
}

const badRequest = (msg, opts) => new HttpError(400, msg, opts);
const unauthorized = (msg = 'invalid api key', opts) => new HttpError(401, msg, opts);
const forbidden = (msg, opts) => new HttpError(403, msg, opts);
const notFound = (msg = 'not found', opts) => new HttpError(404, msg, opts);
const conflict = (msg, opts) => new HttpError(409, msg, opts);
const tooLarge = (msg = 'message too large', opts) => new HttpError(413, msg, opts);
const unsupportedMediaType = (msg = 'content-type must be application/json', opts) =>
  new HttpError(415, msg, opts);
const tooManyRequests = (msg = 'rate limit exceeded', retryAfterSeconds, opts = {}) =>
  new HttpError(429, msg, {
    ...opts,
    headers: { ...(opts.headers || {}), 'Retry-After': String(Math.max(1, Math.ceil(retryAfterSeconds || 60))) },
  });
const badGateway = (msg, opts) => new HttpError(502, msg, opts);

module.exports = {
  HttpError,
  badRequest,
  unauthorized,
  forbidden,
  notFound,
  conflict,
  tooLarge,
  unsupportedMediaType,
  tooManyRequests,
  badGateway,
};
