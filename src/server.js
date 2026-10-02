'use strict';

// Process entry point: configuration, dependencies, the HTTP server, background
// jobs and graceful shutdown. app.js (the cPanel startup file) calls start().
// Under LiteSpeed's lsnode / Passenger, listen() is replaced so the app binds a
// Unix socket; PORT only matters when running standalone.

const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { loadConfig, ConfigError } = require('./config');
const { createDb } = require('./db');
const { createLogger, describeError } = require('./lib/logger');
const { systemClock } = require('./lib/time');
const { runMigrations } = require('./services/migrate');
const { startCleanupTimer } = require('./services/cleanup');
const { ensureBootstrapAdmin } = require('./services/admins');
const sendService = require('./services/send');
const { createApp } = require('./app');

const SHUTDOWN_GRACE_MS = 20000;
// After the grace period, SMTP sends still running get up to
// SMTP_SEND_DEADLINE_MS plus this margin (from the start of the shutdown) to
// finish and record their outcome.
const SEND_SETTLE_MARGIN_MS = 10000;
// Once the sends have settled, how long their HTTP responses get to go out.
const RESPONSE_FLUSH_MS = 5000;
const SEND_POLL_MS = 250;
// Longer than LiteSpeed's upstream keep-alive, so the proxy (not Node) closes
// idle connections; otherwise it can reuse one Node just closed and get a reset.
const KEEP_ALIVE_TIMEOUT_MS = 65000;
const HEADERS_TIMEOUT_MS = 66000;

function buildDeps(config) {
  const logger = createLogger({ file: config.logFile });
  const db = createDb(config.db);
  return { config, db, clock: systemClock, logger };
}

function warnIfEnvReadable(logger) {
  if (process.platform === 'win32') return;
  fs.stat(path.join(__dirname, '..', '.env'), (err, st) => {
    if (err) return;
    if (st.mode & 0o077) {
      logger.warn('.env is readable by group or others; run chmod 600 .env', { mode: (st.mode & 0o777).toString(8) });
    }
  });
}

function warnAboutConfig(config, logger) {
  if (config.trustProxy === true) {
    logger.warn('TRUST_PROXY=true makes client IPs spoofable; use a hop count such as 1');
  }
  if (config.production && !config.forceHttps) logger.warn('FORCE_HTTPS is off in production');
  if (config.production && !config.cookieSecure) logger.warn('COOKIE_SECURE is off in production');
}

function bootstrapInBackground(deps) {
  ensureBootstrapAdmin(deps)
    .then((result) => {
      if (result === 'created') {
        deps.logger.info('bootstrap admin created; remove ADMIN_BOOTSTRAP_PASSWORD from .env', {
          email: deps.config.bootstrapAdmin.email,
        });
      } else if (result === 'exists') {
        deps.logger.warn('ADMIN_BOOTSTRAP_EMAIL/ADMIN_BOOTSTRAP_PASSWORD are set but admins already exist; remove them from .env');
      }
    })
    .catch((err) => deps.logger.error('bootstrap admin check failed', { error: describeError(err) }));
}

// SMTP sends in flight, as counted by services/send.js; null when that module
// offers no counter. Read defensively: shutdown must never fail on it.
function sendsInFlight() {
  try {
    const v = sendService.inFlightSends;
    const n = Number(typeof v === 'function' ? v() : v);
    return Number.isFinite(n) ? Math.max(0, n) : null;
  } catch {
    return null;
  }
}

// → true once no send is in flight, false if timeoutMs passed first.
async function waitForSends(timeoutMs) {
  const ms = Math.max(0, timeoutMs);
  if (typeof sendService.waitForSendsIdle === 'function') {
    try {
      return Boolean(await sendService.waitForSendsIdle(ms));
    } catch {
      // Fall back to polling the counter.
    }
  }
  const until = Date.now() + ms;
  for (;;) {
    const n = sendsInFlight();
    if (n === null || n === 0) return true;
    if (Date.now() >= until) return false;
    await new Promise((resolve) => setTimeout(resolve, Math.min(SEND_POLL_MS, until - Date.now())));
  }
}

// Resolves when `promise` settles or after ms, whichever comes first.
function within(promise, ms) {
  let timer;
  return Promise.race([
    promise,
    new Promise((resolve) => {
      timer = setTimeout(resolve, Math.max(0, ms));
    }),
  ]).finally(() => clearTimeout(timer));
}

// Stops accepting connections and waits up to graceMs for in-flight requests.
// Keep-alive connections are closed as soon as they go idle (Node 20's close()
// only closes the ones idle at that moment). Connections are not cut while an
// SMTP send is still running: a send cut off mid-way becomes an 'unknown' row
// that locks its message_id for the whole idempotency window (docs/SPEC.md
// decision 5), and the caller gets a reset instead of its 200/502. Those get until
// `deadline` (epoch ms), which is bounded because a slow SMTP server can keep
// a send alive indefinitely. → true if every connection finished by itself.
async function closeServer(server, graceMs, deadline) {
  let closed = false;
  const closing = new Promise((resolve) => {
    server.close(() => {
      closed = true;
      resolve();
    });
  });
  server.closeIdleConnections();
  const sweep = setInterval(() => server.closeIdleConnections(), 250);
  try {
    await within(closing, graceMs);
    const pending = sendsInFlight();
    if (!closed && (pending > 0 || (pending === null && typeof sendService.waitForSendsIdle === 'function'))) {
      const settled = await waitForSends(deadline - Date.now());
      // The route answers right after the outcome is recorded.
      if (settled) await within(closing, Math.min(RESPONSE_FLUSH_MS, deadline - Date.now()));
    }
    if (!closed) server.closeAllConnections();
    return closed;
  } finally {
    clearInterval(sweep);
  }
}

// Config errors happen before the logger exists. Under lsnode stderr only
// reaches stderr.log, so also append the reason to LOG_FILE when one is set.
// That value has not been validated, so every file step is best effort.
function reportStartupFailure(text, meta) {
  process.stderr.write(text + '\n');
  let file = '';
  try {
    file = typeof process.env.LOG_FILE === 'string' ? process.env.LOG_FILE.trim() : '';
  } catch {
    file = '';
  }
  if (!file) return;
  try {
    // One line, in the logger's format (JSON escapes the newlines).
    const line = `${new Date().toISOString()} ERROR startup failed ${JSON.stringify(meta)}\n`;
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.appendFileSync(file, line);
  } catch {
    // Nowhere else to report it; stderr already has it.
  }
}

// → { app, server, deps, shutdown } once listen() has been called, or null when
// the configuration is invalid or startup failed (process.exitCode is then 1).
async function start() {
  let config;
  try {
    config = loadConfig();
  } catch (err) {
    if (err instanceof ConfigError) {
      reportStartupFailure(err.message, { reason: 'invalid configuration', problems: err.problems });
    } else {
      reportStartupFailure(`Startup failed: ${err && err.stack}`, {
        error: describeError(err),
        stack: err && err.stack,
      });
    }
    process.exitCode = 1;
    return null;
  }

  const deps = buildDeps(config);
  const { logger, db } = deps;

  let app;
  try {
    if (config.autoMigrate) {
      const applied = await runMigrations(db, { logger });
      if (applied.length) logger.info('migrations applied at startup', { applied });
    }
    app = createApp(deps);
  } catch (err) {
    logger.error('startup failed', { error: describeError(err), stack: err && err.stack });
    process.exitCode = 1;
    await db.close().catch(() => {});
    return null;
  }

  const server = http.createServer(app);
  server.keepAliveTimeout = KEEP_ALIVE_TIMEOUT_MS;
  server.headersTimeout = HEADERS_TIMEOUT_MS;

  let stopCleanup = () => {};
  let stopping = null;
  function shutdown(signal, exitCode = 0) {
    if (stopping) return stopping;
    logger.info('shutting down', { signal });
    stopping = (async () => {
      stopCleanup();
      const deadline = Date.now() + Math.max(SHUTDOWN_GRACE_MS, config.smtpSendDeadlineMs + SEND_SETTLE_MARGIN_MS);
      const graceful = await closeServer(server, SHUTDOWN_GRACE_MS, deadline);
      if (!graceful) logger.warn('shutdown grace period over; closed remaining connections');
      // A send can outlive its connection (the caller hung up); let it record
      // its outcome before the database goes away.
      if (!(await waitForSends(deadline - Date.now()))) {
        const count = sendsInFlight();
        logger.warn('shutdown abandoned SMTP sends still in flight; their outcome will be unknown', {
          count: count === null ? 'unknown' : count,
        });
      }
      await db.close().catch((err) => logger.warn('database close failed', { error: describeError(err) }));
      process.exit(exitCode);
    })();
    return stopping;
  }

  server.on('error', (err) => {
    logger.error('http server error', { error: describeError(err), code: err.code });
    shutdown('server-error', 1);
  });
  // The port/socket is deliberately not logged: under lsnode it is a socket path.
  server.on('listening', () => logger.info('listening', { env: config.nodeEnv }));
  server.listen(config.port);

  process.once('SIGTERM', () => shutdown('SIGTERM'));
  process.once('SIGINT', () => shutdown('SIGINT'));

  bootstrapInBackground(deps);
  stopCleanup = startCleanupTimer(deps);
  warnIfEnvReadable(logger);
  warnAboutConfig(config, logger);

  return { app, server, deps, shutdown };
}

module.exports = { start, buildDeps };
