'use strict';

// Shared test setup. Requiring this file has no side effects: .env.test is read
// lazily by testConfig()/dbAvailable(), and nothing connects or listens until a
// test asks for it. (node --test also loads this file as a test file because it
// sits under test/; it defines no tests, so that run is empty.)
//
// Every test file shares one database and runs in its own process at the same
// time as the others, so helpers create uniquely named rows and tests only look
// at rows they created.

const crypto = require('node:crypto');
const path = require('node:path');
const { loadConfig } = require('../../src/config');
const { createDb } = require('../../src/db');
const { createLogger } = require('../../src/lib/logger');
const { encryptSmtpPassword } = require('../../src/lib/secrets');
const appsRepo = require('../../src/repos/apps');
const { searchMessages } = require('../../src/repos/messages');
const { createKey } = require('../../src/services/keys');

const ROOT = path.join(__dirname, '..', '..');
const DB_SKIP_REASON = 'TEST_DB_NAME not set';

// Fixed so that data written by one test file decrypts in every other one.
const TEST_MASTER_KEY_HEX = '5f0c6a2e9b1d4473a8e0c3b7d2f61e94c07ab5d3e8f2a1960b4c7d3e2f1a8b6c';
const TEST_SESSION_SECRET = 'relay-test-session-secret-not-for-production-use';

const SYSTEM_ACTOR = Object.freeze({ id: null, email: 'system', ip: null });

let envLoaded = false;
function loadTestEnv() {
  if (envLoaded) return;
  envLoaded = true;
  // Variables already in the environment win (dotenv never overrides them), so
  // `TEST_DB_NAME=other node --test` points the suite at another database.
  require('dotenv').config({ path: path.join(ROOT, '.env.test'), quiet: true });
}

function dbAvailable() {
  loadTestEnv();
  const name = process.env.TEST_DB_NAME;
  return typeof name === 'string' && name.trim() !== '';
}

// For the first line of a database test: skips it (with the reason) when no
// test database is configured. → true when the test may run.
function requireDb(t) {
  if (dbAvailable()) return true;
  t.skip(DB_SKIP_REASON);
  return false;
}

function testEnv(extra) {
  loadTestEnv();
  const e = process.env;
  const env = {
    NODE_ENV: 'test',
    PUBLIC_BASE_URL: 'http://localhost:3000',
    DB_HOST: e.TEST_DB_HOST || '127.0.0.1',
    DB_PORT: e.TEST_DB_PORT || '3306',
    DB_USER: e.TEST_DB_USER || 'relay_test',
    DB_PASSWORD: e.TEST_DB_PASSWORD || '',
    // Placeholder so unit tests can build a config without a database; nothing
    // connects to it (createTestDeps refuses to run without TEST_DB_NAME).
    DB_NAME: (e.TEST_DB_NAME || '').trim() || 'relay_test_not_configured',
    DB_CONNECTION_LIMIT: '5',
    MASTER_KEY: TEST_MASTER_KEY_HEX,
    SESSION_SECRET: TEST_SESSION_SECRET,
    RELAY_TIMEZONE: 'Asia/Colombo',
    FORCE_HTTPS: 'false',
    COOKIE_SECURE: 'false',
    TRUST_PROXY: '1',
    RATE_LIMIT_IP_PER_MINUTE: '1000000',
    AUTO_MIGRATE: 'false',
    CLEANUP_INTERVAL_MINUTES: '0',
  };
  if (e.TEST_DB_SOCKET) env.DB_SOCKET = e.TEST_DB_SOCKET;
  return { ...env, ...(extra || {}) };
}

// A frozen config built by the real loadConfig. `overrides` holds camelCase
// config keys applied on top; `overrides.env` holds raw environment variables
// for values that loadConfig derives from others (e.g. MAX_MESSAGE_BYTES).
function testConfig(overrides = {}) {
  const { env, ...fields } = overrides || {};
  const base = loadConfig(testEnv(env));
  const config = {
    ...base,
    forceHttps: false,
    cookieSecure: false,
    ipRateLimitPerMinute: 1000000,
    trustProxy: 1,
    production: false,
    ...fields,
  };
  // Camel-case overrides skip loadConfig's checks. Keep the one whose violation
  // would make a test prove something the real relay can never do (a repeated
  // message_id sent twice after its log row was deleted).
  if (config.logRetentionDays < config.idempotencyDays) {
    throw new Error(
      `testConfig: logRetentionDays (${config.logRetentionDays}) must be at least idempotencyDays (${config.idempotencyDays}), as loadConfig requires`
    );
  }
  return Object.freeze(config);
}

// A clock that only moves when told to, so rate-limit windows, grace periods
// and idempotency windows are deterministic.
function createFakeClock(start = new Date()) {
  const toMs = (v) => {
    const ms = v instanceof Date ? v.getTime() : Number(v);
    if (!Number.isFinite(ms)) throw new TypeError('fake clock: invalid time');
    return ms;
  };
  let t = toMs(start);
  return {
    now: () => new Date(t),
    advance(ms) {
      t += toMs(ms);
      return new Date(t);
    },
    set(date) {
      t = toMs(date);
      return new Date(t);
    },
  };
}

// deps as src/server.js builds them, on the test database. Close with
// `await deps.db.close()` in an after() hook. `smtpConnectionFactory(options)`
// replaces `new SMTPConnection(options)` in the mailer.
function createTestDeps({ clock, configOverrides, smtpConnectionFactory } = {}) {
  if (!dbAvailable()) throw new Error(`createTestDeps: ${DB_SKIP_REASON} (configure .env.test)`);
  const config = testConfig(configOverrides);
  const deps = {
    config,
    db: createDb(config.db),
    clock: clock || createFakeClock(),
    // TEST_VERBOSE=1 shows the relay's own log lines while debugging a test.
    logger: createLogger({ silent: !process.env.TEST_VERBOSE }),
  };
  if (smtpConnectionFactory) deps.smtpConnectionFactory = smtpConnectionFactory;
  return deps;
}

function createHttpApp(deps) {
  const mod = require('../../src/app');
  const factory = typeof mod === 'function' ? mod : mod.createApp;
  return factory(deps);
}

// Fake SMTP server (plain text, no auth required). Accepted messages are parsed
// and appended to `messages` before the server answers 250, so they are visible
// as soon as the relay's HTTP response arrives.
//   setFailure(code)        answer DATA with that SMTP code (null = accept again)
//   setStall(true)          hold every DATA reply (after the whole message was
//                           received) until setStall(false)
//   rejectRcpt(addr, code)  answer RCPT TO for that address (case-insensitive)
//                           with `code` (default 550); null code = accept again
//   rcptLog                 every RCPT TO address exactly as the client sent it
//                           (the session envelope folds case-variants together)
async function startSmtpServer() {
  const { SMTPServer } = require('smtp-server');
  const { simpleParser } = require('mailparser');

  const messages = [];
  const held = [];
  const rcptLog = [];
  const rcptFailures = new Map();
  let failureCode = null;
  let stalled = false;

  function failure(code) {
    const text = code >= 500 ? 'Mailbox unavailable (test server)' : 'Try again later (test server)';
    return Object.assign(new Error(text), { responseCode: code });
  }

  const server = new SMTPServer({
    authOptional: true,
    disabledCommands: ['STARTTLS'],
    logger: false,
    closeTimeout: 1000,
    onRcptTo(address, session, callback) {
      rcptLog.push(address.address);
      const code = rcptFailures.get(String(address.address).toLowerCase());
      if (code) return callback(failure(code));
      callback();
    },
    onData(stream, session, callback) {
      const chunks = [];
      stream.on('data', (chunk) => chunks.push(chunk));
      stream.on('end', () => {
        const raw = Buffer.concat(chunks);
        const envelope = {
          mailFrom: session.envelope.mailFrom ? session.envelope.mailFrom.address : null,
          rcptTo: session.envelope.rcptTo.map((r) => r.address),
        };
        const finish = (forcedCode) => {
          const code = forcedCode || failureCode;
          if (code) return callback(failure(code));
          simpleParser(raw).then(
            (parsed) => {
              messages.push({ envelope, raw, parsed });
              callback(null, `Queued as test-${messages.length}`);
            },
            () => callback(failure(451))
          );
        };
        if (stalled) held.push(finish);
        else finish();
      });
    },
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.removeListener('error', reject);
      resolve();
    });
  });
  // Errors on individual connections (a client hanging up) must not crash a test.
  server.on('error', () => {});

  function setStall(on) {
    stalled = Boolean(on);
    if (!stalled) for (const finish of held.splice(0)) finish();
  }

  return {
    port: server.server.address().port,
    messages,
    rcptLog,
    setFailure(code) {
      failureCode = code === null || code === undefined ? null : Number(code);
    },
    rejectRcpt(address, code = 550) {
      const k = String(address).toLowerCase();
      if (code === null || code === undefined) rcptFailures.delete(k);
      else rcptFailures.set(k, Number(code));
    },
    setStall,
    get stalledCount() {
      return held.length;
    },
    // Messages whose envelope includes `address` (case-insensitive).
    messagesTo(address) {
      const want = String(address).toLowerCase();
      return messages.filter((m) => m.envelope.rcptTo.some((r) => r.toLowerCase() === want));
    },
    close() {
      stalled = false;
      for (const finish of held.splice(0)) finish(421);
      return new Promise((resolve) => server.close(() => resolve()));
    },
  };
}

function uniqueId() {
  return crypto.randomBytes(6).toString('hex');
}

function uniqueName(prefix = 'test') {
  return `${prefix}-${uniqueId()}`;
}

function uniqueEmail(local = 'rcpt', domain = 'example.com') {
  return `${local}.${uniqueId()}@${domain}`;
}

// A random private IPv4 address, for X-Forwarded-For when a test exercises a
// per-IP limit (test files run in parallel against one database).
function uniqueIp() {
  const b = crypto.randomBytes(3);
  return `10.${b[0]}.${b[1]}.${1 + (b[2] % 254)}`;
}

// Inserts an app pointing at the fake SMTP server (encryption none, no SMTP
// username) and gives it a key through the real createKey. `overrides` are app
// fields (camelCase, as repos/apps takes them) plus:
//   smtp          the startSmtpServer() result to send through
//   smtpPassword  stored encrypted, as the admin form would
//   withKey       false to create no key
// → { app, key, keyId }
async function insertTestApp(deps, overrides = {}) {
  const { smtp, smtpPassword, withKey = true, ...fields } = overrides;
  const now = deps.clock.now();
  const slug = uniqueId();
  const settings = {
    name: `test-app-${slug}`,
    enabled: true,
    legacySigning: false,
    smtpHost: '127.0.0.1',
    // Nothing listens on port 1: an app given no fake server cannot deliver.
    smtpPort: smtp ? smtp.port : 1,
    smtpEncryption: 'none',
    smtpUsername: '',
    fromEmail: `sender.${slug}@relay-test.example.com`,
    fromName: 'Relay Test App',
    allowedFrom: [],
    replyToDefault: null,
    limitPerMinute: 10000,
    limitPerDay: 1000000,
    maxMessageBytes: deps.config.maxMessageBytes,
    maxRecipients: deps.config.defaultMaxRecipients,
    ipAllowlist: [],
    ...fields,
  };
  const id = await appsRepo.createApp(deps.db, settings, now);
  if (smtpPassword) {
    const smtpPasswordEnc = encryptSmtpPassword(deps.config, { id, ...settings }, smtpPassword);
    await appsRepo.updateApp(deps.db, id, { smtpPasswordEnc }, now);
  }
  let key = null;
  let keyId = null;
  if (withKey) {
    // No retry: test files create keys concurrently, so a lock regression in
    // createKey (see the concurrency tests in keys.test.js) surfaces everywhere.
    const created = await createKey(deps, { appId: id, actor: SYSTEM_ACTOR });
    key = created.key;
    keyId = created.id;
  }
  return { app: await appsRepo.getApp(deps.db, id), key, keyId };
}

// The app's message log rows, oldest first.
async function listMessages(deps, appId) {
  const { rows } = await searchMessages(deps.db, { appId, limit: 1000, offset: 0 });
  return rows.reverse();
}

// POST /v1/send through supertest. `body` may be an object (sent as JSON) or a
// raw string.
function postV1(httpApp, key, body, headers = {}) {
  const request = require('supertest');
  const req = request(httpApp).post('/v1/send').set('Content-Type', 'application/json');
  if (key) req.set('Authorization', `Bearer ${key}`);
  for (const [name, value] of Object.entries(headers)) req.set(name, value);
  return req.send(typeof body === 'string' ? body : JSON.stringify(body));
}

// X-Relay-Signature for /send.php, computed the way the PHP app does it
// (hash_hmac('sha256', $ts . '.' . $body, $apiKey)), independently of the
// relay's own code.
function signLegacy(key, timestampText, rawBody) {
  return (
    'sha256=' +
    crypto.createHmac('sha256', key).update(`${timestampText}.`, 'utf8').update(Buffer.from(rawBody)).digest('hex')
  );
}

// The fake clock's time as the unix-seconds text PHP's time() would send.
function unixTs(deps) {
  return String(Math.floor(deps.clock.now().getTime() / 1000));
}

// A signed POST /send.php with `rawBody` (string or Buffer) sent exactly as given.
//   ts           X-Relay-Timestamp text (default: the fake clock now)
//   signature    overrides the computed signature
//   contentType  null sends no Content-Type
//   headers      extra headers (e.g. X-Forwarded-For)
function postLegacy(httpApp, deps, key, rawBody, { ts = unixTs(deps), signature, contentType = 'application/json', headers = {} } = {}) {
  const request = require('supertest');
  const req = request(httpApp)
    .post('/send.php')
    .set('X-Relay-Timestamp', ts)
    .set('X-Relay-Signature', signature === undefined ? signLegacy(key, ts, rawBody) : signature);
  for (const [name, value] of Object.entries(headers)) req.set(name, value);
  if (contentType) req.set('Content-Type', contentType);
  // The identity serializer sends the bytes as they are (superagent would
  // otherwise JSON- or form-encode a Buffer according to the Content-Type).
  return req.serialize((b) => b).send(Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(rawBody, 'utf8'));
}

// A small but real PDF (passes the %PDF- signature check).
const SAMPLE_PDF = Buffer.from(
  '%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<<>>\n%%EOF\n',
  'latin1'
);

// Polls until `predicate()` is truthy (it may be async). Throws after `timeout` ms.
async function waitFor(predicate, { timeout = 5000, interval = 10, what = 'condition' } = {}) {
  const deadline = Date.now() + timeout;
  for (;;) {
    if (await predicate()) return;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await new Promise((resolve) => setTimeout(resolve, interval));
  }
}

// Base64 of a Buffer or string.
function b64(content) {
  return Buffer.from(content).toString('base64');
}

module.exports = {
  DB_SKIP_REASON,
  SYSTEM_ACTOR,
  dbAvailable,
  requireDb,
  testConfig,
  createTestDeps,
  createFakeClock,
  createHttpApp,
  startSmtpServer,
  insertTestApp,
  listMessages,
  postV1,
  postLegacy,
  signLegacy,
  unixTs,
  SAMPLE_PDF,
  waitFor,
  uniqueId,
  uniqueName,
  uniqueEmail,
  uniqueIp,
  b64,
};
