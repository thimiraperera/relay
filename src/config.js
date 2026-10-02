'use strict';

// Loads and validates configuration from environment variables and an optional
// .env file in the app root. Values already present in process.env win over the
// .env file. On cPanel, keep everything in .env (see README) so the web app,
// cron jobs, SSH and "Run JS script" all see the same settings.

const net = require('node:net');
const path = require('node:path');

const ENV_FILE = path.join(__dirname, '..', '.env');

// Returns { path, code } describing why .env could not be read, or null. A
// missing/misnamed .env otherwise just looks like "DB_USER is required ...".
let dotenvStatus;
function loadDotenv() {
  if (dotenvStatus !== undefined) return dotenvStatus;
  dotenvStatus = null;
  try {
    const result = require('dotenv').config({ path: ENV_FILE, quiet: true });
    if (result && result.error) dotenvStatus = { path: ENV_FILE, code: result.error.code || 'EREAD' };
  } catch (err) {
    if (err && err.code !== 'MODULE_NOT_FOUND') throw err;
  }
  return dotenvStatus;
}

class ConfigError extends Error {
  constructor(problems) {
    super('Invalid configuration:\n  - ' + problems.join('\n  - '));
    this.name = 'ConfigError';
    this.problems = problems;
  }
}

function str(env, name, def) {
  const v = env[name];
  if (v === undefined || v === null) return def;
  const t = String(v).trim();
  return t === '' ? def : t;
}

function int(env, name, def, problems, { min = -Infinity, max = Infinity } = {}) {
  const raw = str(env, name, undefined);
  if (raw === undefined) return def;
  if (!/^-?\d+$/.test(raw)) {
    problems.push(`${name} must be an integer`);
    return def;
  }
  const n = Number(raw);
  if (n < min || n > max) {
    problems.push(`${name} must be between ${min} and ${max}`);
    return def;
  }
  return n;
}

function bool(env, name, def, problems) {
  const raw = str(env, name, undefined);
  if (raw === undefined) return def;
  const v = raw.toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(v)) return true;
  if (['0', 'false', 'no', 'off'].includes(v)) return false;
  problems.push(`${name} must be true or false`);
  return def;
}

// A master key is 32 random bytes, given as 64 hex characters or base64 (44 chars).
function parseMasterKey(raw, name, problems, { required = true } = {}) {
  if (!raw) {
    if (required) {
      problems.push(`${name} is required (32 random bytes as 64 hex chars or base64); run \`npm run gen-secrets\``);
    }
    return null;
  }
  let buf = null;
  if (/^[0-9a-fA-F]{64}$/.test(raw)) buf = Buffer.from(raw, 'hex');
  else if (/^[A-Za-z0-9+/]{43}=?$/.test(raw) || /^[A-Za-z0-9_-]{43}$/.test(raw)) {
    buf = Buffer.from(raw.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  }
  if (!buf || buf.length !== 32) {
    problems.push(`${name} must decode to exactly 32 bytes (64 hex chars or base64)`);
    return null;
  }
  return buf;
}

const TRUST_PROXY_NAMES = new Set(['loopback', 'linklocal', 'uniquelocal']);

function isIpOrCidr(entry) {
  const [ip, bits, extra] = entry.split('/');
  if (extra !== undefined) return false;
  const family = net.isIP(ip);
  if (!family) return false;
  if (bits === undefined) return true;
  if (!/^\d{1,3}$/.test(bits)) return false;
  return Number(bits) <= (family === 4 ? 32 : 128);
}

// TRUST_PROXY follows Express "trust proxy" semantics: a hop count ("1", the
// right value behind cPanel's LiteSpeed/Passenger), or a comma-separated list of
// addresses/subnets/names. "true" trusts any client-supplied X-Forwarded-For and
// is refused in production because it makes IP allowlists and limits spoofable.
function parseTrustProxy(raw, production, problems) {
  if (raw === undefined) return 1;
  const v = raw.toLowerCase();
  if (v === 'true') {
    if (production) problems.push('TRUST_PROXY=true is unsafe (client IPs become spoofable); use a hop count such as 1');
    return true;
  }
  if (v === 'false') return false;
  if (/^\d+$/.test(v)) return Number(v);
  const entries = raw.split(',').map((s) => s.trim()).filter(Boolean);
  for (const e of entries) {
    if (!TRUST_PROXY_NAMES.has(e.toLowerCase()) && !isIpOrCidr(e)) {
      problems.push(`TRUST_PROXY entry "${e}" is not an IP, CIDR, loopback, linklocal or uniquelocal`);
    }
  }
  return entries;
}

function validTimezone(tz) {
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: tz }).format(new Date(0));
    return true;
  } catch {
    return false;
  }
}

function loadConfig(env) {
  let envFileProblem = null;
  if (env === undefined) {
    envFileProblem = loadDotenv();
    env = process.env;
  }
  const problems = [];
  const nodeEnv = str(env, 'NODE_ENV', 'production');
  const production = nodeEnv === 'production';

  const forceHttps = bool(env, 'FORCE_HTTPS', production, problems);

  const publicBaseUrl = str(env, 'PUBLIC_BASE_URL', production ? undefined : 'http://localhost:3000');
  if (!publicBaseUrl) {
    problems.push('PUBLIC_BASE_URL is required, e.g. https://relay.companysite.site');
  } else if (!/^https?:\/\/[^/\s?#]+$/.test(publicBaseUrl.replace(/\/+$/, ''))) {
    problems.push('PUBLIC_BASE_URL must look like https://relay.example.com (no path)');
  } else if (production && forceHttps && !publicBaseUrl.startsWith('https://')) {
    problems.push('PUBLIC_BASE_URL must start with https:// when FORCE_HTTPS is on');
  }

  const db = {
    host: str(env, 'DB_HOST', 'localhost'),
    port: int(env, 'DB_PORT', 3306, problems, { min: 1, max: 65535 }),
    socketPath: str(env, 'DB_SOCKET', undefined),
    user: str(env, 'DB_USER', undefined),
    password: str(env, 'DB_PASSWORD', ''),
    database: str(env, 'DB_NAME', undefined),
    // At least 2: db.withNamedLock holds one connection for the lock while the
    // migration/cleanup/rotation queries run on another; with 1 they wait forever.
    connectionLimit: int(env, 'DB_CONNECTION_LIMIT', 5, problems, { min: 2, max: 50 }),
  };
  if (!db.user) problems.push('DB_USER is required');
  if (!db.database) problems.push('DB_NAME is required');

  const masterKey = parseMasterKey(str(env, 'MASTER_KEY', undefined), 'MASTER_KEY', problems);
  const masterKeyPrevious = parseMasterKey(str(env, 'MASTER_KEY_PREVIOUS', undefined), 'MASTER_KEY_PREVIOUS', problems, {
    required: false,
  });

  const sessionSecret = str(env, 'SESSION_SECRET', undefined);
  if (!sessionSecret || sessionSecret.length < 32) {
    problems.push('SESSION_SECRET is required and must be at least 32 characters; run `npm run gen-secrets`');
  }

  const bootstrapEmail = str(env, 'ADMIN_BOOTSTRAP_EMAIL', undefined);
  const bootstrapPassword = str(env, 'ADMIN_BOOTSTRAP_PASSWORD', undefined);
  let bootstrapAdmin = null;
  if (bootstrapEmail || bootstrapPassword) {
    if (!bootstrapEmail || !bootstrapPassword) {
      problems.push('ADMIN_BOOTSTRAP_EMAIL and ADMIN_BOOTSTRAP_PASSWORD must be set together');
    } else if (bootstrapPassword.length < 12) {
      problems.push('ADMIN_BOOTSTRAP_PASSWORD must be at least 12 characters');
    } else if (Buffer.byteLength(bootstrapPassword, 'utf8') > 72) {
      problems.push('ADMIN_BOOTSTRAP_PASSWORD must be at most 72 bytes (bcrypt limit)');
    } else {
      bootstrapAdmin = { email: bootstrapEmail.toLowerCase(), password: bootstrapPassword };
    }
  }

  const timezone = str(env, 'RELAY_TIMEZONE', 'Asia/Colombo');
  if (!validTimezone(timezone)) problems.push(`RELAY_TIMEZONE "${timezone}" is not a valid IANA time zone`);

  const maxMessageBytes = int(env, 'MAX_MESSAGE_BYTES', 10 * 1024 * 1024, problems, {
    min: 1024,
    max: 25 * 1024 * 1024,
  });

  const smtpTimeoutMs = int(env, 'SMTP_TIMEOUT_MS', 30000, problems, { min: 1000, max: 120000 });

  const cfg = {
    nodeEnv,
    production,
    port: int(env, 'PORT', 3000, problems, { min: 1, max: 65535 }),
    publicBaseUrl: publicBaseUrl ? publicBaseUrl.replace(/\/+$/, '') : '',
    db,
    masterKey,
    masterKeyPrevious,
    sessionSecret,
    bootstrapAdmin,
    timezone,
    trustProxy: parseTrustProxy(str(env, 'TRUST_PROXY', undefined), production, problems),
    forceHttps,
    cookieSecure: bool(env, 'COOKIE_SECURE', production, problems),
    logFile: str(env, 'LOG_FILE', undefined),
    // Per SMTP phase (connect, greeting, socket inactivity); DNS uses min(this, 5 s).
    smtpTimeoutMs,
    // Hard ceiling for one SMTP send, kept below the web server's proxy timeout.
    smtpSendDeadlineMs: int(env, 'SMTP_SEND_DEADLINE_MS', 50000, problems, { min: 5000, max: 300000 }),
    // Global cap for any app's max_message_bytes (decoded html + text + attachments).
    maxMessageBytes,
    // Raw request limit: base64 adds 4/3, PHP json_encode escapes "/" (+~2%), plus
    // room for the JSON envelope and the HTML.
    bodyLimitBytes: Math.ceil(maxMessageBytes * 1.4) + 1024 * 1024,
    ipRateLimitPerMinute: int(env, 'RATE_LIMIT_IP_PER_MINUTE', 120, problems, { min: 1, max: 1000000 }),
    defaultMaxRecipients: int(env, 'DEFAULT_MAX_RECIPIENTS', 50, problems, { min: 1, max: 1000 }),
    logRetentionDays: int(env, 'LOG_RETENTION_DAYS', 90, problems, { min: 1, max: 3650 }),
    idempotencyDays: int(env, 'IDEMPOTENCY_DAYS', 7, problems, { min: 1, max: 90 }),
    legacyMaxSkewSeconds: int(env, 'LEGACY_MAX_SKEW_SECONDS', 300, problems, { min: 30, max: 3600 }),
    sessionIdleMinutes: int(env, 'SESSION_IDLE_MINUTES', 120, problems, { min: 5, max: 7 * 24 * 60 }),
    sessionAbsoluteHours: int(env, 'SESSION_ABSOLUTE_HOURS', 12, problems, { min: 1, max: 24 * 30 }),
    autoMigrate: bool(env, 'AUTO_MIGRATE', false, problems),
    cleanupIntervalMinutes: int(env, 'CLEANUP_INTERVAL_MINUTES', 360, problems, { min: 0, max: 7 * 24 * 60 }),
    // A message still 'sending' after this long had its process die mid-send; its
    // outcome is unknown and cleanup marks it 'unknown' (the message_id stays locked).
    staleSendingMs: 10 * 60 * 1000,
  };

  if (cfg.smtpSendDeadlineMs >= cfg.staleSendingMs) {
    problems.push('SMTP_SEND_DEADLINE_MS must be below 10 minutes');
  }
  // Idempotency rows point at message rows; if the log is purged first, a repeated
  // message_id could no longer be matched to its first result.
  if (cfg.logRetentionDays < cfg.idempotencyDays) {
    problems.push(
      `LOG_RETENTION_DAYS (${cfg.logRetentionDays}) must be at least IDEMPOTENCY_DAYS (${cfg.idempotencyDays})`
    );
  }

  if (envFileProblem && (envFileProblem.code !== 'ENOENT' || problems.length)) {
    problems.unshift(`could not read ${envFileProblem.path} (${envFileProblem.code}); settings come only from the environment`);
  }

  if (problems.length) throw new ConfigError(problems);
  return Object.freeze(cfg);
}

module.exports = { loadConfig, ConfigError, parseMasterKey, parseTrustProxy, ENV_FILE };
