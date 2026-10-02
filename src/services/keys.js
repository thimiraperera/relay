'use strict';

// API key lifecycle and request authentication.
//
// Every key change runs in a transaction (keyTransaction) that first locks the
// app row, so two admins (or a double-submitted form) cannot both create an
// "active" key.

const { generateApiKey, looksLikeApiKey, hashApiKey } = require('../lib/apiKeys');
const { encryptApiKey, decryptApiKey } = require('../lib/secrets');
const { matchSignatureKeys } = require('../lib/legacySignature');
const { badRequest, conflict, notFound, unauthorized } = require('../lib/errors');
const appsRepo = require('../repos/apps');
const keysRepo = require('../repos/apiKeys');
const { recordAudit } = require('./audit');
const { describeError } = require('../lib/logger');

const GRACE_PERIODS = new Set([0, 3600, 86400]);

const KEY_TX = Object.freeze({ isolation: 'READ COMMITTED' });
const ER_CHECKREAD = 1020;
const ER_LOCK_DEADLOCK = 1213;
const ER_BINLOG_STMT_MODE_AND_ROW_ENGINE = 1665;

// Runs one key change. The app row lock (lockApp, always the first statement
// of fn) is the serialisation point for all key changes of one app; the
// api_keys reads after it are plain reads. READ COMMITTED, because:
// - InnoDB takes no gap locks at READ COMMITTED, so key inserts for different
//   apps never deadlock on api_keys(app_id) gaps (a locking read at REPEATABLE
//   READ did);
// - every statement reads a fresh snapshot taken after the app lock was
//   granted, so it sees every committed change, and an UPDATE of a key whose
//   last_used_at a concurrent request has just touched (touchKeyUsage does not
//   take the app lock) succeeds. At REPEATABLE READ, MariaDB 11.6+ with
//   innodb_snapshot_isolation=ON (its default) fails that UPDATE with
//   ER_CHECKREAD (1020).
// Safety nets, each tried once (fn is rolled back completely, so rerunning it
// is safe; regenerate re-checks the expected key id): a deadlock or
// ER_CHECKREAD reruns it; a server with binlog_format=STATEMENT refuses
// InnoDB writes at READ COMMITTED (1665), so that case reruns at the server's
// default level.
async function keyTransaction(deps, fn) {
  try {
    return await deps.db.transaction(fn, KEY_TX);
  } catch (err) {
    const errno = err && err.errno;
    const retry = errno === ER_BINLOG_STMT_MODE_AND_ROW_ENGINE || errno === ER_LOCK_DEADLOCK || errno === ER_CHECKREAD;
    if (!retry) throw err;
    if (deps.logger) deps.logger.warn('key change retried', { code: err.code, errno });
    return errno === ER_BINLOG_STMT_MODE_AND_ROW_ENGINE ? deps.db.transaction(fn) : deps.db.transaction(fn, KEY_TX);
  }
}

function isValidAt(key, now) {
  return key.revokedAt === null && (key.expiresAt === null || key.expiresAt.getTime() > now.getTime());
}

async function lockApp(tx, appId) {
  const app = await appsRepo.getApp(tx, appId, { forUpdate: true });
  if (!app) throw notFound('app not found');
  return app;
}

function actorId(actor) {
  return actor && actor.id !== undefined ? actor.id : null;
}

// Legacy-signing apps need the plain key to verify HMAC signatures, so their keys
// are stored encrypted; all other keys are stored only as a hash.
async function insertNewKey(deps, tx, app, actor, now) {
  const { key, prefix, hash } = generateApiKey();
  const id = await keysRepo.insertKey(tx, {
    appId: app.id,
    prefix,
    keyHash: app.legacySigning ? null : hash,
    keyEnc: app.legacySigning ? encryptApiKey(deps.config, app.id, key) : null,
    createdBy: actorId(actor),
    now,
  });
  return { id, key, prefix };
}

// The reads after lockApp are plain reads on purpose; see keyTransaction.
async function createKey(deps, { appId, actor }) {
  const now = deps.clock.now();
  return keyTransaction(deps, async (tx) => {
    const app = await lockApp(tx, appId);
    const active = await keysRepo.listActiveKeys(tx, app.id, now);
    if (active.length) throw conflict('app already has an active key');
    const created = await insertNewKey(deps, tx, app, actor, now);
    await recordAudit(
      tx,
      actor,
      'key.create',
      { targetType: 'app', targetId: app.id, details: { keyId: created.id, prefix: created.prefix } },
      now
    );
    return created;
  });
}

function parseGrace(v) {
  let n = null;
  if (typeof v === 'number') n = v;
  else if (typeof v === 'string' && /^\d{1,6}$/.test(v.trim())) n = Number(v.trim());
  if (n === null || !GRACE_PERIODS.has(n)) throw badRequest('invalid grace period');
  return n;
}

// null/undefined/'' mean "the page saw no active key".
function parseExpectedKeyId(v) {
  if (v === null || v === undefined || v === '') return null;
  if (typeof v === 'number') return v;
  const s = String(v).trim();
  return /^\d+$/.test(s) ? Number(s) : NaN;
}

async function regenerateKey(deps, { appId, graceSeconds, expectedActiveKeyId, actor }) {
  const grace = parseGrace(graceSeconds);
  const expected = parseExpectedKeyId(expectedActiveKeyId);
  const now = deps.clock.now();
  const graceEnd = new Date(now.getTime() + grace * 1000);

  return keyTransaction(deps, async (tx) => {
    const app = await lockApp(tx, appId);
    // Plain read after the app row lock; see keyTransaction for why not FOR UPDATE.
    const active = await keysRepo.listActiveKeys(tx, app.id, now);
    const currentId = active.length ? active[0].id : null;
    // Protects against a refreshed/re-submitted form regenerating a second time.
    if (currentId !== expected) throw conflict('keys changed since the page was loaded; reload and try again');

    const graceKeys = await keysRepo.listGraceKeys(tx, app.id, now);
    const oldPrefixes = [];
    for (const key of active) {
      if (grace === 0) await keysRepo.revokeKey(tx, key.id, now);
      else await keysRepo.setKeyExpiry(tx, key.id, graceEnd);
      oldPrefixes.push(key.prefix);
    }
    // Older grace keys never outlive the new grace period.
    for (const key of graceKeys) {
      if (grace === 0) {
        await keysRepo.revokeKey(tx, key.id, now);
        oldPrefixes.push(key.prefix);
      } else if (key.expiresAt.getTime() > graceEnd.getTime()) {
        await keysRepo.setKeyExpiry(tx, key.id, graceEnd);
        oldPrefixes.push(key.prefix);
      }
    }

    const created = await insertNewKey(deps, tx, app, actor, now);
    await recordAudit(
      tx,
      actor,
      'key.regenerate',
      {
        targetType: 'app',
        targetId: app.id,
        details: { keyId: created.id, prefix: created.prefix, oldPrefixes, graceSeconds: grace },
      },
      now
    );
    return created;
  });
}

// Returns true when the key was revoked now, false if it already was.
async function revokeKey(deps, { appId, keyId, actor }) {
  const now = deps.clock.now();
  return keyTransaction(deps, async (tx) => {
    const app = await lockApp(tx, appId);
    const key = await keysRepo.getKey(tx, keyId);
    if (!key || key.appId !== app.id) throw notFound('key not found');
    const changed = (await keysRepo.revokeKey(tx, key.id, now)) === 1;
    if (changed) {
      await recordAudit(
        tx,
        actor,
        'key.revoke',
        { targetType: 'app', targetId: app.id, details: { keyId: key.id, prefix: key.prefix } },
        now
      );
    }
    return changed;
  });
}

// Runs on the caller's transaction; the caller already holds the app row lock.
async function revokeAllKeys(deps, tx, { appId, actor, reason }) {
  const now = deps.clock.now();
  const count = await keysRepo.revokeAllKeysForApp(tx, appId, now);
  await recordAudit(
    tx,
    actor,
    'key.revoke_all',
    { targetType: 'app', targetId: appId, details: { reason: reason === undefined ? null : reason, count } },
    now
  );
  return count;
}

const BEARER = /^Bearer[ \t]+(\S+)[ \t]*$/i;

// { app, apiKey } for a valid, non-legacy key; null otherwise. Enabled state and
// IP allowlist are checked by the send pipeline.
async function authenticateBearer(deps, authorizationHeader) {
  if (typeof authorizationHeader !== 'string') return null;
  const m = BEARER.exec(authorizationHeader.trim());
  if (!m || !looksLikeApiKey(m[1])) return null;
  const apiKey = await keysRepo.findKeyByHash(deps.db, hashApiKey(m[1]));
  if (!apiKey || !apiKey.keyHash) return null;
  if (!isValidAt(apiKey, deps.clock.now())) return null;
  const app = await appsRepo.getApp(deps.db, apiKey.appId);
  if (!app || app.legacySigning) return null;
  return { app, apiKey };
}

// Identifies the app behind a /send.php request by checking the signature
// against every currently valid legacy key. Every candidate is decrypted and
// compared (no early exit), so the response time does not reveal which app or
// how many keys matched. The HMACs run off the main thread (matchSignatureKeys),
// so a large forged body no longer stalls every other request while it is hashed.
async function authenticateLegacy(deps, { timestamp, sigBuf, rawBody }) {
  if (!timestamp || typeof timestamp.text !== 'string' || !Buffer.isBuffer(sigBuf)) {
    throw unauthorized('invalid signature');
  }
  if (!Buffer.isBuffer(rawBody)) throw new TypeError('authenticateLegacy: rawBody must be a Buffer');
  const now = deps.clock.now();
  const candidates = await keysRepo.listValidLegacyKeys(deps.db, now);
  const usable = [];
  const plainKeys = [];
  for (const c of candidates) {
    try {
      plainKeys.push(decryptApiKey(deps.config, c.appId, c.keyEnc));
      usable.push(c);
    } catch {
      deps.logger.warn('legacy api key could not be decrypted', { keyId: c.id, appId: c.appId });
    }
  }
  const matches = await matchSignatureKeys(plainKeys, timestamp.text, rawBody, sigBuf);
  // The first matching key in listing order, as before.
  const match = usable[matches.indexOf(true)] || null;
  if (!match) throw unauthorized('invalid signature');

  const [app, apiKey] = await Promise.all([appsRepo.getApp(deps.db, match.appId), keysRepo.getKey(deps.db, match.id)]);
  if (!app || !app.legacySigning || !apiKey) throw unauthorized('invalid signature');
  return { app, apiKey };
}

// Best effort: never rejects (callers fire and forget).
async function touchKeyUsage(deps, { appId, keyId }) {
  try {
    const now = deps.clock.now();
    await keysRepo.touchKeyLastUsed(deps.db, keyId, now);
    await appsRepo.touchAppLastUsed(deps.db, appId, now);
  } catch (err) {
    try {
      deps.logger.warn('could not record key usage', { appId, keyId, error: describeError(err) });
    } catch {
      // logging must not turn a best-effort update into an unhandled rejection
    }
  }
}

module.exports = {
  createKey,
  regenerateKey,
  revokeKey,
  revokeAllKeys,
  authenticateBearer,
  authenticateLegacy,
  touchKeyUsage,
  GRACE_PERIODS,
};
