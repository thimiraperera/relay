'use strict';

// Admin accounts: bcrypt passwords, optional TOTP two-factor, enable/disable and
// the bootstrap admin from .env. Every change is audited. Changes that must end
// the admin's other sessions bump admin_users.session_epoch (requireAdmin drops
// sessions from an older epoch); those functions return the new epoch so the
// acting admin's own session can be re-issued.

const bcrypt = require('bcryptjs');
const { badRequest, conflict, notFound } = require('../lib/errors');
const { isValidEmail } = require('../lib/addresses');
const { stripCrlf } = require('../lib/headers');
const { encryptTotpSecret, decryptTotpSecret } = require('../lib/secrets');
const { generateSecret, verifyTotp } = require('../lib/totp');
const { isDuplicateKeyError } = require('../db');
const repo = require('../repos/admins');
const { recordAudit, SYSTEM_ACTOR } = require('./audit');
const { hitWindow, peekWindow } = require('./rateLimit');

const BCRYPT_COST = 12;
const MIN_PASSWORD_CHARS = 12;
const MAX_PASSWORD_BYTES = 72;
const MAX_EMAIL_CHARS = 191;
const MAX_NAME_CHARS = 100;
const REAUTH_LIMIT = 10;
const REAUTH_WINDOW_SECONDS = 15 * 60;
const MAX_CONCURRENT_BCRYPT = 2;
const MAX_CONCURRENT_REAUTH_BCRYPT = 2;

const THROTTLED = 'Too many attempts. Try again later.';

// A cost-12 hash of a random string nobody knows. Comparing against it takes as
// long as a real check, so a login for an unknown email is not measurably faster.
const DUMMY_HASH = '$2b$12$ZZiGCP7j2guYWjlKUNtgcuIO6v5ScW4Rqm72csJaZnPxxN9z8P/P.';

const TOTP_CODE_INVALID = 'That code is not valid. Check that the time on your device is correct and try again.';
const TOTP_RESTART = 'Start the two-factor setup again.';

function hashPassword(password) {
  return bcrypt.hash(password, BCRYPT_COST);
}

// bcryptjs rejects non-string input; treat that (and malformed hashes) as a mismatch.
async function verifyPassword(password, hash) {
  if (typeof password !== 'string' || typeof hash !== 'string' || hash === '') return false;
  try {
    return await bcrypt.compare(password, hash);
  } catch {
    return false;
  }
}

// Burns the same CPU time as verifyPassword; always false.
async function dummyVerify(password) {
  await verifyPassword(typeof password === 'string' ? password : '', DUMMY_HASH);
  return false;
}

// bcryptjs runs on the main thread (about 100 ms slices, ~400 ms per compare),
// so a burst of password checks would stall /v1/send for everyone. A gate lets
// at most `max` compares run at once per process: (fn) → { busy: true } when
// they are all taken, else { busy: false, value }.
function createCompareGate(max) {
  let active = 0;
  return async function withSlot(fn) {
    if (active >= max) return { busy: true, value: undefined };
    active++;
    try {
      return { busy: false, value: await fn() };
    } finally {
      active--;
    }
  };
}

// Sign-in (anonymous, so a flood of guesses can fill it) and re-authentication
// (signed-in admins only) have separate gates, so sign-in attempts in progress
// never refuse an admin's correct current password.
const withCompareSlot = createCompareGate(MAX_CONCURRENT_BCRYPT);
const withReauthCompareSlot = createCompareGate(MAX_CONCURRENT_REAUTH_BCRYPT);

// → error message, or null when acceptable. bcrypt ignores bytes after 72, so a
// longer password would silently be truncated.
function validatePassword(password) {
  if (typeof password !== 'string' || password === '') return 'Enter a password.';
  if (Array.from(password).length < MIN_PASSWORD_CHARS) {
    return `Password must be at least ${MIN_PASSWORD_CHARS} characters.`;
  }
  if (Buffer.byteLength(password, 'utf8') > MAX_PASSWORD_BYTES) {
    return `Password must be at most ${MAX_PASSWORD_BYTES} bytes (fewer characters if it uses accents or symbols).`;
  }
  return null;
}

function normalizeEmail(email) {
  return typeof email === 'string' ? email.trim().toLowerCase() : '';
}

function isValidAdminEmail(email) {
  return email.length <= MAX_EMAIL_CHARS && isValidEmail(email);
}

function cleanName(name) {
  const clean = stripCrlf(typeof name === 'string' ? name : '');
  if (Array.from(clean).length > MAX_NAME_CHARS) throw badRequest(`Name must be at most ${MAX_NAME_CHARS} characters.`);
  return clean;
}

// Authenticator apps show codes as "123 456"; people paste them that way.
function normalizeTotpCode(code) {
  return typeof code === 'string' ? code.replace(/\s+/g, '') : '';
}

async function lockAdmin(tx, adminId) {
  const admin = await repo.getAdmin(tx, adminId, { forUpdate: true });
  if (!admin) throw notFound('Admin not found.');
  return admin;
}

function adminTarget(admin, details) {
  return { targetType: 'admin', targetId: admin.id, details: { email: admin.email, ...details } };
}

// Creates the ADMIN_BOOTSTRAP_EMAIL admin when the table is empty.
// → 'created' | 'exists' (some admin already exists) | 'skipped' (not configured) | 'invalid'
async function ensureBootstrapAdmin(deps) {
  const boot = deps.config.bootstrapAdmin;
  if (!boot) return 'skipped';
  if ((await repo.countAdmins(deps.db)) > 0) return 'exists';
  const email = normalizeEmail(boot.email);
  if (!isValidAdminEmail(email)) {
    deps.logger.error('ADMIN_BOOTSTRAP_EMAIL is not a valid email address; bootstrap admin not created');
    return 'invalid';
  }
  if (validatePassword(boot.password)) {
    deps.logger.error('ADMIN_BOOTSTRAP_PASSWORD does not meet the password rules; bootstrap admin not created');
    return 'invalid';
  }
  const passwordHash = await hashPassword(boot.password);
  const now = deps.clock.now();
  try {
    return await deps.db.transaction(async (tx) => {
      // Several workers can start at once; the unique email index settles races.
      if ((await repo.countAdmins(tx)) > 0) return 'exists';
      const id = await repo.createAdmin(tx, { email, name: '', passwordHash, now });
      await recordAudit(tx, SYSTEM_ACTOR, 'admin.bootstrap', { targetType: 'admin', targetId: id, details: { email } }, now);
      return 'created';
    });
  } catch (err) {
    if (isDuplicateKeyError(err)) return 'exists';
    throw err;
  }
}

// → new admin id. Throws HttpError (400/409) with a message fit to show the user.
async function createAdmin(deps, { email, name, password, actor }) {
  const addr = normalizeEmail(email);
  if (!isValidAdminEmail(addr)) throw badRequest('Enter a valid email address.');
  const displayName = cleanName(name);
  const pwError = validatePassword(password);
  if (pwError) throw badRequest(pwError);
  if (await repo.getAdminByEmail(deps.db, addr)) throw conflict('An admin with that email address already exists.');

  const passwordHash = await hashPassword(password);
  const now = deps.clock.now();
  try {
    return await deps.db.transaction(async (tx) => {
      const id = await repo.createAdmin(tx, { email: addr, name: displayName, passwordHash, now });
      await recordAudit(
        tx,
        actor,
        'admin.create',
        { targetType: 'admin', targetId: id, details: { email: addr, name: displayName } },
        now
      );
      return id;
    });
  } catch (err) {
    if (isDuplicateKeyError(err)) throw conflict('An admin with that email address already exists.');
    throw err;
  }
}

// → true when the name changed.
async function setName(deps, { adminId, name, actor }) {
  const displayName = cleanName(name);
  const now = deps.clock.now();
  return deps.db.transaction(async (tx) => {
    const admin = await lockAdmin(tx, adminId);
    if (admin.name === displayName) return false;
    await repo.updateAdmin(tx, admin.id, { name: displayName }, now);
    await recordAudit(tx, actor, 'admin.update', adminTarget(admin, { name: { from: admin.name, to: displayName } }), now);
    return true;
  });
}

// Own change (reset = false) or another admin's reset (reset = true). Ends every
// session of that admin. → new session epoch.
async function setPassword(deps, { adminId, password, actor, reset = false }) {
  const pwError = validatePassword(password);
  if (pwError) throw badRequest(pwError);
  const passwordHash = await hashPassword(password);
  const now = deps.clock.now();
  return deps.db.transaction(async (tx) => {
    const admin = await lockAdmin(tx, adminId);
    await repo.updateAdmin(tx, admin.id, { passwordHash }, now);
    const epoch = await repo.bumpSessionEpoch(tx, admin.id, now);
    await recordAudit(
      tx,
      actor,
      reset ? 'admin.password_reset' : 'admin.password_change',
      adminTarget(admin, { password: '[changed]' }),
      now
    );
    return epoch;
  });
}

// Stores a fresh secret (encrypted, not yet enabled) and returns it for the QR
// code. Allowed only while two-factor is off; repeating it replaces the secret.
async function beginTotpSetup(deps, { adminId, actor }) {
  const now = deps.clock.now();
  return deps.db.transaction(async (tx) => {
    const admin = await lockAdmin(tx, adminId);
    if (admin.totpEnabled) throw conflict('Two-factor authentication is already on.');
    const secret = generateSecret();
    await repo.updateAdmin(
      tx,
      admin.id,
      { totpSecretEnc: encryptTotpSecret(deps.config, admin.id, secret), totpEnabled: false, totpLastStep: null },
      now
    );
    await recordAudit(tx, actor, 'admin.totp_setup', adminTarget(admin, { totpSecret: '[changed]' }), now);
    return secret;
  });
}

// Turns two-factor on once the admin proves their app produces valid codes. The
// accepted step is recorded so the same code cannot then be used to sign in.
// Ends the admin's other sessions. → new session epoch.
async function enableTotp(deps, { adminId, code, actor }) {
  const now = deps.clock.now();
  return deps.db.transaction(async (tx) => {
    const admin = await lockAdmin(tx, adminId);
    if (admin.totpEnabled) throw conflict('Two-factor authentication is already on.');
    if (!admin.totpSecretEnc) throw badRequest(TOTP_RESTART);
    let secret;
    try {
      secret = decryptTotpSecret(deps.config, admin.id, admin.totpSecretEnc);
    } catch {
      throw badRequest(TOTP_RESTART);
    }
    const result = verifyTotp(secret, normalizeTotpCode(code), now.getTime(), {
      window: 1,
      lastStep: admin.totpLastStep,
    });
    if (!result.ok) throw badRequest(TOTP_CODE_INVALID);
    await repo.updateAdmin(tx, admin.id, { totpEnabled: true, totpLastStep: result.step }, now);
    const epoch = await repo.bumpSessionEpoch(tx, admin.id, now);
    await recordAudit(tx, actor, 'admin.totp_enable', adminTarget(admin, { totpEnabled: { from: false, to: true } }), now);
    return epoch;
  });
}

// Clears the secret and ends the admin's sessions. → new session epoch.
async function disableTotp(deps, { adminId, actor }) {
  const now = deps.clock.now();
  return deps.db.transaction(async (tx) => {
    const admin = await lockAdmin(tx, adminId);
    await repo.updateAdmin(tx, admin.id, { totpSecretEnc: null, totpEnabled: false, totpLastStep: null }, now);
    const epoch = await repo.bumpSessionEpoch(tx, admin.id, now);
    await recordAudit(
      tx,
      actor,
      'admin.totp_disable',
      adminTarget(admin, { totpEnabled: { from: admin.totpEnabled, to: false } }),
      now
    );
    return epoch;
  });
}

// → true when the state changed. Refuses to disable the acting admin or the
// last enabled admin; disabling ends the target's sessions.
async function setDisabled(deps, { adminId, disabled, actor }) {
  const want = Boolean(disabled);
  const now = deps.clock.now();
  return deps.db.transaction(async (tx) => {
    // Locks every admin row, so two admins disabling each other at the same
    // moment cannot leave nobody able to sign in.
    const admins = await repo.listAdmins(tx, { forUpdate: true });
    const target = admins.find((a) => a.id === Number(adminId));
    if (!target) throw notFound('Admin not found.');
    if (target.disabled === want) return false;
    if (want) {
      if (actor && actor.id === target.id) throw badRequest('You cannot disable your own account.');
      if (admins.filter((a) => !a.disabled).length <= 1) {
        throw conflict('You cannot disable the last enabled admin.');
      }
    }
    await repo.updateAdmin(tx, target.id, { disabled: want }, now);
    await repo.bumpSessionEpoch(tx, target.id, now);
    await recordAudit(
      tx,
      actor,
      want ? 'admin.disable' : 'admin.enable',
      adminTarget(target, { disabled: { from: target.disabled, to: want } }),
      now
    );
    return true;
  });
}

// adminId → the tail of that admin's re-authentication queue in this process.
// Entries are removed once their queue is empty.
const reauthQueues = new Map();

// Runs fn after every earlier re-authentication of the same admin in this
// process has finished (whatever its outcome); → fn's promise.
function queueReauth(adminId, fn) {
  const previous = reauthQueues.get(adminId) || Promise.resolve();
  const run = previous.then(fn);
  const tail = run.then(
    () => {},
    () => {}
  );
  reauthQueues.set(adminId, tail);
  tail.then(() => {
    if (reauthQueues.get(adminId) === tail) reauthQueues.delete(adminId);
  });
  return run;
}

// Checks the acting admin's current password before a sensitive change, so a
// stolen session cannot be used to guess it: at most REAUTH_LIMIT (10) wrong
// passwords per admin per 15 minutes, counted in `reauth:<adminId>` (an atomic
// database counter shared by every process). Only failures use up the budget,
// so correct passwords never lock an admin out of their own changes:
// - the window is peeked before the compare and hit only after a wrong
//   password. One admin's re-authentications run one at a time in a process
//   (queueReauth), so concurrent wrong guesses cannot all pass the same peek.
//   Across P processes at most REAUTH_LIMIT + P - 1 passwords are checked per
//   window (P compares can pass a peek at REAUTH_LIMIT - 1 at the same time).
// - a refused attempt is counted too (no compare runs); the event that takes the
//   count to REAUTH_LIMIT + 1 opens the throttle episode and is audited
//   (auth.reauth_throttled), exactly once per window. Wrong passwords are
//   audited as auth.reauth_failed.
// - the compare runs in its own bcrypt gate, so sign-ins in progress (their
//   gate can be kept full by anonymous guessing) never refuse it. A busy gate is
//   refused without counting, since nothing was checked.
// `actor` is req.actor (falls back to the admin without an IP).
// → error message, or null when the password is correct.
async function reauthenticate(deps, admin, password, actor) {
  // Blank submissions are not counted: they cannot guess anything.
  if (typeof password !== 'string' || password === '') return 'Enter your current password.';
  const who = actor || { id: admin.id, email: admin.email, ip: null };
  const key = `reauth:${admin.id}`;
  const auditThrottledAt = async (count) => {
    if (count === REAUTH_LIMIT + 1) {
      await recordAudit(deps.db, who, 'auth.reauth_throttled', adminTarget(admin, {}), deps.clock.now());
    }
  };
  return queueReauth(admin.id, async () => {
    const budget = await peekWindow(deps, key, REAUTH_LIMIT, REAUTH_WINDOW_SECONDS);
    if (!budget.allowed) {
      const refused = await hitWindow(deps, key, REAUTH_LIMIT, REAUTH_WINDOW_SECONDS);
      await auditThrottledAt(refused.count);
      return THROTTLED;
    }
    const check = await withReauthCompareSlot(() => verifyPassword(password, admin.passwordHash));
    if (check.busy) return THROTTLED;
    if (check.value) return null;
    const failure = await hitWindow(deps, key, REAUTH_LIMIT, REAUTH_WINDOW_SECONDS);
    await recordAudit(deps.db, who, 'auth.reauth_failed', adminTarget(admin, {}), deps.clock.now());
    // limit + 1 here only when another process's failure got in between.
    await auditThrottledAt(failure.count);
    return 'Your current password is not correct.';
  });
}

module.exports = {
  hashPassword,
  verifyPassword,
  dummyVerify,
  validatePassword,
  normalizeEmail,
  isValidAdminEmail,
  normalizeTotpCode,
  ensureBootstrapAdmin,
  createAdmin,
  setName,
  setPassword,
  beginTotpSetup,
  enableTotp,
  disableTotp,
  setDisabled,
  reauthenticate,
  withCompareSlot,
  withReauthCompareSlot,
  BCRYPT_COST,
  MIN_PASSWORD_CHARS,
  MAX_CONCURRENT_BCRYPT,
  MAX_CONCURRENT_REAUTH_BCRYPT,
  REAUTH_LIMIT,
};
