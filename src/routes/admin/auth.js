'use strict';

// Admin sign-in (password, then a TOTP code when two-factor is on) and sign-out.
//
// Throttling, in fixed 15-minute windows shared by every process:
//   login:ip:<ip>                    20  every POST, checked first (skipped when the client IP is unknown)
//   login:acctip:<ip>:<email>        10  checked first, counted only on failure
//   login:acct:<email>              100  checked first, counted only on failure
//   login:totp:<adminId>             10  every code attempt
// <ip> is an IPv4 address, or the /48 of an IPv6 address (loginIpKey): one
// customer or site usually holds a whole /48, and rotating through its /64s
// must not multiply the budget. So one address cannot spray many accounts, and
// many addresses cannot lock a real admin out (the per-account limit is high;
// the per-account-and-IP one is what stops a single guesser).
// There is deliberately no relay-wide bucket: the bcrypt gate already caps the
// CPU spent on passwords, and the old 600-per-window global count let one
// IPv6 /56 (256 /64s of 20 attempts each) lock every admin out.
// The account buckets exist only for syntactically valid addresses: raw input
// never becomes part of a key (an "email" such as `victim@x.com:ip:<their IP>`
// must not land in someone else's bucket), and the IP comes first in the
// account-and-IP key so the two shapes can never collide.
// bcrypt runs at most twice at a time per process for sign-ins (services/admins.js).
//
// The 'admin-login' per-IP limiter (30/min) is mounted in routes/admin/index.js,
// ahead of the session and CSRF layers, so it also covers refused forms.

const express = require('express');
const { clientIp, ipRateKey } = require('../../lib/clientIp');
const { decryptTotpSecret } = require('../../lib/secrets');
const { verifyTotp } = require('../../lib/totp');
const { safeNext, startAdminSession } = require('../../middleware/auth');
const { ensureToken } = require('../../middleware/csrf');
const { regenerateSession, destroySession, clearSessionCookie } = require('../../middleware/session');
const adminsRepo = require('../../repos/admins');
const admins = require('../../services/admins');
const { recordAudit } = require('../../services/audit');
const { hitWindow, peekWindow } = require('../../services/rateLimit');

const WINDOW_SECONDS = 15 * 60;
const LIMITS = Object.freeze({ ip: 20, accountIp: 10, account: 100, totp: 10 });
const LOGIN_V6_PREFIX = 48;
const PENDING_MS = 5 * 60 * 1000;
const MAX_EMAIL_CHARS = 254;

const THROTTLED = 'Too many attempts. Try again later.';
const INVALID_LOGIN = 'Invalid email or password.';
const INVALID_CODE = 'That code is not valid. Try again with a new code.';
const FORM_EXPIRED = 'The sign-in form expired. Sign in again.';

function renderLogin(res, status, { email = '', next = '', error = null, notice = null }) {
  res.set('Cache-Control', 'no-store');
  res.status(status).render('login', { title: 'Sign in', activeNav: '', email, next, error, notice });
}

function field(req, name) {
  const v = req.body ? req.body[name] : undefined;
  if (typeof v === 'string') return v;
  if (Array.isArray(v) && typeof v[0] === 'string') return v[0];
  return '';
}

function queryString(req, name) {
  const v = req.query[name];
  if (typeof v === 'string') return v;
  return Array.isArray(v) && typeof v[0] === 'string' ? v[0] : '';
}

function loginEmail(req) {
  return admins.normalizeEmail(field(req, 'email')).slice(0, MAX_EMAIL_CHARS);
}

// The <ip> part of the sign-in bucket keys: IPv4 as is, IPv6 by its /48; null
// when the client IP is unknown (the IP buckets are then skipped).
function loginIpKey(req) {
  return ipRateKey(clientIp(req), { v6Prefix: LOGIN_V6_PREFIX });
}

// Error handler for routes/admin/index.js, mounted after the auth routes. The
// anonymous session behind the sign-in form lives 30 minutes (sessionStore.js);
// a form submitted after that arrives without any session token. Show the form
// again with a fresh token and the typed email (kept out of the URL) instead of
// the generic 403. A wrong token or a foreign Origin still gets the 403 page,
// and showing a sign-in form signs nobody in.
function loginFormExpired(err, req, res, next) {
  if (!err || err.code !== 'csrf' || err.reason !== 'missing' || req.method !== 'POST' || req.path !== '/login') {
    return next(err);
  }
  // res.locals.csrfToken only mints tokens for GET pages; this POST needs one.
  ensureToken(req);
  renderLogin(res, 403, { email: loginEmail(req), next: safeNext(field(req, 'next')) || '', notice: FORM_EXPIRED });
}

function createAuthRouter(deps) {
  const { db, config, logger } = deps;
  const router = express.Router();

  // Sign-in attempts are not authenticated yet, so the actor is anonymous and
  // the account concerned (if any) is the audit target.
  function audit(req, action, { admin = null, email, extra = {}, actor = null }) {
    return recordAudit(
      db,
      actor || { id: null, email: null, ip: clientIp(req) },
      action,
      { targetType: 'admin', targetId: admin ? admin.id : null, details: { email, ...extra } },
      deps.clock.now()
    );
  }

  function renderTotp(res, status, error = null) {
    res.set('Cache-Control', 'no-store');
    res.status(status).render('login-2fa', { title: 'Two-factor authentication', activeNav: '', error });
  }

  // The per-account buckets, built in one place so checkThrottle and
  // countFailure can never disagree on a key. None for an address that cannot
  // belong to an admin (login:ip and the bcrypt gate still bound those requests).
  function accountBuckets(email, validEmail, ipKey) {
    if (!validEmail) return [];
    return [
      ipKey && { bucket: 'account_ip', key: `login:acctip:${ipKey}:${email}`, limit: LIMITS.accountIp },
      { bucket: 'account', key: `login:acct:${email}`, limit: LIMITS.account },
    ].filter(Boolean);
  }

  // → { blocked, toAudit: [bucket names] }. The IP bucket is counted on every
  // attempt and audited once, on the first refused attempt (count === limit + 1);
  // the account buckets are only peeked here (see countFailure).
  async function checkThrottle(email, validEmail, ipKey) {
    if (ipKey) {
      const ip = await hitWindow(deps, `login:ip:${ipKey}`, LIMITS.ip, WINDOW_SECONDS);
      if (!ip.allowed) return { blocked: true, toAudit: ip.count === LIMITS.ip + 1 ? ['ip'] : [] };
    }
    const accounts = accountBuckets(email, validEmail, ipKey);
    const peeks = await Promise.all(accounts.map((b) => peekWindow(deps, b.key, b.limit, WINDOW_SECONDS)));
    return { blocked: peeks.some((p) => !p.allowed), toAudit: [] };
  }

  // Counts a failed password for the account buckets. Those are only peeked
  // before an attempt, so they are audited when this failure exhausts them.
  async function countFailure(email, validEmail, ipKey) {
    const hits = accountBuckets(email, validEmail, ipKey);
    const results = await Promise.all(hits.map((h) => hitWindow(deps, h.key, h.limit, WINDOW_SECONDS)));
    return hits.filter((h, i) => results[i].count === h.limit).map((h) => h.bucket);
  }

  async function auditThrottled(req, email, validEmail, buckets) {
    if (!buckets.length) return;
    const admin = validEmail ? await adminsRepo.getAdminByEmail(db, email) : null;
    for (const bucket of buckets) {
      await audit(req, 'auth.login_throttled', { admin, email, extra: { bucket } });
    }
  }

  async function finishLogin(req, admin, now) {
    await adminsRepo.updateAdmin(db, admin.id, { lastLoginAt: now }, now);
    await audit(req, 'auth.login', {
      admin,
      email: admin.email,
      actor: { id: admin.id, email: admin.email, ip: clientIp(req) },
    });
    await startAdminSession(req, { adminId: admin.id, epoch: admin.sessionEpoch, authAt: now.getTime() });
  }

  // The password step is done and the session waits for a TOTP code.
  function pendingAdminId(req) {
    const s = req.session;
    if (!s || !s.pendingAdminId || typeof s.pendingAt !== 'number') return null;
    const age = deps.clock.now().getTime() - s.pendingAt;
    return age >= 0 && age <= PENDING_MS ? s.pendingAdminId : null;
  }

  function restartLogin(req, res, message) {
    if (req.session) {
      delete req.session.pendingAdminId;
      delete req.session.pendingAt;
      delete req.session.pendingEpoch;
      delete req.session.pendingNext;
    }
    req.flash('info', message);
    res.redirect(303, '/admin/login');
  }

  router.get('/login', (req, res) => {
    const next = safeNext(queryString(req, 'next')) || '';
    if (req.session && req.session.adminId) return res.redirect(302, next || '/admin');
    let notice = null;
    if (queryString(req, 'expired')) notice = 'Your session has ended. Sign in again.';
    else if (queryString(req, 'signed_out')) notice = 'You have signed out.';
    renderLogin(res, 200, { next, notice });
  });

  router.post('/login', async (req, res) => {
    const email = loginEmail(req);
    const validEmail = admins.isValidAdminEmail(email);
    const password = field(req, 'password');
    const next = safeNext(field(req, 'next')) || '';
    const ipKey = loginIpKey(req);

    const throttle = await checkThrottle(email, validEmail, ipKey);
    if (throttle.blocked) {
      await auditThrottled(req, email, validEmail, throttle.toAudit);
      return renderLogin(res, 429, { email, next, error: THROTTLED });
    }

    const admin = validEmail ? await adminsRepo.getAdminByEmail(db, email) : null;
    const check = await admins.withCompareSlot(() =>
      admin ? admins.verifyPassword(password, admin.passwordHash) : admins.dummyVerify(password)
    );
    if (check.busy) return renderLogin(res, 429, { email, next, error: THROTTLED });
    const passwordOk = check.value;

    if (!passwordOk || admin.disabled) {
      const exhausted = await countFailure(email, validEmail, ipKey);
      const reason = !admin ? 'unknown' : passwordOk ? 'disabled' : 'password';
      await audit(req, 'auth.login_failed', { admin, email, extra: { reason } });
      await auditThrottled(req, email, validEmail, exhausted);
      return renderLogin(res, 401, { email, next, error: INVALID_LOGIN });
    }

    const now = deps.clock.now();
    if (admin.totpEnabled) {
      await regenerateSession(req);
      req.session.pendingAdminId = admin.id;
      req.session.pendingAt = now.getTime();
      req.session.pendingEpoch = admin.sessionEpoch;
      req.session.pendingNext = next;
      return res.redirect(303, '/admin/login/2fa');
    }
    await finishLogin(req, admin, now);
    res.redirect(303, next || '/admin');
  });

  router.get('/login/2fa', (req, res) => {
    if (!pendingAdminId(req)) return restartLogin(req, res, 'Sign in with your email and password first.');
    renderTotp(res, 200);
  });

  router.post('/login/2fa', async (req, res) => {
    const adminId = pendingAdminId(req);
    if (!adminId) return restartLogin(req, res, 'The sign-in took too long. Sign in again.');

    const attempt = await hitWindow(deps, `login:totp:${adminId}`, LIMITS.totp, WINDOW_SECONDS);
    if (!attempt.allowed) {
      if (attempt.count === LIMITS.totp + 1) {
        const admin = await adminsRepo.getAdmin(db, adminId);
        await audit(req, 'auth.login_throttled', { admin, email: admin ? admin.email : null, extra: { bucket: 'totp' } });
      }
      return renderTotp(res, 429, THROTTLED);
    }

    const admin = await adminsRepo.getAdmin(db, adminId);
    // Anything that changed since the password step (disabled, password or
    // two-factor reset) bumps the epoch or clears the secret: start over.
    if (
      !admin ||
      admin.disabled ||
      !admin.totpEnabled ||
      !admin.totpSecretEnc ||
      admin.sessionEpoch !== req.session.pendingEpoch
    ) {
      return restartLogin(req, res, 'Sign in again.');
    }

    let secret;
    try {
      secret = decryptTotpSecret(config, admin.id, admin.totpSecretEnc);
    } catch (err) {
      logger.error('totp secret cannot be decrypted', { adminId: admin.id, error: err.message });
      return renderTotp(
        res,
        500,
        'Two-factor authentication cannot be checked for this account. Ask another admin to turn it off for you.'
      );
    }

    const now = deps.clock.now();
    const result = verifyTotp(secret, admins.normalizeTotpCode(field(req, 'code')), now.getTime(), {
      window: 1,
      lastStep: admin.totpLastStep,
    });
    // claimTotpStep makes each code single-use even across concurrent requests.
    const claimed = result.ok && (await adminsRepo.claimTotpStep(db, admin.id, result.step, now));
    if (!claimed) {
      await audit(req, 'auth.totp_failed', { admin, email: admin.email });
      return renderTotp(res, 401, INVALID_CODE);
    }

    const next = safeNext(req.session.pendingNext) || '/admin';
    await finishLogin(req, admin, now);
    res.redirect(303, next);
  });

  router.post('/logout', async (req, res) => {
    const adminId = req.session ? req.session.adminId : null;
    if (adminId) {
      const admin = await adminsRepo.getAdmin(db, adminId);
      if (admin) {
        await audit(req, 'auth.logout', {
          admin,
          email: admin.email,
          actor: { id: admin.id, email: admin.email, ip: clientIp(req) },
        });
      }
    }
    await destroySession(req);
    clearSessionCookie(res, config);
    res.redirect(303, '/admin/login?signed_out=1');
  });

  return router;
}

module.exports = createAuthRouter;
module.exports.createAuthRouter = createAuthRouter;
module.exports.loginFormExpired = loginFormExpired;
module.exports.LOGIN_LIMITS = LIMITS;
module.exports.loginIpKey = loginIpKey;
module.exports.LOGIN_V6_PREFIX = LOGIN_V6_PREFIX;
module.exports.FORM_EXPIRED = FORM_EXPIRED;
