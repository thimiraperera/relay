'use strict';

// The signed-in admin's own account: password change and TOTP two-factor
// (setup → enable with a code, or disable). Password and two-factor changes end
// the admin's other sessions; the current one is re-issued with the new epoch.

const express = require('express');
const QRCode = require('qrcode');
const { HttpError } = require('../../lib/errors');
const { otpauthUrl } = require('../../lib/totp');
const { startAdminSession } = require('../../middleware/auth');
const admins = require('../../services/admins');

function field(req, name) {
  const v = req.body ? req.body[name] : undefined;
  if (typeof v === 'string') return v;
  if (Array.isArray(v) && typeof v[0] === 'string') return v[0];
  return '';
}

function isUserError(err) {
  return err instanceof HttpError && err.status >= 400 && err.status < 500;
}

function createAccountRouter(deps) {
  const router = express.Router();

  function render(req, res, { status = 200, errors = {}, setup = null } = {}) {
    const a = req.adminUser;
    res.status(status).render('account', {
      title: 'Account',
      activeNav: 'account',
      account: {
        email: a.email,
        name: a.name,
        totpEnabled: a.totpEnabled,
        // A secret is stored but no code has been confirmed yet.
        totpPending: !a.totpEnabled && Boolean(a.totpSecretEnc),
        lastLoginAt: a.lastLoginAt,
        createdAt: a.createdAt,
      },
      errors,
      setup,
      minPasswordChars: admins.MIN_PASSWORD_CHARS,
    });
  }

  // Keeps the acting admin signed in after their own epoch was bumped.
  function reissue(req, epoch) {
    return startAdminSession(req, { adminId: req.adminUser.id, epoch, authAt: req.session.authAt });
  }

  router.get('/account', (req, res) => render(req, res));

  router.post('/account/password', async (req, res) => {
    const current = field(req, 'current_password');
    const password = field(req, 'new_password');
    const confirm = field(req, 'confirm_password');

    const errors = {};
    const pwError = admins.validatePassword(password);
    if (pwError) errors.new_password = pwError;
    else if (password !== confirm) errors.confirm_password = 'The two new passwords do not match.';
    else if (password === current) errors.new_password = 'Choose a password that differs from the current one.';
    if (!errors.new_password && !errors.confirm_password) {
      const reauthError = await admins.reauthenticate(deps, req.adminUser, current, req.actor);
      if (reauthError) errors.current_password = reauthError;
    }
    if (Object.keys(errors).length) return render(req, res, { status: 400, errors });

    const epoch = await admins.setPassword(deps, {
      adminId: req.adminUser.id,
      password,
      actor: req.actor,
      reset: false,
    });
    await reissue(req, epoch);
    req.flash('success', 'Password changed. Your other sessions have been signed out.');
    res.redirect(303, '/admin/account');
  });

  router.post('/account/totp/setup', async (req, res) => {
    if (req.adminUser.totpEnabled) {
      req.flash('info', 'Two-factor authentication is already on.');
      return res.redirect(303, '/admin/account');
    }
    const reauthError = await admins.reauthenticate(deps, req.adminUser, field(req, 'current_password'), req.actor);
    if (reauthError) return render(req, res, { status: 400, errors: { setup_password: reauthError } });

    const secret = await admins.beginTotpSetup(deps, { adminId: req.adminUser.id, actor: req.actor });
    const url = otpauthUrl({ secret, accountName: req.adminUser.email, issuer: 'Relay' });
    const qrDataUrl = await QRCode.toDataURL(url, { errorCorrectionLevel: 'M', margin: 2, width: 220 });
    res.set('Cache-Control', 'no-store');
    render(req, res, {
      setup: { secret, secretGrouped: secret.replace(/(.{4})(?=.)/g, '$1 '), qrDataUrl },
    });
  });

  router.post('/account/totp/enable', async (req, res) => {
    let epoch;
    try {
      epoch = await admins.enableTotp(deps, { adminId: req.adminUser.id, code: field(req, 'code'), actor: req.actor });
    } catch (err) {
      if (!isUserError(err)) throw err;
      req.flash('error', err.message);
      return res.redirect(303, '/admin/account');
    }
    await reissue(req, epoch);
    req.flash('success', 'Two-factor authentication is on. Your other sessions have been signed out.');
    res.redirect(303, '/admin/account');
  });

  router.post('/account/totp/disable', async (req, res) => {
    if (!req.adminUser.totpEnabled && !req.adminUser.totpSecretEnc) {
      req.flash('info', 'Two-factor authentication is already off.');
      return res.redirect(303, '/admin/account');
    }
    const reauthError = await admins.reauthenticate(deps, req.adminUser, field(req, 'current_password'), req.actor);
    if (reauthError) return render(req, res, { status: 400, errors: { disable_password: reauthError } });

    const epoch = await admins.disableTotp(deps, { adminId: req.adminUser.id, actor: req.actor });
    await reissue(req, epoch);
    req.flash('success', 'Two-factor authentication is off.');
    res.redirect(303, '/admin/account');
  });

  return router;
}

module.exports = createAccountRouter;
module.exports.createAccountRouter = createAccountRouter;
