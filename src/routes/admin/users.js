'use strict';

// Admin users: list, create, disable/enable and password reset. Every one of
// these changes requires the acting admin's current password.

const express = require('express');
const { HttpError, notFound } = require('../../lib/errors');
const { startAdminSession } = require('../../middleware/auth');
const adminsRepo = require('../../repos/admins');
const admins = require('../../services/admins');

const MAX_NAME_CHARS = 100;

function field(req, name) {
  const v = req.body ? req.body[name] : undefined;
  if (typeof v === 'string') return v;
  if (Array.isArray(v) && typeof v[0] === 'string') return v[0];
  return '';
}

function parseId(value) {
  return typeof value === 'string' && /^[1-9]\d{0,9}$/.test(value) ? Number(value) : null;
}

function isUserError(err) {
  return err instanceof HttpError && err.status >= 400 && err.status < 500;
}

function createUsersRouter(deps) {
  const { db } = deps;
  const router = express.Router();

  async function render(req, res, { status = 200, form = {}, errors = {} } = {}) {
    const list = await adminsRepo.listAdmins(db);
    res.status(status).render('users', {
      title: 'Users',
      activeNav: 'users',
      admins: list.map((a) => ({
        id: a.id,
        email: a.email,
        name: a.name,
        totpEnabled: a.totpEnabled,
        disabled: a.disabled,
        lastLoginAt: a.lastLoginAt,
        createdAt: a.createdAt,
        isSelf: a.id === req.adminUser.id,
      })),
      enabledCount: list.filter((a) => !a.disabled).length,
      form: { email: form.email || '', name: form.name || '' },
      errors,
      minPasswordChars: admins.MIN_PASSWORD_CHARS,
    });
  }

  function targetId(req) {
    const id = parseId(req.params.id);
    if (id === null) throw notFound('Admin not found.');
    return id;
  }

  router.get('/users', (req, res) => render(req, res));

  router.post('/users', async (req, res) => {
    const form = { email: field(req, 'email').trim(), name: field(req, 'name').trim() };
    const password = field(req, 'password');
    const email = admins.normalizeEmail(form.email);

    const errors = {};
    if (!admins.isValidAdminEmail(email)) errors.email = 'Enter a valid email address.';
    if (Array.from(form.name).length > MAX_NAME_CHARS) errors.name = `Name must be at most ${MAX_NAME_CHARS} characters.`;
    const pwError = admins.validatePassword(password);
    if (pwError) errors.password = pwError;
    if (!Object.keys(errors).length) {
      const reauthError = await admins.reauthenticate(deps, req.adminUser, field(req, 'current_password'), req.actor);
      if (reauthError) errors.current_password = reauthError;
    }
    if (Object.keys(errors).length) return render(req, res, { status: 400, form, errors });

    try {
      await admins.createAdmin(deps, { email, name: form.name, password, actor: req.actor });
    } catch (err) {
      if (!isUserError(err)) throw err;
      return render(req, res, { status: err.status, form, errors: { email: err.message } });
    }
    req.flash('success', `Admin ${email} created. Share the password with them over a separate channel.`);
    res.redirect(303, '/admin/users');
  });

  // Both directions need the current password: enabling brings an account's old
  // credentials back into use, and disabling can lock other admins out.
  async function changeDisabled(req, res, disabled) {
    const id = targetId(req);
    const reauthError = await admins.reauthenticate(deps, req.adminUser, field(req, 'current_password'), req.actor);
    if (reauthError) {
      req.flash('error', (disabled ? 'Admin not disabled: ' : 'Admin not enabled: ') + reauthError);
      return res.redirect(303, '/admin/users');
    }
    let changed;
    try {
      changed = await admins.setDisabled(deps, { adminId: id, disabled, actor: req.actor });
    } catch (err) {
      if (!isUserError(err)) throw err;
      req.flash('error', err.message);
      return res.redirect(303, '/admin/users');
    }
    if (changed) {
      req.flash('success', disabled ? 'Admin disabled and signed out everywhere.' : 'Admin enabled.');
    } else {
      req.flash('info', disabled ? 'That admin is already disabled.' : 'That admin is already enabled.');
    }
    res.redirect(303, '/admin/users');
  }

  router.post('/users/:id/disable', (req, res) => changeDisabled(req, res, true));
  router.post('/users/:id/enable', (req, res) => changeDisabled(req, res, false));

  router.post('/users/:id/reset-password', async (req, res) => {
    const id = targetId(req);
    const target = await adminsRepo.getAdmin(db, id);
    if (!target) throw notFound('Admin not found.');

    const password = field(req, 'new_password');
    const pwError = admins.validatePassword(password);
    if (pwError) {
      req.flash('error', `Password for ${target.email} not changed: ${pwError}`);
      return res.redirect(303, '/admin/users');
    }
    const reauthError = await admins.reauthenticate(deps, req.adminUser, field(req, 'current_password'), req.actor);
    if (reauthError) {
      req.flash('error', `Password for ${target.email} not changed: ${reauthError}`);
      return res.redirect(303, '/admin/users');
    }

    let epoch = await admins.setPassword(deps, { adminId: id, password, actor: req.actor, reset: true });
    // For an admin who lost both the password and the authenticator device.
    const turnOffTotp = field(req, 'disable_totp') === '1' && (target.totpEnabled || Boolean(target.totpSecretEnc));
    if (turnOffTotp) epoch = await admins.disableTotp(deps, { adminId: id, actor: req.actor });

    const self = id === req.adminUser.id;
    if (self) await startAdminSession(req, { adminId: id, epoch, authAt: req.session.authAt });
    req.flash(
      'success',
      `Password for ${target.email} reset${turnOffTotp ? ' and two-factor authentication turned off' : ''}. ` +
        (self ? 'Your other sessions have been signed out.' : 'Their existing sessions have been signed out.')
    );
    res.redirect(303, '/admin/users');
  });

  return router;
}

module.exports = createUsersRouter;
module.exports.createUsersRouter = createUsersRouter;
