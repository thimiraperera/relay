'use strict';

// Admin pages for apps: the list (GET /admin), create, settings, API keys and
// test email. Mounted inside the /admin router after requireAdmin, so
// req.adminUser, req.actor, req.flash and res.locals.csrfToken are set.

const express = require('express');
const appsRepo = require('../../repos/apps');
const keysRepo = require('../../repos/apiKeys');
const { countsForDay } = require('../../repos/messages');
const { listAudit } = require('../../repos/audit');
const keysService = require('../../services/keys');
const { sendTestEmail } = require('../../services/send');
const appsAdmin = require('../../services/appsAdmin');
const { buildSnippets } = require('../../lib/snippets');
const { decryptSmtpPassword } = require('../../lib/secrets');
const { localDay } = require('../../lib/time');
const { HttpError, notFound } = require('../../lib/errors');

const RECENT_AUDIT = 10;
const FLASH_MAX = 200;
const GRACE_LABELS = Object.freeze({ 0: 'no grace period', 3600: '1 hour', 86400: '24 hours' });
const NOT_PRINTABLE_ASCII = new RegExp('[^\\x20-\\x7E]+', 'g');

// SMTP banners and error texts come from remote servers: keep what reaches the
// flash message to printable ASCII and a short length.
function flashText(s) {
  const clean = String(s).replace(NOT_PRINTABLE_ASCII, ' ').replace(/ {2,}/g, ' ').trim();
  return clean.length > FLASH_MAX ? clean.slice(0, FLASH_MAX - 3) + '...' : clean;
}

// Service messages are lowercase API-style reasons; flash them as sentences.
function sentence(msg) {
  const s = String(msg || '').trim();
  if (!s) return 'Something went wrong.';
  const first = s.charAt(0).toUpperCase() + s.slice(1);
  return /[.!?]$/.test(first) ? first : first + '.';
}

// 400/409 from the key services are form problems (stale page, double submit,
// bad grace value): shown as a flash on the app page instead of an error page.
function isFormError(err) {
  return err instanceof HttpError && (err.status === 400 || err.status === 409);
}

module.exports = function createAppsRouter(deps) {
  const { config, db } = deps;
  const router = express.Router();

  function limits() {
    return appsAdmin.messageSizeLimitsMb(config);
  }

  function appPath(app) {
    return `/admin/apps/${app.id}`;
  }

  async function loadApp(req) {
    const id = appsAdmin.parseId(req.params.id);
    const app = id === null ? null : await appsRepo.getApp(db, id);
    if (!app) throw notFound('app not found');
    return app;
  }

  function passwordState(app) {
    if (!app.smtpPasswordEnc) return 'not set';
    return decryptSmtpPassword(config, app) === null ? 'unreadable' : 'set';
  }

  // `expectedUpdatedAt` is the settings form's version token. A re-render after
  // a validation error keeps the one that was submitted: the values on the page
  // are still based on that version, so a change saved meanwhile is caught when
  // the corrected form is submitted.
  async function renderShow(req, res, app, { form, errors = {}, status = 200, expectedUpdatedAt } = {}) {
    const now = deps.clock.now();
    const [keyRows, audit] = await Promise.all([
      keysRepo.listKeysForApp(db, app.id),
      listAudit(db, { targetType: 'app', targetId: String(app.id), limit: RECENT_AUDIT, offset: 0 }),
    ]);
    const keys = keyRows.map((k) => ({ ...k, status: appsAdmin.keyStatus(k, now) }));
    const currentUser = res.locals.currentUser;
    res.status(status).render('apps/show', {
      title: app.name,
      activeNav: 'apps',
      app,
      now,
      form: form || appsAdmin.appToForm(app),
      expectedUpdatedAt: expectedUpdatedAt === undefined ? appsAdmin.settingsVersion(app) : expectedUpdatedAt,
      errors,
      limits: limits(),
      keys,
      activeApiKey: keys.find((k) => k.status === 'active') || null,
      passwordState: passwordState(app),
      auditRows: audit.rows.map((r) => ({
        ...r,
        summary: appsAdmin.summarizeAuditDetails(r.details),
        actor: appsAdmin.describeActor(r),
      })),
      auditTotal: audit.total,
      snippets: buildSnippets({
        baseUrl: config.publicBaseUrl,
        app,
        idempotencyDays: config.idempotencyDays,
        maxSkewSeconds: config.legacyMaxSkewSeconds,
      }),
      testTo: currentUser && currentUser.email ? currentUser.email : '',
    });
  }

  function renderKeyCreated(res, app, created, extra) {
    // The full key is on this page and nowhere else: never cache it.
    res.set('Cache-Control', 'no-store');
    res.render('apps/key-created', {
      title: 'New API key',
      activeNav: 'apps',
      app,
      newKey: created.key,
      prefix: created.prefix,
      endpoint: app.legacySigning ? `${config.publicBaseUrl}/send.php` : `${config.publicBaseUrl}/v1/send`,
      regenerated: false,
      graceSeconds: 0,
      graceLabel: GRACE_LABELS[0],
      graceUntil: null,
      ...extra,
    });
  }

  router.get('/', async (req, res) => {
    const now = deps.clock.now();
    const today = localDay(now, config.timezone);
    const [apps, counts] = await Promise.all([appsRepo.listApps(db), countsForDay(db, today)]);
    const rows = apps.map((app) => {
      const c = counts.get(app.id) || { sent: 0, failed: 0 };
      return { app, sent: c.sent, failed: c.failed };
    });
    res.render('apps/list', { title: 'Apps', activeNav: 'apps', rows, today, timezone: config.timezone });
  });

  router.get('/apps', (req, res) => {
    res.redirect('/admin');
  });

  router.get('/apps/new', (req, res) => {
    res.render('apps/new', {
      title: 'New app',
      activeNav: 'apps',
      form: appsAdmin.defaultForm(config),
      errors: {},
      limits: limits(),
    });
  });

  router.post('/apps', async (req, res) => {
    const { values, errors, form } = appsAdmin.validateAppInput(req.body || {}, config, { isCreate: true });
    if (Object.keys(errors).length) {
      res.status(400).render('apps/new', { title: 'New app', activeNav: 'apps', form, errors, limits: limits() });
      return;
    }
    const id = await appsAdmin.createAppFromInput(deps, values, req.actor);
    req.flash('success', 'App created — generate an API key');
    res.redirect(303, `/admin/apps/${id}`);
  });

  router.get('/apps/:id', async (req, res) => {
    const app = await loadApp(req);
    await renderShow(req, res, app);
  });

  router.post('/apps/:id', async (req, res) => {
    const app = await loadApp(req);
    const body = req.body || {};
    // Always passed (a missing field is ''), so a form without the token, e.g.
    // one cached from before it existed, is refused like a stale one.
    const expectedUpdatedAt = appsAdmin.formField(body, 'expected_updated_at');
    const { values, errors, form } = appsAdmin.validateAppInput(body, config, { isCreate: false });
    if (Object.keys(errors).length) {
      await renderShow(req, res, app, { form, errors, status: 400, expectedUpdatedAt });
      return;
    }
    let result;
    try {
      result = await appsAdmin.updateAppFromInput(deps, app.id, values, req.actor, { expectedUpdatedAt });
    } catch (err) {
      // 409: the settings changed since the form was loaded; nothing was saved.
      if (!isFormError(err)) throw err;
      req.flash('error', sentence(err.message));
      res.redirect(303, appPath(app));
      return;
    }
    req.flash(result.changed ? 'success' : 'info', result.changed ? 'Settings saved.' : 'No changes to save.');
    if (result.passwordCleared) {
      req.flash(
        'warning',
        'The SMTP host, port, encryption or username changed, so the stored SMTP password was cleared. ' +
          'Enter the password again or the app cannot send.'
      );
    }
    if (result.legacyChanged) {
      req.flash(
        'warning',
        values.legacySigning
          ? 'Legacy signing was turned on, so every API key of this app was revoked. Generate a new key and use it to sign /send.php requests.'
          : 'Legacy signing was turned off, so every API key of this app was revoked. Generate a new key for /v1/send.'
      );
    }
    res.redirect(303, appPath(app));
  });

  router.post('/apps/:id/keys', async (req, res) => {
    const app = await loadApp(req);
    let created;
    try {
      created = await keysService.createKey(deps, { appId: app.id, actor: req.actor });
    } catch (err) {
      if (!isFormError(err)) throw err;
      req.flash('error', sentence(err.message));
      res.redirect(303, appPath(app));
      return;
    }
    renderKeyCreated(res, app, created, {});
  });

  router.post('/apps/:id/keys/regenerate', async (req, res) => {
    const app = await loadApp(req);
    const body = req.body || {};
    const grace = appsAdmin.formField(body, 'grace');
    const startedAt = deps.clock.now();
    let created;
    try {
      created = await keysService.regenerateKey(deps, {
        appId: app.id,
        graceSeconds: grace,
        expectedActiveKeyId: appsAdmin.formField(body, 'expected_key_id'),
        actor: req.actor,
      });
    } catch (err) {
      if (!isFormError(err)) throw err;
      req.flash('error', sentence(err.message));
      res.redirect(303, appPath(app));
      return;
    }
    // regenerateKey accepted the value, so it is one of 0, 3600, 86400.
    const graceSeconds = Number(grace.trim());
    renderKeyCreated(res, app, created, {
      regenerated: true,
      graceSeconds,
      graceLabel: GRACE_LABELS[graceSeconds] || `${graceSeconds} seconds`,
      graceUntil: graceSeconds > 0 ? new Date(startedAt.getTime() + graceSeconds * 1000) : null,
    });
  });

  router.post('/apps/:id/keys/:keyId/revoke', async (req, res) => {
    const app = await loadApp(req);
    const keyId = appsAdmin.parseId(req.params.keyId);
    if (keyId === null) throw notFound('key not found');
    const revoked = await keysService.revokeKey(deps, { appId: app.id, keyId, actor: req.actor });
    const key = await keysRepo.getKey(db, keyId);
    const label = key ? `${key.prefix}…` : `#${keyId}`;
    if (revoked) req.flash('success', `API key ${label} revoked. Anything still using it now gets 401.`);
    else req.flash('info', `API key ${label} was already revoked.`);
    res.redirect(303, appPath(app));
  });

  router.post('/apps/:id/test', async (req, res) => {
    const app = await loadApp(req);
    const to = appsAdmin.formField(req.body || {}, 'to').trim();
    const result = await sendTestEmail(deps, { app, to, actor: req.actor });
    if (result.ok) {
      req.flash('success', flashText(`Test email sent to ${to}. Server response: ${result.response || '(none)'}`));
    } else {
      req.flash('error', flashText(`Test email failed: ${result.error || 'unknown error'}`));
    }
    res.redirect(303, appPath(app));
  });

  return router;
};

module.exports.flashText = flashText;
