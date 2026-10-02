'use strict';

// GET /admin/audit: every configuration change and security event, newest first.
// Optional ?app=<id> narrows it to one app's entries (linked from the app page).

const express = require('express');
const { listApps } = require('../../repos/apps');
const { listAudit } = require('../../repos/audit');
const { formField, parseId, parsePage, summarizeAuditDetails, describeActor } = require('../../services/appsAdmin');

const PAGE_SIZE = 50;

function describeTarget(row, appNames) {
  if (!row.targetType) return { label: '—', href: null };
  if (row.targetType === 'app' && row.targetId) {
    const name = appNames.get(String(row.targetId));
    return name === undefined
      ? { label: `app #${row.targetId}`, href: null }
      : { label: name, href: `/admin/apps/${row.targetId}` };
  }
  return { label: row.targetId ? `${row.targetType} #${row.targetId}` : row.targetType, href: null };
}

module.exports = function createAuditRouter(deps) {
  const router = express.Router();

  router.get('/audit', async (req, res) => {
    const query = req.query || {};
    const page = parsePage(formField(query, 'page'));
    const appId = parseId(formField(query, 'app').trim());
    const filter = appId === null ? {} : { targetType: 'app', targetId: String(appId) };

    const [result, apps] = await Promise.all([
      listAudit(deps.db, { ...filter, limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE }),
      listApps(deps.db),
    ]);
    const appNames = new Map(apps.map((a) => [String(a.id), a.name]));
    const rows = result.rows.map((r) => ({
      ...r,
      summary: summarizeAuditDetails(r.details),
      actor: describeActor(r),
      target: describeTarget(r, appNames),
    }));

    res.render('audit', {
      title: 'Audit log',
      activeNav: 'audit',
      rows,
      total: result.total,
      page,
      pageSize: PAGE_SIZE,
      apps,
      appFilter: appId === null ? '' : String(appId),
      linkQuery: appId === null ? {} : { app: String(appId) },
    });
  });

  return router;
};
