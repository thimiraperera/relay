'use strict';

// GET /admin/stats: sent and failed messages per app per local day. "Failed" is
// failed + rejected + unknown, with the breakdown shown alongside.

const express = require('express');
const { listApps } = require('../../repos/apps');
const { statsByDay } = require('../../repos/messages');
const { formField, parseId } = require('../../services/appsAdmin');
const { localDay, addDays } = require('../../lib/time');

const DAY_OPTIONS = Object.freeze([7, 14, 30, 90]);
const DEFAULT_DAYS = 14;

function emptyTotals() {
  return { sent: 0, failed: 0, rejected: 0, unknown: 0, failedTotal: 0 };
}

function add(totals, row) {
  totals.sent += row.sent;
  totals.failed += row.failed;
  totals.rejected += row.rejected;
  totals.unknown += row.unknown;
  totals.failedTotal += row.failedTotal;
}

module.exports = function createStatsRouter(deps) {
  const router = express.Router();

  router.get('/stats', async (req, res) => {
    const query = req.query || {};
    const daysText = formField(query, 'days').trim();
    const days = /^\d{1,3}$/.test(daysText) && DAY_OPTIONS.includes(Number(daysText)) ? Number(daysText) : DEFAULT_DAYS;
    const appId = parseId(formField(query, 'app').trim());

    const toDay = localDay(deps.clock.now(), deps.config.timezone);
    const fromDay = addDays(toDay, -(days - 1));

    const [raw, apps] = await Promise.all([
      statsByDay(deps.db, { fromDay, toDay, appId: appId === null ? undefined : appId }),
      listApps(deps.db),
    ]);

    const rows = raw.map((r) => ({ ...r, failedTotal: r.failed + r.rejected + r.unknown }));
    const totals = emptyTotals();
    const perApp = new Map();
    for (const row of rows) {
      add(totals, row);
      let entry = perApp.get(row.appId);
      if (!entry) {
        entry = { appId: row.appId, appName: row.appName, ...emptyTotals() };
        perApp.set(row.appId, entry);
      }
      add(entry, row);
    }
    const byApp = [...perApp.values()].sort(
      (a, b) => String(a.appName || '').localeCompare(String(b.appName || '')) || a.appId - b.appId
    );

    res.render('stats', {
      title: 'Stats',
      activeNav: 'stats',
      days,
      dayOptions: DAY_OPTIONS,
      appFilter: appId === null ? '' : String(appId),
      apps,
      fromDay,
      toDay,
      timezone: deps.config.timezone,
      rows,
      byApp,
      totals,
    });
  });

  return router;
};
