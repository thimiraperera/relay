'use strict';

// Deployment diagnostics: versions, runtime, database settings, cleanup status,
// API authentication failures and how the relay sees the current request
// (the quickest way to check TRUST_PROXY on a new host).

const express = require('express');
const { clientIp } = require('../../lib/clientIp');
const { localDay, localDateTime } = require('../../lib/time');
const { getKv } = require('../../repos/kv');
const { getCounter } = require('../../repos/rateCounters');
const { describeError } = require('../../lib/logger');
const { version: appVersion } = require('../../../package.json');

const CLEANUP_STALE_MS = 3 * 60 * 60 * 1000;
const AUTH_ROUTES = Object.freeze([
  { route: 'api', label: 'POST /v1/send' },
  { route: 'legacy', label: 'POST /send.php' },
]);

function detectRuntime() {
  if (typeof process.title === 'string' && process.title.startsWith('lsnode:')) return 'LiteSpeed (lsnode)';
  // Passenger defines this global inside the application process.
  if (typeof PhusionPassenger !== 'undefined') return 'Passenger';
  return 'Node.js (standalone)';
}

function humanDuration(totalSeconds) {
  const s = Math.max(0, Math.floor(totalSeconds));
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d) return `${d} d ${h} h`;
  if (h) return `${h} h ${m} min`;
  if (m) return `${m} min`;
  return `${s} s`;
}

function parseJson(text) {
  if (typeof text !== 'string' || text === '') return null;
  try {
    const v = JSON.parse(text);
    return v && typeof v === 'object' ? v : null;
  } catch {
    return null;
  }
}

function parseDate(text) {
  if (!text) return null;
  const d = new Date(text);
  return Number.isNaN(d.getTime()) ? null : d;
}

function createSystemRouter(deps) {
  const { config, db, logger } = deps;
  const router = express.Router();

  async function databaseInfo() {
    try {
      const rows = await db.query(
        'SELECT VERSION() AS version, @@max_user_connections AS maxUserConnections, @@wait_timeout AS waitTimeout'
      );
      const r = rows[0] || {};
      return { ok: true, version: r.version, maxUserConnections: r.maxUserConnections, waitTimeout: r.waitTimeout };
    } catch (err) {
      logger.warn('system page database check failed', { error: describeError(err) });
      return { ok: false, error: err.code || describeError(err) };
    }
  }

  // Rejected requests over an app's flood ceiling are only counted, in
  // rate_counters 'rejdrop:<appId>:<local day>' (services/send.js); list today's.
  async function droppedRejections(day) {
    const rows = await db.query('SELECT k, count FROM rate_counters WHERE k LIKE ? ORDER BY k', [`rejdrop:%:${day}`]);
    const counts = rows
      .map((r) => ({ appId: Number(String(r.k).split(':')[1]), count: Number(r.count) }))
      .filter((r) => Number.isSafeInteger(r.appId) && r.appId > 0 && r.count > 0);
    if (!counts.length) return [];
    const apps = await db.query('SELECT id, name FROM apps WHERE id IN (?)', [counts.map((r) => r.appId)]);
    const names = new Map(apps.map((a) => [Number(a.id), a.name]));
    return counts.map((r) => ({ ...r, name: names.has(r.appId) ? names.get(r.appId) : `app #${r.appId}` }));
  }

  // Best effort: the page should still render when the database is down.
  // cleanup.last_run is written by every cleanup, including the in-process
  // timer that runs a minute after each start; cleanup.last_cron_run only by
  // the cron script (scripts/cleanup.js), so it alone shows the cron is alive.
  async function readOps(day) {
    try {
      const [lastRun, lastCronRun, lastResult, dropped, ...failures] = await Promise.all([
        getKv(db, 'cleanup.last_run'),
        getKv(db, 'cleanup.last_cron_run'),
        getKv(db, 'cleanup.last_result'),
        droppedRejections(day),
        ...AUTH_ROUTES.map(async ({ route, label }) => ({
          label,
          today: await getCounter(db, `authfail:${route}:${day}`),
          last: parseJson(await getKv(db, `authfail.${route}.last`)),
        })),
      ]);
      return {
        cleanup: {
          lastRun: parseDate(lastRun),
          lastCronRun: parseDate(lastCronRun),
          lastResult: parseJson(lastResult),
        },
        authFailures: failures,
        droppedRejections: dropped,
      };
    } catch (err) {
      logger.warn('system page status read failed', { error: describeError(err) });
      return null;
    }
  }

  function warningsFor(ops, database, now) {
    const w = [];
    if (!database.ok) w.push('The database query failed. Check DB_HOST/DB_SOCKET, DB_USER and DB_PASSWORD.');
    if (config.bootstrapAdmin) {
      w.push(
        'ADMIN_BOOTSTRAP_EMAIL and ADMIN_BOOTSTRAP_PASSWORD are still set. Remove them from .env and restart the app.'
      );
    }
    if (config.trustProxy === true) {
      w.push(
        'TRUST_PROXY=true trusts any X-Forwarded-For header, so client IPs (allowlists, rate limits) can be spoofed. Use a hop count such as 1.'
      );
    }
    if (config.production && !config.forceHttps) w.push('FORCE_HTTPS is off: plain-HTTP requests are accepted.');
    if (config.production && !config.cookieSecure) {
      w.push('COOKIE_SECURE is off: the admin session cookie can travel over plain HTTP.');
    }
    if (ops) {
      const { lastRun, lastCronRun } = ops.cleanup;
      const stale = (d) => !d || now.getTime() - d.getTime() > CLEANUP_STALE_MS;
      if (!lastCronRun) {
        w.push(
          'No run of the hourly cleanup cron job has been recorded. Set it up as described in the README (Step 9); ' +
            'its first run shows here within the hour. ' +
            (lastRun ? 'Until then only the in-process timer, which stops with the app, has run cleanup.' : 'Cleanup has never run.')
        );
      } else if (stale(lastCronRun)) {
        w.push(
          'The hourly cleanup cron job has not run in the last 3 hours. Check the cron command ' +
            '(the Node version in the nodevenv path) and logs/cron.log.'
        );
      } else if (stale(lastRun)) {
        w.push('The cron job runs, but no cleanup has finished in the last 3 hours. Check logs/cron.log for errors.');
      }
    }
    return w;
  }

  function requestAsSeen(req) {
    const header = (name) => req.get(name) || '(none)';
    return [
      { label: 'Client IP (used for limits and allowlists)', value: clientIp(req) || 'unavailable' },
      { label: 'req.ips', value: JSON.stringify(req.ips) },
      { label: 'req.secure', value: String(req.secure) },
      { label: 'req.protocol', value: req.protocol },
      { label: 'X-Forwarded-For', value: header('x-forwarded-for') },
      { label: 'X-Forwarded-Proto', value: header('x-forwarded-proto') },
      { label: 'X-Forwarded-Host', value: header('x-forwarded-host') },
      { label: 'Host', value: header('host') },
      { label: 'Socket remote address', value: (req.socket && req.socket.remoteAddress) || '(none)' },
      { label: 'TRUST_PROXY (trust proxy)', value: JSON.stringify(config.trustProxy) },
    ];
  }

  router.get('/system', async (req, res) => {
    const now = deps.clock.now();
    const [database, ops] = await Promise.all([databaseInfo(), readOps(localDay(now, config.timezone))]);
    res.render('system', {
      title: 'System',
      activeNav: 'system',
      info: {
        version: appVersion,
        nodeVersion: process.version,
        runtime: detectRuntime(),
        nodeEnv: config.nodeEnv,
        timezone: config.timezone,
        localNow: localDateTime(now, config.timezone),
        uptime: humanDuration(process.uptime()),
        publicBaseUrl: config.publicBaseUrl,
      },
      database,
      ops,
      warnings: warningsFor(ops, database, now),
      requestRows: requestAsSeen(req),
    });
  });

  // Used by the "Check client IP" button: called once plainly and once with a
  // forged X-Forwarded-For. If the forged address comes back, TRUST_PROXY
  // trusts more hops than the real proxy chain has.
  router.get('/system/ip-check', (req, res) => {
    res.set('Cache-Control', 'no-store');
    res.json({ ip: clientIp(req) });
  });

  return router;
}

module.exports = createSystemRouter;
module.exports.createSystemRouter = createSystemRouter;
