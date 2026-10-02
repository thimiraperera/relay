'use strict';

// Periodic housekeeping. The hourly cPanel cron (scripts/cleanup.js) is the
// primary trigger because LiteSpeed stops idle Node processes; the in-process
// timer is a supplement for busy instances. A named lock keeps concurrent runs
// (cron + timers in several workers) from overlapping.
//
// kv keys: cleanup.last_run and cleanup.last_result are written by every
// finished run, whatever started it. cleanup.last_cron_run is written only by
// the cron script (recordCronRun), so Admin > System can tell whether the cron
// itself runs: the in-process timer, which runs a minute after every start,
// would otherwise hide a dead cron.

const { markStaleSending, deleteMessagesBefore } = require('../repos/messages');
const { deleteIdempotencyBefore } = require('../repos/idempotency');
const { deleteExpiredCounters } = require('../repos/rateCounters');
const { setKv } = require('../repos/kv');
const { describeError } = require('../lib/logger');

const DAY_MS = 24 * 60 * 60 * 1000;
const MESSAGE_BATCH = 5000;
const FIRST_RUN_DELAY_MS = 60 * 1000;
const SESSION_SWEEP_MS = 15 * 60 * 1000;
const CRON_RUN_KEY = 'cleanup.last_cron_run';

async function deleteExpiredSessions(deps) {
  const nowSeconds = Math.floor(deps.clock.now().getTime() / 1000);
  const res = await deps.db.query('DELETE FROM sessions WHERE expires < ?', [nowSeconds]);
  return res.affectedRows;
}

async function cleanupOnce(deps) {
  const { db, config } = deps;
  const now = deps.clock.now();
  const nowMs = now.getTime();

  const unknownMarked = await markStaleSending(db, new Date(nowMs - config.staleSendingMs), now);
  const sessionsDeleted = await deleteExpiredSessions(deps);
  const idempotencyDeleted = await deleteIdempotencyBefore(db, new Date(nowMs - config.idempotencyDays * DAY_MS));

  const messageCutoff = new Date(nowMs - config.logRetentionDays * DAY_MS);
  let messagesDeleted = 0;
  for (;;) {
    const n = await deleteMessagesBefore(db, messageCutoff, MESSAGE_BATCH);
    messagesDeleted += n;
    if (n < MESSAGE_BATCH) break;
  }

  const countersDeleted = await deleteExpiredCounters(db, now);
  const result = { unknownMarked, sessionsDeleted, idempotencyDeleted, messagesDeleted, countersDeleted };
  await setKv(db, 'cleanup.last_run', now.toISOString(), now);
  await setKv(db, 'cleanup.last_result', JSON.stringify(result), now);
  return result;
}

async function runCleanup(deps) {
  const { acquired, result } = await deps.db.withNamedLock('cleanup', 0, () => cleanupOnce(deps));
  if (!acquired) {
    deps.logger.warn('cleanup skipped: another cleanup is running');
    return {
      unknownMarked: 0,
      sessionsDeleted: 0,
      idempotencyDeleted: 0,
      messagesDeleted: 0,
      countersDeleted: 0,
      skipped: true,
    };
  }
  deps.logger.info('cleanup finished', result);
  return { ...result, skipped: false };
}

// Called by scripts/cleanup.js after runCleanup resolved, also when the run was
// skipped because another cleanup held the lock (the cron itself fired). Not
// called by the in-process timer. → the recorded time (Date).
async function recordCronRun(deps) {
  const now = deps.clock.now();
  await setKv(deps.db, CRON_RUN_KEY, now.toISOString(), now);
  return now;
}

// Starts the in-process timers (all unref'd so they never keep the process
// alive) and returns a function that stops them. CLEANUP_INTERVAL_MINUTES=0
// disables in-process cleanup entirely (cron only).
function startCleanupTimer(deps) {
  const minutes = deps.config.cleanupIntervalMinutes;
  if (!(minutes > 0)) return () => {};

  const timers = [];
  let running = false;
  const runSafely = async () => {
    if (running) return;
    running = true;
    try {
      await runCleanup(deps);
    } catch (err) {
      deps.logger.error('cleanup failed', { err });
    } finally {
      running = false;
    }
  };
  const sweepSessions = async () => {
    try {
      await deleteExpiredSessions(deps);
    } catch (err) {
      deps.logger.warn('session sweep failed', { error: describeError(err) });
    }
  };

  const first = setTimeout(() => {
    runSafely();
    const every = setInterval(runSafely, minutes * 60 * 1000);
    every.unref();
    timers.push(every);
  }, FIRST_RUN_DELAY_MS);
  first.unref();
  timers.push(first);

  const sessions = setInterval(sweepSessions, SESSION_SWEEP_MS);
  sessions.unref();
  timers.push(sessions);

  return function stopCleanupTimer() {
    for (const t of timers) {
      clearTimeout(t);
      clearInterval(t);
    }
    timers.length = 0;
  };
}

module.exports = { runCleanup, startCleanupTimer, deleteExpiredSessions, recordCronRun, CRON_RUN_KEY };
