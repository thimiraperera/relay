'use strict';

// The cleanup job (src/services/cleanup.js). Idempotency, replay protection and
// the "outcome unknown" lock (docs/SPEC.md decision 5) depend on it not deleting
// anything early.
//
// runCleanup is global, and the other test files run at the same time against
// the same database with clocks at (or after) real time. So this file never
// moves its clock: it stays at real now, and the rows under test are backdated
// instead. Every other file's rows are then younger than every cutoff, and the
// assertions only look at rows created here, never at the global counts.

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const h = require('./support/helpers');
const { runCleanup } = require('../src/services/cleanup');
const { insertMessage, completeMessage, getMessage } = require('../src/repos/messages');
const { insertIdempotency, findIdempotency } = require('../src/repos/idempotency');
const { incrementCounter, getCounter } = require('../src/repos/rateCounters');
const { getKv } = require('../src/repos/kv');
const { localDay } = require('../src/lib/time');

const T = { timeout: 30000 };
const MINUTE = 60 * 1000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

describe('cleanup job', () => {
  let deps;
  let smtp;
  let httpApp;

  before(async () => {
    if (!h.dbAvailable()) return;
    smtp = await h.startSmtpServer();
    deps = h.createTestDeps({ clock: h.createFakeClock(new Date()) });
    httpApp = h.createHttpApp(deps);
  });

  after(async () => {
    if (smtp) await smtp.close();
    if (deps) await deps.db.close();
  });

  const ago = (ms) => new Date(deps.clock.now().getTime() - ms);

  // A messages row as a request at `createdAt` would have left it.
  async function seedMessage(app, { createdAt, status, messageId = null }) {
    const id = await insertMessage(deps.db, {
      publicId: 'msg_' + h.uniqueId() + h.uniqueId(),
      appId: app.id,
      apiKeyId: null,
      source: 'api',
      clientMessageId: messageId,
      status: 'sending',
      day: localDay(createdAt, deps.config.timezone),
      createdAt,
      fromEmail: app.fromEmail,
      toAddrs: ['seed@example.com'],
      ccAddrs: [],
      bccAddrs: [],
      recipientCount: 1,
      subject: 'seeded',
      sizeBytes: 10,
      attachmentCount: 0,
      error: null,
      httpStatus: null,
      clientIp: null,
    });
    if (status !== 'sending') await completeMessage(deps.db, id, { status, completedAt: createdAt, httpStatus: 200 });
    return id;
  }

  async function cleanup() {
    const result = await runCleanup(deps);
    assert.equal(result.skipped, false);
    return result;
  }

  it('marks a send interrupted for more than 10 minutes as unknown, which keeps its id locked', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { app, key } = await h.insertTestApp(deps, { smtp });
    const staleId = h.uniqueName('stale');
    const staleAt = ago(11 * MINUTE);
    const stale = await seedMessage(app, { createdAt: staleAt, status: 'sending', messageId: staleId });
    assert.equal(await insertIdempotency(deps.db, app.id, staleId, stale, staleAt), true);
    const young = await seedMessage(app, { createdAt: ago(9 * MINUTE), status: 'sending' });

    await cleanup();
    const marked = await getMessage(deps.db, stale);
    assert.equal(marked.status, 'unknown');
    assert.equal(marked.error, 'interrupted: outcome unknown');
    assert.equal(marked.completedAt.getTime(), deps.clock.now().getTime());
    assert.equal((await getMessage(deps.db, young)).status, 'sending', 'a 9-minute-old send is left alone');

    const to = h.uniqueEmail();
    const retry = await h.postV1(httpApp, key, { to, subject: 's', text: 't', message_id: staleId });
    assert.equal(retry.status, 409);
    assert.deepEqual(retry.body, { ok: false, error: 'message_id outcome unknown' });
    assert.equal(smtp.messagesTo(to).length, 0);
  });

  it('keeps an idempotency entry for IDEMPOTENCY_DAYS and deletes it after that', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { app, key } = await h.insertTestApp(deps, { smtp });
    const keptId = h.uniqueName('kept');
    const goneId = h.uniqueName('gone');
    const keptAt = ago(6 * DAY + 23 * HOUR);
    const goneAt = ago(7 * DAY + HOUR);
    const kept = await seedMessage(app, { createdAt: keptAt, status: 'sent', messageId: keptId });
    const gone = await seedMessage(app, { createdAt: goneAt, status: 'sent', messageId: goneId });
    await insertIdempotency(deps.db, app.id, keptId, kept, keptAt);
    await insertIdempotency(deps.db, app.id, goneId, gone, goneAt);

    await cleanup();
    assert.ok(await findIdempotency(deps.db, app.id, keptId), 'kept inside the window');
    assert.equal(await findIdempotency(deps.db, app.id, goneId), null, 'deleted after the window');

    // Inside the window a repeat is still answered with the first result.
    const to = h.uniqueEmail();
    const repeat = await h.postV1(httpApp, key, { to, subject: 's', text: 't', message_id: keptId });
    assert.equal(repeat.status, 200, JSON.stringify(repeat.body));
    assert.equal(repeat.headers['idempotent-replayed'], 'true');
    assert.equal(repeat.body.id, (await getMessage(deps.db, kept)).publicId);
    assert.equal(smtp.messagesTo(to).length, 0, 'not sent again');
  });

  it('deletes messages after LOG_RETENTION_DAYS and keeps younger ones', T, async (t) => {
    if (!h.requireDb(t)) return;
    assert.equal(deps.config.logRetentionDays, 90);
    const { app } = await h.insertTestApp(deps, { smtp, withKey: false });
    const kept = await seedMessage(app, { createdAt: ago(89 * DAY), status: 'sent' });
    const gone = await seedMessage(app, { createdAt: ago(91 * DAY), status: 'failed' });
    await cleanup();
    assert.ok(await getMessage(deps.db, kept));
    assert.equal(await getMessage(deps.db, gone), null);
  });

  it('deletes expired sessions and rate counters, keeps live ones', T, async (t) => {
    if (!h.requireDb(t)) return;
    const nowSeconds = Math.floor(deps.clock.now().getTime() / 1000);
    const sid = () => crypto.randomBytes(32).toString('hex');
    const [deadSession, liveSession] = [sid(), sid()];
    await deps.db.query('INSERT INTO sessions (session_id, expires, data) VALUES (?, ?, ?), (?, ?, ?)', [
      deadSession,
      nowSeconds - 1,
      '{}',
      liveSession,
      nowSeconds + 3600,
      '{}',
    ]);
    const deadCounter = h.uniqueName('cleanup-test:dead');
    const liveCounter = h.uniqueName('cleanup-test:live');
    await incrementCounter(deps.db, deadCounter, ago(1000));
    await incrementCounter(deps.db, liveCounter, new Date(deps.clock.now().getTime() + MINUTE));

    await cleanup();
    const sessions = await deps.db.query('SELECT session_id FROM sessions WHERE session_id IN (?, ?)', [deadSession, liveSession]);
    assert.deepEqual(
      sessions.map((r) => r.session_id),
      [liveSession]
    );
    assert.equal(await getCounter(deps.db, deadCounter), 0);
    assert.equal(await getCounter(deps.db, liveCounter), 1);
    await deps.db.query('DELETE FROM sessions WHERE session_id = ?', [liveSession]);
  });

  it('keeps the replay nonce of a signed request for as long as its timestamp is accepted', T, async (t) => {
    if (!h.requireDb(t)) return;
    const legacy = await h.insertTestApp(deps, { smtp, legacySigning: true });
    const to = h.uniqueEmail();
    const raw = JSON.stringify({ to, subject: 'No id', html: '<p>no message_id</p>' });
    // A timestamp at the old edge of the window: still accepted for 1 second.
    const ts = String(Math.floor(deps.clock.now().getTime() / 1000) - deps.config.legacyMaxSkewSeconds + 1);
    const signature = h.signLegacy(legacy.key, ts, raw);
    const first = await h.postLegacy(httpApp, deps, legacy.key, raw, { ts });
    assert.equal(first.status, 200, JSON.stringify(first.body));

    const [nonce] = await deps.db.query('SELECT expires_at FROM rate_counters WHERE k = ?', [
      'legacysig:' + signature.slice('sha256='.length),
    ]);
    assert.ok(nonce, 'the signature is remembered');
    const acceptedUntil = (Number(ts) + deps.config.legacyMaxSkewSeconds) * 1000;
    assert.ok(nonce.expires_at.getTime() >= acceptedUntil, 'remembered at least until the timestamp is no longer accepted');
    // ...and not much longer (timestamp + allowed skew + 60 s), so cleanup
    // removes it soon after.
    assert.ok(nonce.expires_at.getTime() <= acceptedUntil + 120 * 1000, `expires ${nonce.expires_at.toISOString()}`);

    await cleanup();
    const replay = await h.postLegacy(httpApp, deps, legacy.key, raw, { ts });
    assert.equal(replay.status, 409);
    assert.deepEqual(replay.body, { error: 'replayed request' });
    assert.equal(smtp.messagesTo(to).length, 1);
  });

  it('records each run and skips a run while another one holds the lock', T, async (t) => {
    if (!h.requireDb(t)) return;
    const result = await cleanup();
    for (const k of ['unknownMarked', 'sessionsDeleted', 'idempotencyDeleted', 'messagesDeleted', 'countersDeleted']) {
      assert.ok(Number.isInteger(result[k]) && result[k] >= 0, k);
    }
    assert.equal(await getKv(deps.db, 'cleanup.last_run'), deps.clock.now().toISOString());
    const recorded = JSON.parse(await getKv(deps.db, 'cleanup.last_result'));
    assert.equal(typeof recorded.messagesDeleted, 'number');

    const outer = await deps.db.withNamedLock('cleanup', 0, async () => runCleanup(deps));
    assert.equal(outer.acquired, true);
    assert.equal(outer.result.skipped, true, 'a second run while one is running is skipped');
  });
});
