'use strict';

// message_id idempotency on /v1/send (docs/SPEC.md decisions 1 and 5): a sent message
// is never sent twice within IDEMPOTENCY_DAYS, a failed or rejected attempt may
// be retried, and an attempt still in flight or with an unknown outcome locks
// the id.

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const { SMTPServer } = require('smtp-server');
const h = require('./support/helpers');
const appsRepo = require('../src/repos/apps');
const { insertMessage, completeMessage } = require('../src/repos/messages');
const { insertIdempotency, findIdempotency, reassignIdempotency } = require('../src/repos/idempotency');
const { localDay } = require('../src/lib/time');
const { inFlightSends, waitForSendsIdle } = require('../src/services/send');

const T = { timeout: 30000 };
const MINUTE = 60 * 1000;
const DAY = 24 * 60 * MINUTE;

function message(to, messageId, extra = {}) {
  return { to, subject: 'Idempotency test', text: 'Hello', message_id: messageId, ...extra };
}

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.removeListener('error', reject);
      resolve(server.address().port);
    });
  });
}

async function rowsFor(deps, appId, messageId) {
  return (await h.listMessages(deps, appId)).filter((r) => r.clientMessageId === messageId);
}

describe('idempotency (/v1/send message_id)', () => {
  let deps;
  let smtp;
  let httpApp;

  before(async () => {
    if (!h.dbAvailable()) return;
    smtp = await h.startSmtpServer();
    deps = h.createTestDeps({ clock: h.createFakeClock() });
    httpApp = h.createHttpApp(deps);
  });

  after(async () => {
    if (smtp) await smtp.close();
    if (deps) await deps.db.close();
  });

  // A messages row plus an idempotency entry pointing at it, as a request that
  // died (or is still running) would leave them.
  async function seedAttempt(app, messageId, { status, ageMs }) {
    const createdAt = new Date(deps.clock.now().getTime() - ageMs);
    const rowId = await insertMessage(deps.db, {
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
    if (status !== 'sending') {
      await completeMessage(deps.db, rowId, { status, completedAt: createdAt, error: 'seeded' });
    }
    assert.equal(await insertIdempotency(deps.db, app.id, messageId, rowId, createdAt), true);
    return rowId;
  }

  it('returns the first result for a repeated message_id and delivers once', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { app, key } = await h.insertTestApp(deps, { smtp });
    const to = h.uniqueEmail();
    const id = h.uniqueName('order');

    const first = await h.postV1(httpApp, key, message(to, id));
    assert.equal(first.status, 200, JSON.stringify(first.body));
    assert.equal(first.body.ok, true);
    assert.match(first.body.id, /^msg_[0-9a-f]{24}$/);
    assert.equal(first.headers['idempotent-replayed'], undefined);

    const second = await h.postV1(httpApp, key, message(to, id, { subject: 'Changed subject' }));
    assert.equal(second.status, 200);
    assert.deepEqual(second.body, { ok: true, id: first.body.id });
    assert.equal(second.headers['idempotent-replayed'], 'true');

    assert.equal(smtp.messagesTo(to).length, 1);
    const rows = (await h.listMessages(deps, app.id)).filter((r) => r.clientMessageId === id);
    assert.equal(rows.length, 1, 'the replay writes no second log row');
    assert.equal(rows[0].status, 'sent');
    assert.equal(rows[0].publicId, first.body.id);
  });

  it('lets a failed attempt be retried and then delivers exactly once', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { app, key } = await h.insertTestApp(deps, { smtp });
    const to = h.uniqueEmail();
    const id = h.uniqueName('retry');

    smtp.setFailure(550);
    let res;
    try {
      res = await h.postV1(httpApp, key, message(to, id));
    } finally {
      smtp.setFailure(null);
    }
    assert.equal(res.status, 502);
    assert.deepEqual(res.body, { ok: false, error: 'smtp error: EMESSAGE 550' });
    assert.equal(smtp.messagesTo(to).length, 0);

    const retry = await h.postV1(httpApp, key, message(to, id));
    assert.equal(retry.status, 200, JSON.stringify(retry.body));
    const again = await h.postV1(httpApp, key, message(to, id));
    assert.equal(again.status, 200);
    assert.equal(again.body.id, retry.body.id);
    assert.equal(again.headers['idempotent-replayed'], 'true');
    assert.equal(smtp.messagesTo(to).length, 1);

    const rows = (await h.listMessages(deps, app.id)).filter((r) => r.clientMessageId === id);
    assert.deepEqual(
      rows.map((r) => r.status),
      ['failed', 'sent']
    );
    const entry = await findIdempotency(deps.db, app.id, id);
    assert.equal(entry.message.publicId, retry.body.id);
  });

  it('lets a rejected request be retried with the same message_id', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { key } = await h.insertTestApp(deps, { smtp });
    const to = h.uniqueEmail();
    const id = h.uniqueName('rejected');
    const bad = await h.postV1(httpApp, key, message('not-an-address', id));
    assert.equal(bad.status, 400);
    assert.deepEqual(bad.body, { ok: false, error: 'invalid to address' });
    const good = await h.postV1(httpApp, key, message(to, id));
    assert.equal(good.status, 200, JSON.stringify(good.body));
    assert.equal(smtp.messagesTo(to).length, 1);
  });

  it('delivers once when duplicates arrive concurrently', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { key } = await h.insertTestApp(deps, { smtp });
    const to = h.uniqueEmail();
    const id = h.uniqueName('race');
    const results = await Promise.all([
      h.postV1(httpApp, key, message(to, id)),
      h.postV1(httpApp, key, message(to, id)),
      h.postV1(httpApp, key, message(to, id)),
    ]);
    const ok = results.filter((r) => r.status === 200);
    const busy = results.filter((r) => r.status === 409);
    assert.equal(ok.length + busy.length, results.length, results.map((r) => `${r.status} ${JSON.stringify(r.body)}`).join('; '));
    assert.ok(ok.length >= 1);
    assert.equal(new Set(ok.map((r) => r.body.id)).size, 1, 'every 200 carries the same id');
    for (const r of busy) assert.deepEqual(r.body, { ok: false, error: 'message_id is already being sent' });
    assert.equal(smtp.messagesTo(to).length, 1);
  });

  it('takes over an id only from the attempt it read (compare-and-swap)', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { app } = await h.insertTestApp(deps, { smtp, withKey: false });
    const key = h.uniqueName('cas-repo');
    const now = deps.clock.now();
    // idempotency_keys.message_id has no foreign key: plain numbers will do.
    const [rowA, staleRowB, rowC] = [900000001, 900000002, 900000003];
    assert.equal(await insertIdempotency(deps.db, app.id, key, rowA, now), true);
    assert.equal(await insertIdempotency(deps.db, app.id, key, rowC, now), false, 'duplicate insert refused');

    assert.equal(await reassignIdempotency(deps.db, app.id, key, staleRowB, rowC, now), false, 'stale expectation');
    assert.equal((await findIdempotency(deps.db, app.id, key)).messageId, rowA);

    assert.equal(await reassignIdempotency(deps.db, app.id, key, rowA, rowC, now), true);
    assert.equal((await findIdempotency(deps.db, app.id, key)).messageId, rowC);
    assert.equal(await reassignIdempotency(deps.db, app.id, key, rowA, staleRowB, now), false, 'only once');
  });

  it('lets exactly one of several concurrent retries of a failed id send', T, async (t) => {
    if (!h.requireDb(t)) return;
    const N = 5;
    // Own deps: its query function is wrapped below.
    const local = h.createTestDeps({ clock: h.createFakeClock() });
    const localApp = h.createHttpApp(local);
    const original = local.db.query;
    let fallback = null;
    try {
      const { app, key } = await h.insertTestApp(local, { smtp });
      const to = h.uniqueEmail();
      const id = h.uniqueName('cas-http');
      smtp.setFailure(550);
      let first;
      try {
        first = await h.postV1(localApp, key, message(to, id));
      } finally {
        smtp.setFailure(null);
      }
      assert.equal(first.status, 502);

      // Hold every compare-and-swap UPDATE until all N retries have read the
      // failed attempt, so they all race for the same takeover. (The natural
      // race rarely overlaps that closely.) The gate waits before a connection
      // is taken, so it cannot exhaust the pool.
      let arrived = 0;
      let release;
      const gate = new Promise((resolve) => {
        release = resolve;
      });
      fallback = setTimeout(() => release(), 5000);
      local.db.query = async (sql, params) => {
        if (/^\s*UPDATE idempotency_keys/i.test(sql)) {
          arrived++;
          if (arrived >= N) release();
          await gate;
        }
        return original(sql, params);
      };
      const results = await Promise.all(Array.from({ length: N }, () => h.postV1(localApp, key, message(to, id))));
      local.db.query = original;
      const summary = results.map((r) => `${r.status} ${JSON.stringify(r.body)}`).join('; ');
      assert.equal(arrived, N, `every retry reached the compare-and-swap (${summary})`);

      const ok = results.filter((r) => r.status === 200);
      const busy = results.filter((r) => r.status === 409);
      assert.equal(ok.length, 1, summary);
      assert.equal(busy.length, N - 1, summary);
      for (const r of busy) assert.deepEqual(r.body, { ok: false, error: 'message_id is already being sent' });
      assert.equal(smtp.messagesTo(to).length, 1, 'delivered exactly once');
      // The losers' own rows were discarded.
      assert.deepEqual(
        (await rowsFor(local, app.id, id)).map((r) => r.status),
        ['failed', 'sent']
      );
      const again = await h.postV1(localApp, key, message(to, id));
      assert.equal(again.status, 200);
      assert.equal(again.body.id, ok[0].body.id);
    } finally {
      clearTimeout(fallback);
      local.db.query = original;
      await local.db.close();
    }
  });

  it('answers 409 while the first attempt is still sending', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { key } = await h.insertTestApp(deps, { smtp });
    const to = h.uniqueEmail();
    const id = h.uniqueName('inflight');

    smtp.setStall(true);
    let first;
    try {
      first = h.postV1(httpApp, key, message(to, id)).then((r) => r);
      await h.waitFor(() => smtp.stalledCount === 1, { what: 'the first send to reach DATA' });
      const second = await h.postV1(httpApp, key, message(to, id));
      assert.equal(second.status, 409);
      assert.deepEqual(second.body, { ok: false, error: 'message_id is already being sent' });
    } finally {
      smtp.setStall(false);
    }
    const firstRes = await first;
    assert.equal(firstRes.status, 200, JSON.stringify(firstRes.body));
    const third = await h.postV1(httpApp, key, message(to, id));
    assert.equal(third.status, 200);
    assert.equal(third.body.id, firstRes.body.id);
    assert.equal(smtp.messagesTo(to).length, 1);
  });

  // Graceful shutdown waits on this so a restart does not cut
  // a send off midway and leave an 'unknown' row that locks the message_id.
  it('tracks sends in flight until their outcome is recorded', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { app, key } = await h.insertTestApp(deps, { smtp });
    const to = h.uniqueEmail();
    const id = h.uniqueName('drain');
    assert.equal(inFlightSends(), 0);
    assert.equal(await waitForSendsIdle(10), true, 'idle at once when nothing is sending');

    smtp.setStall(true);
    let pending;
    try {
      pending = h.postV1(httpApp, key, message(to, id)).then((r) => r);
      await h.waitFor(() => smtp.stalledCount === 1, { what: 'the send to reach DATA' });
      assert.equal(inFlightSends(), 1);
      assert.equal(await waitForSendsIdle(50), false, 'not idle while the server holds the message');
      const idle = waitForSendsIdle(10000);
      smtp.setStall(false);
      assert.equal(await idle, true);
    } finally {
      smtp.setStall(false);
    }
    // Idle means the outcome is already recorded, before the response is read.
    assert.deepEqual(
      (await rowsFor(deps, app.id, id)).map((r) => r.status),
      ['sent']
    );
    assert.equal(inFlightSends(), 0);
    assert.equal((await pending).status, 200);
  });

  it('keeps ids separate per app', T, async (t) => {
    if (!h.requireDb(t)) return;
    const a = await h.insertTestApp(deps, { smtp });
    const b = await h.insertTestApp(deps, { smtp });
    const to = h.uniqueEmail();
    const id = h.uniqueName('shared');
    const ra = await h.postV1(httpApp, a.key, message(to, id));
    const rb = await h.postV1(httpApp, b.key, message(to, id));
    assert.equal(ra.status, 200);
    assert.equal(rb.status, 200);
    assert.notEqual(ra.body.id, rb.body.id);
    assert.equal(rb.headers['idempotent-replayed'], undefined);
    assert.equal(smtp.messagesTo(to).length, 2);
  });

  it('remembers an id for 7 days and sends again after that', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { key } = await h.insertTestApp(deps, { smtp });
    const to = h.uniqueEmail();
    const id = h.uniqueName('weekly');

    const first = await h.postV1(httpApp, key, message(to, id));
    assert.equal(first.status, 200);

    deps.clock.advance(6 * DAY + 23 * 60 * MINUTE);
    const withinWindow = await h.postV1(httpApp, key, message(to, id));
    assert.equal(withinWindow.status, 200);
    assert.equal(withinWindow.body.id, first.body.id);
    assert.equal(smtp.messagesTo(to).length, 1);

    deps.clock.advance(2 * 60 * MINUTE);
    const afterWindow = await h.postV1(httpApp, key, message(to, id));
    assert.equal(afterWindow.status, 200, JSON.stringify(afterWindow.body));
    assert.notEqual(afterWindow.body.id, first.body.id);
    assert.equal(afterWindow.headers['idempotent-replayed'], undefined);
    assert.equal(smtp.messagesTo(to).length, 2);
  });

  it('locks an id whose attempt has been sending for longer than 10 minutes', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { app, key } = await h.insertTestApp(deps, { smtp });
    const to = h.uniqueEmail();
    const id = h.uniqueName('stale');
    await seedAttempt(app, id, { status: 'sending', ageMs: 11 * MINUTE });
    const before = (await h.listMessages(deps, app.id)).length;

    const res = await h.postV1(httpApp, key, message(to, id));
    assert.equal(res.status, 409);
    assert.deepEqual(res.body, { ok: false, error: 'message_id outcome unknown' });
    assert.equal(smtp.messagesTo(to).length, 0);
    assert.equal((await h.listMessages(deps, app.id)).length, before, 'a locked id is not logged as rejected');
  });

  it('locks an id whose attempt has an unknown outcome for the whole window', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { app, key } = await h.insertTestApp(deps, { smtp });
    const to = h.uniqueEmail();
    const id = h.uniqueName('unknown');
    await seedAttempt(app, id, { status: 'unknown', ageMs: 20 * MINUTE });

    const res = await h.postV1(httpApp, key, message(to, id));
    assert.equal(res.status, 409);
    assert.deepEqual(res.body, { ok: false, error: 'message_id outcome unknown' });

    deps.clock.advance(6 * DAY);
    const later = await h.postV1(httpApp, key, message(to, id));
    assert.equal(later.status, 409);
    assert.deepEqual(later.body, { ok: false, error: 'message_id outcome unknown' });
    assert.equal(smtp.messagesTo(to).length, 0);
  });

  it('answers "already being sent" for a recent sending attempt', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { app, key } = await h.insertTestApp(deps, { smtp });
    const to = h.uniqueEmail();
    const id = h.uniqueName('young');
    await seedAttempt(app, id, { status: 'sending', ageMs: 1 * MINUTE });
    const res = await h.postV1(httpApp, key, message(to, id));
    assert.equal(res.status, 409);
    assert.deepEqual(res.body, { ok: false, error: 'message_id is already being sent' });
    assert.equal(smtp.messagesTo(to).length, 0);
  });

  it('refuses an empty or over-long message_id', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { key } = await h.insertTestApp(deps, { smtp });
    for (const bad of ['', 'x'.repeat(192), { id: 1 }, -1, 1.5]) {
      const res = await h.postV1(httpApp, key, message(h.uniqueEmail(), bad));
      assert.equal(res.status, 400, JSON.stringify(bad));
      assert.deepEqual(res.body, { ok: false, error: 'invalid message_id' });
    }
    const ok = await h.postV1(httpApp, key, message(h.uniqueEmail(), 'x'.repeat(191)));
    assert.equal(ok.status, 200, JSON.stringify(ok.body));
  });
});

// How an SMTP failure decides whether the message_id may be retried
// (docs/SPEC.md decisions 1 and 5): a failure before any message data
// reached the server is 'failed' and retryable; a network failure after the
// data started (no reply to the final dot, the overall deadline) is 'unknown'
// and locks the id, because the server may already have accepted the message.
describe('SMTP failures and message_id locking', () => {
  let deps;
  let smtp;
  let httpApp;
  const extraServers = [];

  before(async () => {
    if (!h.dbAvailable()) return;
    smtp = await h.startSmtpServer();
    // Short per-phase timeout so a stalled server gives up quickly.
    deps = h.createTestDeps({ clock: h.createFakeClock(), configOverrides: { smtpTimeoutMs: 1500 } });
    httpApp = h.createHttpApp(deps);
  });

  after(async () => {
    for (const close of extraServers) await close();
    if (smtp) await smtp.close();
    if (deps) await deps.db.close();
  });

  async function pointAt(app, port) {
    await appsRepo.updateApp(deps.db, app.id, { smtpPort: port }, deps.clock.now());
  }

  it('locks the id when the server never answers the final dot (outcome unknown)', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { app, key } = await h.insertTestApp(deps, { smtp });
    const to = h.uniqueEmail();
    const id = h.uniqueName('no-reply');

    smtp.setStall(true);
    let first;
    let retry;
    try {
      first = await h.postV1(httpApp, key, message(to, id));
      // The server holds the whole message and has not answered yet.
      assert.equal(smtp.stalledCount, 1);
      retry = await h.postV1(httpApp, key, message(to, id));
    } finally {
      // The server now "commits" the message it was holding.
      smtp.setStall(false);
    }
    assert.equal(first.status, 502);
    assert.deepEqual(first.body, { ok: false, error: 'smtp error: ETIMEDOUT (outcome unknown)' });
    assert.equal(retry.status, 409);
    assert.deepEqual(retry.body, { ok: false, error: 'message_id outcome unknown' });

    const rows = await rowsFor(deps, app.id, id);
    assert.equal(rows.length, 1, 'the refused retry writes no row');
    assert.equal(rows[0].status, 'unknown');
    assert.equal(rows[0].httpStatus, 502);
    assert.match(rows[0].error, /outcome unknown/);

    await h.waitFor(() => smtp.messagesTo(to).length === 1, { what: 'the held message to be committed' });
    const later = await h.postV1(httpApp, key, message(to, id));
    assert.equal(later.status, 409);
    assert.deepEqual(later.body, { ok: false, error: 'message_id outcome unknown' });
    assert.equal(smtp.messagesTo(to).length, 1, 'never delivered a second time');
  });

  it('ends a stalled send at the overall deadline and locks the id', T, async (t) => {
    if (!h.requireDb(t)) return;
    const deadlineMs = 2000;
    // Per-phase timeout far longer than the deadline: only the deadline can end it.
    const local = h.createTestDeps({
      clock: h.createFakeClock(),
      configOverrides: { smtpTimeoutMs: 30000, smtpSendDeadlineMs: deadlineMs },
    });
    try {
      const localApp = h.createHttpApp(local);
      const { app, key } = await h.insertTestApp(local, { smtp });
      const to = h.uniqueEmail();
      const id = h.uniqueName('deadline');
      smtp.setStall(true);
      let res;
      let ms;
      try {
        const started = Date.now();
        res = await h.postV1(localApp, key, message(to, id));
        ms = Date.now() - started;
      } finally {
        smtp.setStall(false);
      }
      assert.equal(res.status, 502);
      assert.deepEqual(res.body, { ok: false, error: 'smtp error: ETIMEDOUT (outcome unknown)' });
      assert.ok(ms >= deadlineMs - 500 && ms < deadlineMs + 3000, `took ${ms} ms`);
      assert.equal((await rowsFor(local, app.id, id))[0].status, 'unknown');
      const retry = await h.postV1(localApp, key, message(to, id));
      assert.equal(retry.status, 409);
      assert.deepEqual(retry.body, { ok: false, error: 'message_id outcome unknown' });
    } finally {
      await local.db.close();
    }
  });

  it('keeps a recipient refused at RCPT retryable (failed)', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { app, key } = await h.insertTestApp(deps, { smtp });
    const to = h.uniqueEmail();
    const id = h.uniqueName('rcpt-550');
    smtp.rejectRcpt(to, 550);
    let first;
    try {
      first = await h.postV1(httpApp, key, message(to, id));
    } finally {
      smtp.rejectRcpt(to, null);
    }
    assert.equal(first.status, 502);
    assert.deepEqual(first.body, { ok: false, error: 'smtp error: EENVELOPE 550' });
    assert.equal(smtp.messagesTo(to).length, 0);

    const retry = await h.postV1(httpApp, key, message(to, id));
    assert.equal(retry.status, 200, JSON.stringify(retry.body));
    assert.equal(smtp.messagesTo(to).length, 1);
    assert.deepEqual(
      (await rowsFor(deps, app.id, id)).map((r) => r.status),
      ['failed', 'sent']
    );
  });

  it('keeps a refused connection retryable (failed)', T, async (t) => {
    if (!h.requireDb(t)) return;
    // A port that was just free: nothing listens there any more.
    const probe = net.createServer();
    const closedPort = await listen(probe);
    await new Promise((resolve) => probe.close(resolve));

    const { app, key } = await h.insertTestApp(deps, { smtp, smtpPort: closedPort });
    const to = h.uniqueEmail();
    const id = h.uniqueName('refused');
    const first = await h.postV1(httpApp, key, message(to, id));
    assert.equal(first.status, 502);
    assert.match(first.body.error, /^smtp error: [A-Z]+$/, 'no response code, not "outcome unknown"');
    assert.equal((await rowsFor(deps, app.id, id))[0].status, 'failed');

    await pointAt(app, smtp.port);
    const retry = await h.postV1(httpApp, key, message(to, id));
    assert.equal(retry.status, 200, JSON.stringify(retry.body));
    assert.equal(smtp.messagesTo(to).length, 1);
  });

  it('keeps a server that never greets retryable (failed, not unknown)', T, async (t) => {
    if (!h.requireDb(t)) return;
    const sockets = new Set();
    const silent = net.createServer((socket) => {
      sockets.add(socket);
      socket.on('error', () => {});
      socket.on('close', () => sockets.delete(socket));
    });
    const silentPort = await listen(silent);
    extraServers.push(() => {
      for (const s of sockets) s.destroy();
      return new Promise((resolve) => silent.close(resolve));
    });

    const { app, key } = await h.insertTestApp(deps, { smtp, smtpPort: silentPort });
    const to = h.uniqueEmail();
    const id = h.uniqueName('no-greeting');
    const first = await h.postV1(httpApp, key, message(to, id));
    assert.equal(first.status, 502);
    assert.deepEqual(first.body, { ok: false, error: 'smtp error: ETIMEDOUT' });
    assert.equal((await rowsFor(deps, app.id, id))[0].status, 'failed');

    await pointAt(app, smtp.port);
    const retry = await h.postV1(httpApp, key, message(to, id));
    assert.equal(retry.status, 200, JSON.stringify(retry.body));
    assert.equal(smtp.messagesTo(to).length, 1);
  });

  it('refuses an untrusted TLS certificate with 502 and sends nothing', T, async (t) => {
    if (!h.requireDb(t)) return;
    let delivered = 0;
    // smtp-server's bundled self-signed certificate: no client may trust it.
    const tlsServer = new SMTPServer({
      secure: true,
      authOptional: true,
      logger: false,
      closeTimeout: 500,
      onData(stream, session, callback) {
        delivered++;
        stream.resume();
        stream.on('end', () => callback());
      },
    });
    tlsServer.on('error', () => {});
    const tlsPort = await listen(tlsServer.server);
    extraServers.push(() => new Promise((resolve) => tlsServer.close(resolve)));

    const { app, key } = await h.insertTestApp(deps, { smtp, smtpPort: tlsPort, smtpEncryption: 'ssl' });
    const to = h.uniqueEmail();
    const id = h.uniqueName('tls');
    const res = await h.postV1(httpApp, key, message(to, id));
    assert.equal(res.status, 502);
    assert.deepEqual(res.body, { ok: false, error: 'smtp error: ESOCKET' });
    assert.equal(delivered, 0);
    const [row] = await rowsFor(deps, app.id, id);
    assert.equal(row.status, 'failed', 'nothing was sent, so the id stays retryable');
    assert.match(row.error, /certificate|self.signed|CERT|expired/i);
  });
});
