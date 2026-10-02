'use strict';

// POST /v1/send and GET /v1/health: authentication, request parsing order,
// validation, per-app and per-IP limits, rejected-request logging and the
// bounded html-to-text conversion.

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const h = require('./support/helpers');
const { createDb } = require('../src/db');
const { createLogger } = require('../src/lib/logger');
const { htmlToText } = require('../src/lib/htmlText');
const { localDay, addDays } = require('../src/lib/time');

const T = { timeout: 60000 };
const MINUTE = 60 * 1000;

// 12:00 local time (Asia/Colombo, UTC+05:30 without DST, see helpers.testEnv)
// on the day after today: far from the local midnight at which per-day
// counters reset, and never behind the real clock (rows and counters a test
// writes stay "fresh" for a cleanup run that uses real time).
function middayTomorrow(timezone) {
  assert.equal(timezone, 'Asia/Colombo');
  return new Date(`${addDays(localDay(new Date(), timezone), 1)}T06:30:00Z`);
}

// Inputs that make an unbounded html-to-text superlinear or overflow the stack.
function bigTable(bytes) {
  const row = '<tr><td>account</td><td>1234567890</td><td>Colombo</td></tr>';
  return '<table>' + row.repeat(Math.ceil(bytes / row.length)) + '</table>';
}
function nestedLists(depth) {
  return '<ul><li>'.repeat(depth) + 'deep' + '</li></ul>'.repeat(depth);
}

describe('GET /v1/health', () => {
  it('answers {"ok":true} without authentication or a database', async () => {
    // Nothing on this route touches the pool, so it works without TEST_DB_NAME.
    const config = h.testConfig();
    const deps = { config, db: createDb(config.db), clock: h.createFakeClock(), logger: createLogger({ silent: true }) };
    try {
      const res = await request(h.createHttpApp(deps)).get('/v1/health');
      assert.equal(res.status, 200);
      assert.deepEqual(res.body, { ok: true });
      assert.equal(res.headers['cache-control'], 'no-store');
    } finally {
      await deps.db.close();
    }
  });
});

describe('POST /v1/send', () => {
  let deps;
  let smtp;
  let httpApp;
  let main; // { app, key }

  before(async () => {
    if (!h.dbAvailable()) return;
    smtp = await h.startSmtpServer();
    deps = h.createTestDeps({ clock: h.createFakeClock() });
    httpApp = h.createHttpApp(deps);
    main = await h.insertTestApp(deps, { smtp });
  });

  after(async () => {
    if (smtp) await smtp.close();
    if (deps) await deps.db.close();
  });

  function basic(to, extra = {}) {
    return { to, subject: 'API test', text: 'Hello from the API test', ...extra };
  }

  it('sends a message and answers {"ok":true,"id"}', T, async (t) => {
    if (!h.requireDb(t)) return;
    const to = h.uniqueEmail();
    const res = await h.postV1(httpApp, main.key, basic(to));
    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.equal(res.body.ok, true);
    assert.match(res.body.id, /^msg_[0-9a-f]{24}$/);
    assert.deepEqual(Object.keys(res.body).sort(), ['id', 'ok']);
    assert.equal(res.headers['cache-control'], 'no-store');
    const [msg] = smtp.messagesTo(to);
    assert.equal(msg.parsed.subject, 'API test');
    assert.equal(msg.parsed.text.trim(), 'Hello from the API test');
    const row = (await h.listMessages(deps, main.app.id)).find((r) => r.publicId === res.body.id);
    assert.equal(row.status, 'sent');
    assert.equal(row.source, 'api');
    assert.equal(row.toAddrs, to);
  });

  it('generates a text part for html-only messages', T, async (t) => {
    if (!h.requireDb(t)) return;
    const to = h.uniqueEmail();
    const res = await h.postV1(httpApp, main.key, {
      to,
      subject: 'Html only',
      html: '<h1>Welcome</h1><p>Your account <a href="https://example.com/a">is ready</a>.</p>',
    });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    const [msg] = smtp.messagesTo(to);
    assert.match(msg.parsed.html, /<h1>Welcome<\/h1>/);
    assert.match(msg.parsed.text, /WELCOME|Welcome/);
    assert.match(msg.parsed.text, /is ready/);
  });

  it('answers 401 without a key, with WWW-Authenticate', T, async (t) => {
    if (!h.requireDb(t)) return;
    const res = await h.postV1(httpApp, null, basic(h.uniqueEmail()));
    assert.equal(res.status, 401);
    assert.deepEqual(res.body, { ok: false, error: 'missing api key' });
    assert.equal(res.headers['www-authenticate'], 'Bearer');
  });

  it('answers 401 for malformed, unknown or non-Bearer keys', T, async (t) => {
    if (!h.requireDb(t)) return;
    const unknownKey = 'rly_' + 'A'.repeat(43);
    for (const header of [
      'Bearer not-a-key',
      `Bearer ${unknownKey}`,
      `Basic ${Buffer.from('user:pass').toString('base64')}`,
      `Bearer ${main.key}x`,
      main.key,
    ]) {
      const res = await h.postV1(httpApp, null, basic(h.uniqueEmail()), { Authorization: header });
      assert.equal(res.status, 401, header);
      assert.deepEqual(res.body, { ok: false, error: 'invalid api key' });
      assert.equal(res.headers['www-authenticate'], 'Bearer');
    }
  });

  it('accepts the Bearer scheme in any case', T, async (t) => {
    if (!h.requireDb(t)) return;
    const res = await h.postV1(httpApp, null, basic(h.uniqueEmail()), { Authorization: `bearer ${main.key}` });
    assert.equal(res.status, 200, JSON.stringify(res.body));
  });

  it('answers 415 for a body that is not application/json', T, async (t) => {
    if (!h.requireDb(t)) return;
    const body = JSON.stringify(basic(h.uniqueEmail()));
    const asText = await request(httpApp)
      .post('/v1/send')
      .set('Authorization', `Bearer ${main.key}`)
      .set('Content-Type', 'text/plain')
      .send(body);
    assert.equal(asText.status, 415);
    assert.deepEqual(asText.body, { ok: false, error: 'content-type must be application/json' });

    const noType = await request(httpApp)
      .post('/v1/send')
      .set('Authorization', `Bearer ${main.key}`)
      .send(Buffer.from(body));
    assert.equal(noType.status, 415);
    assert.deepEqual(noType.body, { ok: false, error: 'content-type must be application/json' });

    const withCharset = await h.postV1(httpApp, main.key, body, { 'Content-Type': 'application/json; charset=utf-8' });
    assert.equal(withCharset.status, 200, JSON.stringify(withCharset.body));
  });

  it('checks the key before looking at the body', T, async (t) => {
    if (!h.requireDb(t)) return;
    const bad = { Authorization: 'Bearer rly_' + 'B'.repeat(43) };
    const broken = await h.postV1(httpApp, null, '{"to": broken', bad);
    assert.equal(broken.status, 401);
    assert.deepEqual(broken.body, { ok: false, error: 'invalid api key' });

    const wrongType = await request(httpApp).post('/v1/send').set(bad).set('Content-Type', 'text/plain').send('x');
    assert.equal(wrongType.status, 401);

    const gzip = await h.postV1(httpApp, null, '{}', { ...bad, 'Content-Encoding': 'gzip' });
    assert.equal(gzip.status, 401);
  });

  it('answers 400 for a body that is not a JSON object', T, async (t) => {
    if (!h.requireDb(t)) return;
    for (const raw of ['{"to": broken', '[1,2,3]', '"just a string"', 'null']) {
      const res = await h.postV1(httpApp, main.key, raw);
      assert.equal(res.status, 400, raw);
      assert.deepEqual(res.body, { ok: false, error: 'invalid json body' });
    }
  });

  it('refuses compressed bodies and unknown charsets with 415', T, async (t) => {
    if (!h.requireDb(t)) return;
    const body = JSON.stringify(basic(h.uniqueEmail()));
    const gzip = await h.postV1(httpApp, main.key, body, { 'Content-Encoding': 'gzip' });
    assert.equal(gzip.status, 415);
    assert.deepEqual(gzip.body, { ok: false, error: 'content-encoding not supported' });
    const charset = await h.postV1(httpApp, main.key, body, { 'Content-Type': 'application/json; charset=x-unknown' });
    assert.equal(charset.status, 415);
    assert.deepEqual(charset.body, { ok: false, error: 'unsupported charset' });
  });

  it('validates the required fields', T, async (t) => {
    if (!h.requireDb(t)) return;
    const to = h.uniqueEmail();
    const cases = [
      [{ subject: 'S', text: 'T' }, 'to is required'],
      [{ to: [], subject: 'S', text: 'T' }, 'to is required'],
      [{ to, text: 'T' }, 'subject is required'],
      [{ to, subject: ' \r\n ', text: 'T' }, 'subject is required'],
      [{ to, subject: 'x'.repeat(999), text: 'T' }, 'subject too long'],
      [{ to, subject: 'S' }, 'html or text is required'],
      [{ to, subject: 'S', html: '', text: '' }, 'html or text is required'],
    ];
    for (const [body, error] of cases) {
      const res = await h.postV1(httpApp, main.key, body);
      assert.equal(res.status, 400, JSON.stringify(body).slice(0, 80));
      assert.deepEqual(res.body, { ok: false, error });
    }
    const longest = await h.postV1(httpApp, main.key, { to, subject: 'x'.repeat(998), text: 'T' });
    assert.equal(longest.status, 200, JSON.stringify(longest.body));
  });

  it('caps unique recipients per app', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { key } = await h.insertTestApp(deps, { smtp, maxRecipients: 3 });
    const [a, b, c, d] = [h.uniqueEmail(), h.uniqueEmail(), h.uniqueEmail(), h.uniqueEmail()];
    const tooMany = await h.postV1(httpApp, key, basic([a, b], { cc: [c], bcc: d }));
    assert.equal(tooMany.status, 400);
    assert.deepEqual(tooMany.body, { ok: false, error: 'too many recipients (max 3)' });
    const longArray = await h.postV1(httpApp, key, basic([a, b, c, d]));
    assert.equal(longArray.status, 400);
    assert.deepEqual(longArray.body, { ok: false, error: 'too many recipients (max 3)' });
    assert.equal(smtp.messagesTo(a).length, 0);

    // Duplicates (any case) count once.
    const dupes = await h.postV1(httpApp, key, basic([a, b], { cc: a.toUpperCase(), bcc: [c] }));
    assert.equal(dupes.status, 200, JSON.stringify(dupes.body));
  });

  it('sends case-variant duplicates once: one RCPT TO per unique recipient', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { app, key } = await h.insertTestApp(deps, { smtp, maxRecipients: 2 });
    const base = `case${h.uniqueId()}@example.com`;
    const first = 'Ab' + base;
    const variants = { to: `${first}, aB${base}`, cc: 'AB' + base.toUpperCase(), bcc: ['ab' + base] };
    const res = await h.postV1(httpApp, key, basic(variants.to, { cc: variants.cc, bcc: variants.bcc }));
    assert.equal(res.status, 200, JSON.stringify(res.body));

    const want = ('ab' + base).toLowerCase();
    const rcpts = smtp.rcptLog.filter((r) => r.toLowerCase() === want);
    assert.equal(rcpts.length, 1, `RCPT TO commands: ${rcpts.join(', ')}`);
    const [msg] = smtp.messagesTo(want);
    assert.equal(msg.parsed.to.value.length, 1);
    assert.equal(msg.parsed.to.value[0].address.toLowerCase(), want);
    assert.equal(msg.parsed.cc, undefined, 'the cc copy of a to address is dropped');

    const row = (await h.listMessages(deps, app.id)).find((r) => r.publicId === res.body.id);
    assert.equal(row.recipientCount, 1);
    assert.equal(row.toAddrs.toLowerCase(), want);

    // Real distinct recipients still count, whatever their case.
    const other = h.uniqueEmail();
    const two = await h.postV1(httpApp, key, basic([first, other], { cc: other.toUpperCase() }));
    assert.equal(two.status, 200, JSON.stringify(two.body));
    const both = smtp.rcptLog.filter((r) => [want, other].includes(r.toLowerCase()));
    assert.equal(both.length, 1 + 2);
  });

  it('stores only a short excerpt of the raw request for a rejected request', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { app, key } = await h.insertTestApp(deps, { smtp, enabled: false });
    const long = 'x'.repeat(64 * 1024);
    const items = Array.from({ length: 30 }, (_, i) => `${i}-${'y'.repeat(400)}@example.com`);
    const res = await h.postV1(httpApp, key, { to: long, cc: items, bcc: long, subject: 's'.repeat(2000), text: 't' });
    assert.equal(res.status, 403);
    assert.deepEqual(res.body, { ok: false, error: 'app disabled' });
    const [row] = await h.listMessages(deps, app.id);
    assert.equal(row.status, 'rejected');
    for (const field of ['toAddrs', 'ccAddrs', 'bccAddrs']) {
      assert.ok(row[field].length <= 1000, `${field} has ${row[field].length} characters`);
    }
    assert.ok(row.toAddrs.startsWith('xxx'));
    const ccItems = row.ccAddrs.split(', ');
    assert.ok(ccItems.length <= 20);
    assert.equal(ccItems[0], items[0].slice(0, 254), 'each list item is cut to 254 characters');
    assert.ok(row.subject.length <= 255);
  });

  it('writes at most max(60, per-minute limit) rejected rows per app per minute', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { app, key } = await h.insertTestApp(deps, { smtp, enabled: false, limitPerMinute: 1 });
    const statuses = [];
    for (let i = 0; i < 61; i++) statuses.push((await h.postV1(httpApp, key, basic(h.uniqueEmail()))).status);
    assert.deepEqual([...new Set(statuses)], [403], 'the answer never changes');
    assert.equal((await h.listMessages(deps, app.id)).length, 60);
    const day = localDay(deps.clock.now(), deps.config.timezone);
    const [counter] = await deps.db.query('SELECT count FROM rate_counters WHERE k = ?', [`rejdrop:${app.id}:${day}`]);
    assert.equal(counter && counter.count, 1, 'the dropped row is counted');
  });

  it('logs authenticated requests refused while reading the body', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { app, key } = await h.insertTestApp(deps, { smtp });
    const broken = await h.postV1(httpApp, key, '{"to": broken');
    assert.equal(broken.status, 400);
    const asText = await request(httpApp)
      .post('/v1/send')
      .set('Authorization', `Bearer ${key}`)
      .set('Content-Type', 'text/plain')
      .send('{"to":"a@example.com"}');
    assert.equal(asText.status, 415);
    const charset = await h.postV1(httpApp, key, '{}', { 'Content-Type': 'application/json; charset=x-unknown' });
    assert.equal(charset.status, 415);

    const rows = await h.listMessages(deps, app.id);
    assert.deepEqual(
      rows.map((r) => [r.status, r.httpStatus, r.error, r.source]),
      [
        ['rejected', 400, 'invalid json body', 'api'],
        ['rejected', 415, 'content-type must be application/json', 'api'],
        ['rejected', 415, 'unsupported charset', 'api'],
      ]
    );

    // Not authenticated: nothing to attribute the request to, no row.
    const anonymous = await h.postV1(httpApp, null, '{"to": broken', { Authorization: 'Bearer rly_' + 'C'.repeat(43) });
    assert.equal(anonymous.status, 401);
    assert.equal((await h.listMessages(deps, app.id)).length, 3);
  });

  it('refuses a disabled app with 403', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { app, key } = await h.insertTestApp(deps, { smtp, enabled: false });
    const to = h.uniqueEmail();
    const res = await h.postV1(httpApp, key, basic(to));
    assert.equal(res.status, 403);
    assert.deepEqual(res.body, { ok: false, error: 'app disabled' });
    assert.equal(smtp.messagesTo(to).length, 0);
    const [row] = await h.listMessages(deps, app.id);
    assert.equal(row.status, 'rejected');
    assert.equal(row.httpStatus, 403);
  });

  it('enforces the IP allowlist on the proxy-appended address only', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { app, key } = await h.insertTestApp(deps, { smtp, ipAllowlist: ['203.0.113.5', '198.51.100.0/24'] });
    const send = (xff) => h.postV1(httpApp, key, basic(h.uniqueEmail()), xff ? { 'X-Forwarded-For': xff } : {});

    assert.equal((await send('203.0.113.5')).status, 200);
    assert.equal((await send('192.0.2.77, 198.51.100.20')).status, 200, 'right-most entry in the allowed range');

    // The client wrote an allowed address into X-Forwarded-For itself; the proxy
    // appended the real one.
    const spoofed = await send('203.0.113.5, 192.0.2.77');
    assert.equal(spoofed.status, 403);
    assert.deepEqual(spoofed.body, { ok: false, error: 'ip not allowed' });

    const direct = await send(null);
    assert.equal(direct.status, 403);
    assert.deepEqual(direct.body, { ok: false, error: 'ip not allowed' });

    const rows = await h.listMessages(deps, app.id);
    const rejected = rows.filter((r) => r.status === 'rejected');
    assert.equal(rejected.length, 2);
    assert.equal(rejected[0].clientIp, '192.0.2.77');
  });

  it('answers 429 with Retry-After over the per-minute limit', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { app, key } = await h.insertTestApp(deps, { smtp, limitPerMinute: 2 });
    assert.equal((await h.postV1(httpApp, key, basic(h.uniqueEmail()))).status, 200);
    assert.equal((await h.postV1(httpApp, key, basic(h.uniqueEmail()))).status, 200);
    const to = h.uniqueEmail();
    const limited = await h.postV1(httpApp, key, basic(to));
    assert.equal(limited.status, 429);
    assert.deepEqual(limited.body, { ok: false, error: 'rate limit exceeded (per minute)' });
    const retryAfter = Number(limited.headers['retry-after']);
    assert.ok(Number.isInteger(retryAfter) && retryAfter >= 1 && retryAfter <= 60, `Retry-After ${retryAfter}`);
    assert.equal(smtp.messagesTo(to).length, 0);
    const last = (await h.listMessages(deps, app.id)).at(-1);
    assert.equal(last.status, 'rejected');
    assert.equal(last.httpStatus, 429);

    deps.clock.advance(MINUTE);
    assert.equal((await h.postV1(httpApp, key, basic(h.uniqueEmail()))).status, 200, 'next window');
  });

  it('answers 429 over the per-day limit', T, async (t) => {
    if (!h.requireDb(t)) return;
    // The per-day window resets at local midnight: pin the clock to mid-day so
    // the three sends below always fall on the same local day.
    deps.clock.set(middayTomorrow(deps.config.timezone));
    const { key } = await h.insertTestApp(deps, { smtp, limitPerDay: 2 });
    assert.equal((await h.postV1(httpApp, key, basic(h.uniqueEmail()))).status, 200);
    deps.clock.advance(MINUTE);
    assert.equal((await h.postV1(httpApp, key, basic(h.uniqueEmail()))).status, 200);
    deps.clock.advance(MINUTE);
    const limited = await h.postV1(httpApp, key, basic(h.uniqueEmail()));
    assert.equal(limited.status, 429);
    assert.deepEqual(limited.body, { ok: false, error: 'rate limit exceeded (per day)' });
    assert.ok(Number(limited.headers['retry-after']) >= 60);
  });

  it('logs rejected requests with the raw request data', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { app, key } = await h.insertTestApp(deps, { smtp });
    const res = await h.postV1(httpApp, key, {
      to: 'not an address',
      cc: ['x@example.com'],
      subject: 'Rejected subject',
      text: 'body text',
      message_id: 'rej-1',
    });
    assert.equal(res.status, 400);
    assert.deepEqual(res.body, { ok: false, error: 'invalid to address' });
    const [row] = await h.listMessages(deps, app.id);
    assert.equal(row.status, 'rejected');
    assert.equal(row.error, 'invalid to address');
    assert.equal(row.httpStatus, 400);
    assert.equal(row.toAddrs, 'not an address');
    assert.equal(row.subject, 'Rejected subject');
    assert.equal(row.clientMessageId, 'rej-1');
    assert.equal(row.source, 'api');
  });

  it('records SMTP failures as failed with 502', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { app, key } = await h.insertTestApp(deps, { smtp });
    smtp.setFailure(451);
    let res;
    try {
      res = await h.postV1(httpApp, key, basic(h.uniqueEmail()));
    } finally {
      smtp.setFailure(null);
    }
    assert.equal(res.status, 502);
    assert.deepEqual(res.body, { ok: false, error: 'smtp error: EMESSAGE 451' });
    const [row] = await h.listMessages(deps, app.id);
    assert.equal(row.status, 'failed');
    assert.equal(row.httpStatus, 502);
    assert.match(row.smtpResponse, /451/);
  });

  it('converts a 2 MB html table quickly', T, async (t) => {
    if (!h.requireDb(t)) return;
    const to = h.uniqueEmail();
    const html = bigTable(2 * 1024 * 1024);
    const started = Date.now();
    const res = await h.postV1(httpApp, main.key, { to, subject: 'Big table', html });
    const elapsed = Date.now() - started;
    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.ok(elapsed < 20000, `took ${elapsed} ms`);
    assert.equal(smtp.messagesTo(to).length, 1);
  });

  it('survives 5,000 nested lists', T, async (t) => {
    if (!h.requireDb(t)) return;
    const to = h.uniqueEmail();
    const started = Date.now();
    const res = await h.postV1(httpApp, main.key, { to, subject: 'Deep lists', html: nestedLists(5000) });
    const elapsed = Date.now() - started;
    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.ok(elapsed < 20000, `took ${elapsed} ms`);
    assert.equal(smtp.messagesTo(to).length, 1);
  });

  it('answers unknown /v1 paths with a JSON 404', T, async (t) => {
    if (!h.requireDb(t)) return;
    const res = await request(httpApp).get('/v1/nope');
    assert.equal(res.status, 404);
    assert.deepEqual(res.body, { ok: false, error: 'not found' });
  });
});

describe('htmlToText limits', () => {
  it('returns quickly (or null) for hostile input instead of throwing', () => {
    for (const html of [bigTable(2 * 1024 * 1024), nestedLists(5000), '<div>'.repeat(100000)]) {
      const started = Date.now();
      const text = htmlToText(html);
      assert.ok(text === null || typeof text === 'string');
      assert.ok(Date.now() - started < 10000, 'conversion is bounded');
    }
    assert.equal(htmlToText(''), null);
    assert.match(htmlToText('<p>Hello <b>world</b></p>'), /Hello world/);
  });

  it('keeps table cells apart and puts each row on its own line', () => {
    const text = htmlToText(
      '<table><tr><td><table><tr><td>Name:</td><td>Kamal</td></tr><tr><td> NIC: </td><td>123V</td></tr></table>' +
        '</td></tr></table><table><tr><th>Item</th><th>Price</th></tr><tr><td>Widget</td><td>$4.00</td></tr></table>'
    );
    assert.match(text, /^Name: Kamal$/m);
    assert.match(text, /^NIC: 123V$/m);
    assert.match(text, /^Item Price$/m);
    assert.match(text, /^Widget \$4\.00$/m);
  });
});

describe('request limits', () => {
  let deps;
  let smtp;
  let httpApp;

  before(async () => {
    if (!h.dbAvailable()) return;
    smtp = await h.startSmtpServer();
    // A 4 KiB request limit: an oversized body still fits in the socket buffers,
    // so the early 401/413 (sent without reading the body) cannot race a reset.
    // 3 requests per minute per IP.
    deps = h.createTestDeps({
      clock: h.createFakeClock(),
      configOverrides: { bodyLimitBytes: 4096, ipRateLimitPerMinute: 3 },
    });
    httpApp = h.createHttpApp(deps);
  });

  after(async () => {
    if (smtp) await smtp.close();
    if (deps) await deps.db.close();
  });

  it('answers 413 for a request over the body limit, but only after authentication', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { app, key } = await h.insertTestApp(deps, { smtp });
    const huge = JSON.stringify({ to: h.uniqueEmail(), subject: 'S', text: 'x'.repeat(deps.config.bodyLimitBytes + 100) });
    const ip = { 'X-Forwarded-For': h.uniqueIp() };
    const anonymous = await h.postV1(httpApp, null, huge, ip);
    assert.equal(anonymous.status, 401);
    assert.deepEqual(anonymous.body, { ok: false, error: 'missing api key' });
    const authed = await h.postV1(httpApp, key, huge, ip);
    assert.equal(authed.status, 413);
    assert.deepEqual(authed.body, { ok: false, error: 'request too large' });
    // Authenticated, so it is logged (size = the declared Content-Length).
    const [row] = await h.listMessages(deps, app.id);
    assert.equal(row.status, 'rejected');
    assert.equal(row.httpStatus, 413);
    assert.equal(row.error, 'request too large');
    assert.equal(row.sizeBytes, Buffer.byteLength(huge));
  });

  it('limits /send.php per client IP, before the signature is checked', T, async (t) => {
    if (!h.requireDb(t)) return;
    const legacy = await h.insertTestApp(deps, { smtp, legacySigning: true });
    const ip = h.uniqueIp();
    const send = (signed) => {
      const raw = JSON.stringify({ message_id: h.uniqueName('ip'), to: h.uniqueEmail(), subject: 'S', html: '<p>x</p>' });
      return h.postLegacy(httpApp, deps, legacy.key, raw, {
        headers: { 'X-Forwarded-For': ip },
        ...(signed ? {} : { signature: 'sha256=' + '0'.repeat(64) }),
      });
    };
    assert.equal((await send(true)).status, 200);
    assert.equal((await send(false)).status, 401);
    assert.equal((await send(true)).status, 200);

    const limited = await send(true);
    assert.equal(limited.status, 429);
    assert.deepEqual(limited.body, { error: 'too many requests' });
    const retryAfter = Number(limited.headers['retry-after']);
    assert.ok(retryAfter >= 1 && retryAfter <= 60, `Retry-After ${retryAfter}`);
    const unsigned = await send(false);
    assert.equal(unsigned.status, 429, 'limited before the signature is looked at');

    deps.clock.advance(MINUTE);
    assert.equal((await send(true)).status, 200, 'next window');
  });

  it('limits requests per client IP, before authentication', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { key } = await h.insertTestApp(deps, { smtp });
    const ip = { 'X-Forwarded-For': h.uniqueIp() };
    assert.equal((await h.postV1(httpApp, key, { to: h.uniqueEmail(), subject: 'S', text: 'T' }, ip)).status, 200);
    assert.equal((await h.postV1(httpApp, null, { to: h.uniqueEmail(), subject: 'S', text: 'T' }, ip)).status, 401);
    assert.equal((await h.postV1(httpApp, key, { to: h.uniqueEmail(), subject: 'S', text: 'T' }, ip)).status, 200);

    const limited = await h.postV1(httpApp, key, { to: h.uniqueEmail(), subject: 'S', text: 'T' }, ip);
    assert.equal(limited.status, 429);
    assert.equal(limited.body.ok, false);
    assert.equal(typeof limited.body.error, 'string');
    const retryAfter = Number(limited.headers['retry-after']);
    assert.ok(retryAfter >= 1 && retryAfter <= 60, `Retry-After ${retryAfter}`);

    const otherIp = await h.postV1(httpApp, key, { to: h.uniqueEmail(), subject: 'S', text: 'T' }, {
      'X-Forwarded-For': h.uniqueIp(),
    });
    assert.equal(otherIp.status, 200, 'another client is not affected');

    deps.clock.advance(MINUTE);
    assert.equal((await h.postV1(httpApp, key, { to: h.uniqueEmail(), subject: 'S', text: 'T' }, ip)).status, 200);
  });
});
