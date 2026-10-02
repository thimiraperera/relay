'use strict';

// /send.php request signing: the pure helpers in src/lib/legacySignature.js and
// the endpoint as the existing PHP app calls it. Signatures in the HTTP tests are
// computed independently (as PHP's hash_hmac does), not with the relay's code.

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const request = require('supertest');
const sig = require('../src/lib/legacySignature');
const appsRepo = require('../src/repos/apps');
const h = require('./support/helpers');

const T = { timeout: 30000 };
const PDF = h.SAMPLE_PDF;

// hash_hmac('sha256', $ts . '.' . $body, $apiKey)
function phpSign(key, timestampText, rawBody) {
  return (
    'sha256=' +
    crypto.createHmac('sha256', key).update(`${timestampText}.`, 'utf8').update(Buffer.from(rawBody)).digest('hex')
  );
}

// PHP json_encode() with its default flags: "/" escaped as "\/" and every
// non-ASCII character as a lowercase \uXXXX escape (UTF-16 units, so
// characters outside the BMP become surrogate pairs, as in PHP).
function phpJsonEncode(value) {
  return JSON.stringify(value)
    .split('/')
    .join('\\/')
    .replace(/[\u0080-\uffff]/g, (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
}

describe('legacy signature helpers', () => {
  const key = 'rly_' + 'k'.repeat(43);
  const body = Buffer.from('{"message_id":"m1","to":"a@example.com","subject":"Hi","html":"<p>x</p>"}');

  it('parses a well-formed signature header (hex in either case, trimmed)', () => {
    const hex = 'ab'.repeat(32);
    const buf = sig.parseSignatureHeader(`sha256=${hex}`);
    assert.ok(Buffer.isBuffer(buf));
    assert.equal(buf.length, 32);
    assert.equal(buf.toString('hex'), hex);
    assert.deepEqual(sig.parseSignatureHeader(`  sha256=${hex.toUpperCase()}  `), buf);
  });

  it('rejects malformed signature headers', () => {
    const hex = 'ab'.repeat(32);
    for (const bad of [
      undefined,
      null,
      '',
      hex,
      `sha1=${hex}`,
      `sha256=${hex.slice(2)}`,
      `sha256=${hex}00`,
      `sha256=${'zz'.repeat(32)}`,
      `sha256= ${hex}`,
      `sha256=${hex}, sha256=${hex}`,
    ]) {
      assert.equal(sig.parseSignatureHeader(bad), null, `accepted ${JSON.stringify(bad)}`);
    }
  });

  it('parses timestamps and keeps the header text exactly (trimmed)', () => {
    assert.deepEqual(sig.parseTimestampHeader('1700000000'), { text: '1700000000', seconds: 1700000000 });
    assert.deepEqual(sig.parseTimestampHeader(' 1700000000 '), { text: '1700000000', seconds: 1700000000 });
    assert.deepEqual(sig.parseTimestampHeader('01700000000'), { text: '01700000000', seconds: 1700000000 });
    for (const bad of [undefined, '', ' ', '-1700000000', '1700000000.5', '1e9', 'abc', '1234567890123']) {
      assert.equal(sig.parseTimestampHeader(bad), null, `accepted ${JSON.stringify(bad)}`);
    }
  });

  it('accepts timestamps within 5 minutes either way and refuses older or future ones', () => {
    const nowMs = 1_700_000_000_000;
    const now = 1_700_000_000;
    assert.equal(sig.isTimestampFresh(now, nowMs, 300), true);
    assert.equal(sig.isTimestampFresh(now - 300, nowMs, 300), true);
    assert.equal(sig.isTimestampFresh(now + 300, nowMs, 300), true);
    assert.equal(sig.isTimestampFresh(now - 301, nowMs, 300), false, 'old timestamp');
    assert.equal(sig.isTimestampFresh(now + 301, nowMs, 300), false, 'future timestamp');
    assert.equal(sig.isTimestampFresh(NaN, nowMs, 300), false);
  });

  it('computes HMAC-SHA256(key, timestamp + "." + raw body)', () => {
    const expected = phpSign(key, '1700000000', body);
    assert.equal(sig.formatSignature(sig.computeSignature(key, '1700000000', body)), expected);
    assert.equal(sig.signatureMatches(key, '1700000000', body, sig.parseSignatureHeader(expected)), true);
  });

  it('refuses a bad signature, a tampered body, another key or another timestamp text', () => {
    const good = sig.parseSignatureHeader(phpSign(key, '1700000000', body));
    const tampered = Buffer.from(body.toString().replace('Hi', 'Ho'));
    assert.equal(sig.signatureMatches(key, '1700000000', body, crypto.randomBytes(32)), false);
    assert.equal(sig.signatureMatches(key, '1700000000', tampered, good), false);
    assert.equal(sig.signatureMatches(key + 'x', '1700000000', body, good), false);
    assert.equal(sig.signatureMatches(key, '1700000001', body, good), false);
    assert.equal(sig.signatureMatches(key, '1700000000', body, good.subarray(0, 31)), false);
  });

  it('signs the timestamp header text exactly as sent (leading zeros matter)', () => {
    const padded = sig.computeSignature(key, '01700000000', body);
    const plain = sig.computeSignature(key, '1700000000', body);
    assert.notDeepEqual(padded, plain);
    assert.equal(sig.signatureMatches(key, '01700000000', body, padded), true);
    assert.equal(sig.signatureMatches(key, '1700000000', body, padded), false);
  });

  // The request path (services/keys.js authenticateLegacy) uses the WebCrypto
  // verifier; it must answer exactly as the synchronous helpers do.
  it('computes the same digest off the main thread (WebCrypto)', async () => {
    const expected = phpSign(key, '1700000000', body);
    assert.equal(sig.formatSignature(await sig.computeSignatureAsync(key, '1700000000', body)), expected);
    assert.deepEqual(await sig.computeSignatureAsync(key, '01700000000', body), sig.computeSignature(key, '01700000000', body));
    assert.deepEqual(await sig.computeSignatureAsync(key, '1700000000', Buffer.alloc(0)), sig.computeSignature(key, '1700000000', ''));
  });

  it('matchSignatureKeys: good, bad, tampered, other key, other timestamp, short signature', async () => {
    const other = 'rly_' + 'o'.repeat(43);
    const good = sig.parseSignatureHeader(phpSign(key, '1700000000', body));
    const tampered = Buffer.from(body.toString().replace('Hi', 'Ho'));
    const match = (keys, ts, b, s) => sig.matchSignatureKeys(keys, ts, b, s);
    assert.deepEqual(await match([other, key, key + 'x'], '1700000000', body, good), [false, true, false]);
    assert.deepEqual(await match([key, other], '1700000000', body, crypto.randomBytes(32)), [false, false]);
    assert.deepEqual(await match([key, other], '1700000000', tampered, good), [false, false]);
    assert.deepEqual(await match([key], '1700000001', body, good), [false]);
    assert.deepEqual(await match([key], '1700000000', body, good.subarray(0, 31)), [false]);
    assert.deepEqual(await match([], '1700000000', body, good), []);
    // Every key is checked: a key listed twice matches twice.
    assert.deepEqual(await match([key, other, key], '1700000000', body, good), [true, false, true]);
  });

  it('matchSignatureKeys agrees with signatureMatches on random inputs', async () => {
    const keys = Array.from({ length: 3 }, () => 'rly_' + crypto.randomBytes(32).toString('base64url'));
    for (let i = 0; i < 40; i++) {
      const b = crypto.randomBytes(1 + ((i * 97) % 5000));
      const ts = String(1700000000 + i);
      const k = keys[i % keys.length];
      const flipped = Buffer.from(b);
      flipped[i % flipped.length] ^= 0x01;
      for (const [rawBody, s] of [
        [b, sig.computeSignature(k, ts, b)],
        [flipped, sig.computeSignature(k, ts, b)],
        [b, crypto.randomBytes(32)],
      ]) {
        const expected = keys.map((kk) => sig.signatureMatches(kk, ts, rawBody, s));
        assert.deepEqual(await sig.matchSignatureKeys(keys, ts, rawBody, s), expected, `input ${i}`);
      }
    }
  });

  it('matchSignatureKeys checks a large body against every key without blocking the event loop for long', async () => {
    const keys = Array.from({ length: 3 }, () => 'rly_' + crypto.randomBytes(32).toString('base64url'));
    const big = crypto.randomBytes(4 * 1024 * 1024);
    const good = sig.computeSignature(keys[2], '1700000000', big);
    let ticks = 0;
    const ticker = setInterval(() => ticks++, 0);
    try {
      assert.deepEqual(await sig.matchSignatureKeys(keys, '1700000000', big, good), [false, false, true]);
      assert.deepEqual(await sig.matchSignatureKeys(keys, '1700000000', big, crypto.randomBytes(32)), [false, false, false]);
    } finally {
      clearInterval(ticker);
    }
    // The hashing ran on the thread pool, so timers kept firing meanwhile.
    assert.ok(ticks >= 1, `timer ticks while hashing: ${ticks}`);
  });
});

describe('POST /send.php', () => {
  let deps;
  let smtp;
  let httpApp;
  let legacy; // { app, key }

  before(async () => {
    if (!h.dbAvailable()) return;
    smtp = await h.startSmtpServer();
    deps = h.createTestDeps({ clock: h.createFakeClock() });
    httpApp = h.createHttpApp(deps);
    legacy = await h.insertTestApp(deps, { smtp, legacySigning: true, fromName: 'Legacy Site' });
  });

  after(async () => {
    if (smtp) await smtp.close();
    if (deps) await deps.db.close();
  });

  function nowTs() {
    return String(Math.floor(deps.clock.now().getTime() / 1000));
  }

  // Sends rawBody exactly as given. contentType null sends no Content-Type at all.
  function postLegacy(rawBody, { key = legacy.key, ts = nowTs(), signature, contentType = 'application/json' } = {}) {
    const req = request(httpApp).post('/send.php');
    if (ts !== null) req.set('X-Relay-Timestamp', ts);
    const signatureValue = signature === undefined ? phpSign(key, ts, rawBody) : signature;
    if (signatureValue !== null) req.set('X-Relay-Signature', signatureValue);
    if (contentType) {
      req.set('Content-Type', contentType);
      return req.send(rawBody);
    }
    return req.send(Buffer.from(rawBody, 'utf8'));
  }

  function legacyBody(fields = {}) {
    return JSON.stringify({
      message_id: h.uniqueName('legacy'),
      to: h.uniqueEmail('applicant'),
      to_name: 'Applicant',
      subject: 'Your account application',
      html: '<p>Thank you for applying.</p>',
      ...fields,
    });
  }

  for (const contentType of ['application/json', 'application/x-www-form-urlencoded', 'text/plain', null]) {
    it(`accepts a good signature with Content-Type ${contentType || '(none)'}`, T, async (t) => {
      if (!h.requireDb(t)) return;
      const to = h.uniqueEmail('applicant');
      const res = await postLegacy(legacyBody({ to }), { contentType });
      assert.equal(res.status, 200, JSON.stringify(res.body));
      assert.deepEqual(res.body, { ok: true });
      const delivered = smtp.messagesTo(to);
      assert.equal(delivered.length, 1);
      assert.equal(delivered[0].parsed.subject, 'Your account application');
      assert.match(delivered[0].parsed.html, /Thank you for applying/);
      assert.deepEqual(delivered[0].parsed.from.value, [{ address: legacy.app.fromEmail, name: 'Legacy Site' }]);
    });
  }

  it('rejects a bad signature with 401 {error}', T, async (t) => {
    if (!h.requireDb(t)) return;
    const to = h.uniqueEmail();
    const res = await postLegacy(legacyBody({ to }), { signature: 'sha256=' + crypto.randomBytes(32).toString('hex') });
    assert.equal(res.status, 401);
    assert.deepEqual(res.body, { error: 'invalid signature' });
    assert.equal(smtp.messagesTo(to).length, 0);
  });

  it('rejects a signature made with a key that is not a legacy key', T, async (t) => {
    if (!h.requireDb(t)) return;
    const normal = await h.insertTestApp(deps, { smtp });
    const to = h.uniqueEmail();
    const res = await postLegacy(legacyBody({ to }), { key: normal.key });
    assert.equal(res.status, 401);
    assert.deepEqual(res.body, { error: 'invalid signature' });
    assert.equal(smtp.messagesTo(to).length, 0);
  });

  it('rejects an old timestamp with 401', T, async (t) => {
    if (!h.requireDb(t)) return;
    const to = h.uniqueEmail();
    const old = String(Number(nowTs()) - 301);
    const res = await postLegacy(legacyBody({ to }), { ts: old });
    assert.equal(res.status, 401);
    assert.deepEqual(res.body, { error: 'timestamp out of range' });
    assert.equal(smtp.messagesTo(to).length, 0);
  });

  it('rejects a timestamp too far in the future with 401', T, async (t) => {
    if (!h.requireDb(t)) return;
    const to = h.uniqueEmail();
    const future = String(Number(nowTs()) + 301);
    const res = await postLegacy(legacyBody({ to }), { ts: future });
    assert.equal(res.status, 401);
    assert.deepEqual(res.body, { error: 'timestamp out of range' });
  });

  it('accepts a timestamp just inside the window', T, async (t) => {
    if (!h.requireDb(t)) return;
    const to = h.uniqueEmail();
    const res = await postLegacy(legacyBody({ to }), { ts: String(Number(nowTs()) - 299) });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.equal(smtp.messagesTo(to).length, 1);
  });

  it('rejects a tampered body with 401', T, async (t) => {
    if (!h.requireDb(t)) return;
    const to = h.uniqueEmail();
    const evil = h.uniqueEmail('attacker');
    const signedBody = legacyBody({ to });
    const ts = nowTs();
    const res = await postLegacy(signedBody.replace(to, evil), { ts, signature: phpSign(legacy.key, ts, signedBody) });
    assert.equal(res.status, 401);
    assert.deepEqual(res.body, { error: 'invalid signature' });
    assert.equal(smtp.messagesTo(to).length, 0);
    assert.equal(smtp.messagesTo(evil).length, 0);
  });

  it('rejects missing or malformed signature headers with 401', T, async (t) => {
    if (!h.requireDb(t)) return;
    const body = legacyBody();
    const cases = [
      { ts: null },
      { signature: null },
      { signature: 'sha256=xyz' },
      { signature: 'md5=' + 'a'.repeat(64) },
      { ts: 'yesterday' },
    ];
    for (const opts of cases) {
      const res = await postLegacy(body, opts);
      assert.equal(res.status, 401, JSON.stringify(opts));
      assert.deepEqual(res.body, { error: 'missing or malformed signature headers' });
    }
  });

  it('signs the timestamp header text exactly as sent', T, async (t) => {
    if (!h.requireDb(t)) return;
    const ts = '0' + nowTs();
    const to1 = h.uniqueEmail();
    const ok = await postLegacy(legacyBody({ to: to1 }), { ts });
    assert.equal(ok.status, 200, JSON.stringify(ok.body));
    assert.equal(smtp.messagesTo(to1).length, 1);

    const to2 = h.uniqueEmail();
    const body2 = legacyBody({ to: to2 });
    const bad = await postLegacy(body2, { ts, signature: phpSign(legacy.key, ts.slice(1), body2) });
    assert.equal(bad.status, 401);
    assert.deepEqual(bad.body, { error: 'invalid signature' });
    assert.equal(smtp.messagesTo(to2).length, 0);
  });

  it('answers a duplicate message_id with 200 and delivers once', T, async (t) => {
    if (!h.requireDb(t)) return;
    const to = h.uniqueEmail();
    const body = legacyBody({ to });
    const first = await postLegacy(body);
    assert.equal(first.status, 200);
    deps.clock.advance(2000);
    // A PHP retry re-signs the same body with a new timestamp.
    const second = await postLegacy(body);
    assert.equal(second.status, 200);
    assert.deepEqual(second.body, { ok: true });
    assert.equal(smtp.messagesTo(to).length, 1);
  });

  it('refuses a replayed request without message_id with 409', T, async (t) => {
    if (!h.requireDb(t)) return;
    const to = h.uniqueEmail();
    const body = JSON.stringify({ to, subject: 'No id', html: '<p>no id</p>' });
    const ts = nowTs();
    const signature = phpSign(legacy.key, ts, body);
    const first = await postLegacy(body, { ts, signature });
    assert.equal(first.status, 200, JSON.stringify(first.body));
    const replay = await postLegacy(body, { ts, signature });
    assert.equal(replay.status, 409);
    assert.deepEqual(replay.body, { error: 'replayed request' });
    assert.equal(smtp.messagesTo(to).length, 1);

    // The same message signed again with a new timestamp is a new request.
    deps.clock.advance(1000);
    const again = await postLegacy(body);
    assert.equal(again.status, 200);
    assert.equal(smtp.messagesTo(to).length, 2);
  });

  it('treats an empty message_id as absent (replay protection applies)', T, async (t) => {
    if (!h.requireDb(t)) return;
    const to = h.uniqueEmail();
    const body = legacyBody({ to, message_id: '' });
    const ts = nowTs();
    const signature = phpSign(legacy.key, ts, body);
    assert.equal((await postLegacy(body, { ts, signature })).status, 200);
    const replay = await postLegacy(body, { ts, signature });
    assert.equal(replay.status, 409);
    assert.deepEqual(replay.body, { error: 'replayed request' });
    assert.equal(smtp.messagesTo(to).length, 1);
  });

  it('accepts a numeric message_id and de-duplicates on it', T, async (t) => {
    if (!h.requireDb(t)) return;
    const to = h.uniqueEmail();
    const numericId = crypto.randomInt(1, 2 ** 47);
    const body = legacyBody({ to, message_id: numericId });
    assert.equal((await postLegacy(body)).status, 200);
    deps.clock.advance(1000);
    assert.equal((await postLegacy(legacyBody({ to, message_id: String(numericId) }))).status, 200);
    assert.equal(smtp.messagesTo(to).length, 1);
    const rows = await h.listMessages(deps, legacy.app.id);
    const row = rows.find((r) => r.clientMessageId === String(numericId));
    assert.ok(row, 'message row with the numeric id');
    assert.equal(row.status, 'sent');
    assert.equal(row.source, 'legacy');
  });

  it('accepts a null to_name', T, async (t) => {
    if (!h.requireDb(t)) return;
    const to = h.uniqueEmail();
    const res = await postLegacy(legacyBody({ to, to_name: null }));
    assert.equal(res.status, 200, JSON.stringify(res.body));
    const [msg] = smtp.messagesTo(to);
    assert.equal(msg.parsed.to.value[0].address, to);
  });

  it('uses to_name as the display name', T, async (t) => {
    if (!h.requireDb(t)) return;
    const to = h.uniqueEmail();
    const res = await postLegacy(legacyBody({ to, to_name: 'Nimal Perera' }));
    assert.equal(res.status, 200);
    const [msg] = smtp.messagesTo(to);
    assert.deepEqual(msg.parsed.to.value, [{ address: to, name: 'Nimal Perera' }]);
  });

  it('ignores extra fields (cc, bcc, from, reply_to, text, headers)', T, async (t) => {
    if (!h.requireDb(t)) return;
    const to = h.uniqueEmail();
    const extra = h.uniqueEmail('extra');
    const res = await postLegacy(
      legacyBody({
        to,
        cc: extra,
        bcc: [extra],
        from: 'spoof@evil.example.com',
        reply_to: extra,
        text: 'ignored text',
        headers: { 'X-Injected': '1' },
        unknown_field: { nested: true },
      })
    );
    assert.equal(res.status, 200, JSON.stringify(res.body));
    const [msg] = smtp.messagesTo(to);
    assert.deepEqual(msg.envelope.rcptTo, [to]);
    assert.equal(msg.envelope.mailFrom, legacy.app.fromEmail);
    assert.equal(msg.parsed.from.value[0].address, legacy.app.fromEmail);
    assert.equal(msg.parsed.cc, undefined);
    assert.equal(msg.parsed.replyTo, undefined);
    assert.equal(msg.parsed.headers.has('x-injected'), false);
    assert.equal(smtp.messagesTo(extra).length, 0);
  });

  it('requires exactly one recipient', T, async (t) => {
    if (!h.requireDb(t)) return;
    const res = await postLegacy(legacyBody({ to: [h.uniqueEmail(), h.uniqueEmail()] }));
    assert.equal(res.status, 400);
    assert.deepEqual(res.body, { error: 'exactly one recipient required' });
  });

  it('answers a signed body that is not JSON with 400 {error} and logs it as rejected', T, async (t) => {
    if (!h.requireDb(t)) return;
    const own = await h.insertTestApp(deps, { smtp, legacySigning: true });
    const res = await postLegacy('this is not json', { key: own.key });
    assert.equal(res.status, 400);
    assert.deepEqual(res.body, { error: 'invalid json body' });
    const rows = await h.listMessages(deps, own.app.id);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].status, 'rejected');
    assert.equal(rows[0].source, 'legacy');
    assert.equal(rows[0].httpStatus, 400);
    assert.equal(rows[0].error, 'invalid json body');
  });

  it('logs nothing for a request with a bad signature', T, async (t) => {
    if (!h.requireDb(t)) return;
    const own = await h.insertTestApp(deps, { smtp, legacySigning: true });
    const body = legacyBody();
    const ts = nowTs();
    const res = await postLegacy(body, { key: own.key, ts, signature: phpSign(own.key + 'x', ts, body) });
    assert.equal(res.status, 401);
    assert.deepEqual(await h.listMessages(deps, own.app.id), []);
  });

  // PHP's json_encode escapes "/" and non-ASCII characters by default, and the
  // signature covers exactly those bytes. Re-serialising the JSON before the
  // check would break every such request.
  it('verifies the signature over the raw bytes PHP json_encode sends', T, async (t) => {
    if (!h.requireDb(t)) return;
    const to = h.uniqueEmail('applicant');
    const fields = {
      message_id: h.uniqueName('php'),
      to,
      to_name: 'නිමල් පෙරේරා',
      subject: 'ඔබගේ ගිණුම් අයදුම්පත 😀',
      html: '<p>See https://x.example/a</p>',
    };
    const raw = phpJsonEncode(fields);
    assert.ok(raw.includes('<\\/p>'), 'escaped slashes in the fixture');
    assert.ok(raw.includes('\\u0d'), 'escaped Sinhala in the fixture');
    assert.ok(raw.includes('\\ud83d\\ude00'), 'surrogate pair escapes in the fixture');
    assert.notEqual(raw, JSON.stringify(fields));

    const res = await postLegacy(raw, { contentType: 'application/x-www-form-urlencoded' });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.deepEqual(res.body, { ok: true });
    const [msg] = smtp.messagesTo(to);
    assert.match(msg.parsed.html, /<p>See https:\/\/x\.example\/a<\/p>/);
    assert.equal(msg.parsed.subject, fields.subject);
    assert.equal(msg.parsed.to.value[0].name, fields.to_name);
  });

  it('accepts pretty-printed JSON signed as sent', T, async (t) => {
    if (!h.requireDb(t)) return;
    const to = h.uniqueEmail();
    const raw = JSON.stringify(JSON.parse(legacyBody({ to })), null, 4) + '\n';
    const res = await postLegacy(raw);
    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.equal(smtp.messagesTo(to).length, 1);
  });

  it('accepts a body that starts with a UTF-8 BOM (signed including the BOM)', T, async (t) => {
    if (!h.requireDb(t)) return;
    const to = h.uniqueEmail();
    const raw = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(legacyBody({ to }), 'utf8')]);
    const ts = nowTs();
    const res = await request(httpApp)
      .post('/send.php')
      .set('Content-Type', 'application/json')
      .set('X-Relay-Timestamp', ts)
      .set('X-Relay-Signature', phpSign(legacy.key, ts, raw))
      // superagent would JSON-serialise a Buffer sent as application/json.
      .serialize((b) => b)
      .send(raw);
    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.equal(smtp.messagesTo(to).length, 1);
  });

  it('refuses a body that differs from the signed bytes only in JSON formatting', T, async (t) => {
    if (!h.requireDb(t)) return;
    const to = h.uniqueEmail();
    const fields = { message_id: h.uniqueName('fmt'), to, subject: 'S', html: '<p>a/b</p>' };
    const ts = nowTs();
    // Signed canonical, sent escaped: the same JSON value, other bytes.
    const sent = await postLegacy(phpJsonEncode(fields), { ts, signature: phpSign(legacy.key, ts, JSON.stringify(fields)) });
    assert.equal(sent.status, 401);
    assert.deepEqual(sent.body, { error: 'invalid signature' });
    // And the other way round.
    const back = await postLegacy(JSON.stringify(fields), { ts, signature: phpSign(legacy.key, ts, phpJsonEncode(fields)) });
    assert.equal(back.status, 401);
    assert.equal(smtp.messagesTo(to).length, 0);
  });

  it('delivers an attachment with its filename and content intact', T, async (t) => {
    if (!h.requireDb(t)) return;
    const to = h.uniqueEmail();
    const body = legacyBody({
      to,
      attachments: [{ filename: 'application.pdf', content_type: 'application/octet-stream', content_base64: PDF.toString('base64') }],
    });
    const res = await postLegacy(body, { contentType: 'application/x-www-form-urlencoded' });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.deepEqual(res.body, { ok: true });
    const [msg] = smtp.messagesTo(to);
    assert.equal(msg.parsed.attachments.length, 1);
    const [file] = msg.parsed.attachments;
    assert.equal(file.filename, 'application.pdf');
    assert.equal(file.contentType, 'application/pdf');
    assert.ok(file.content.equals(PDF), 'the PDF arrives byte for byte');
  });

  it('refuses a disallowed attachment type with 400 and delivers nothing', T, async (t) => {
    if (!h.requireDb(t)) return;
    const own = await h.insertTestApp(deps, { smtp, legacySigning: true });
    const to = h.uniqueEmail();
    const body = legacyBody({ to, attachments: [{ filename: 'setup.exe', content_base64: h.b64(Buffer.from('MZ\x90\x00', 'latin1')) }] });
    const res = await postLegacy(body, { key: own.key });
    assert.equal(res.status, 400);
    assert.deepEqual(res.body, { error: 'attachment type not allowed: exe' });
    assert.equal(smtp.messagesTo(to).length, 0);
    const last = (await h.listMessages(deps, own.app.id)).at(-1);
    assert.equal(last.status, 'rejected');
    assert.equal(last.source, 'legacy');
    assert.equal(last.httpStatus, 400);
  });

  it('applies the app size limit to legacy attachments, exactly up to the limit', T, async (t) => {
    if (!h.requireDb(t)) return;
    const limit = 5000;
    const small = await h.insertTestApp(deps, { smtp, legacySigning: true, maxMessageBytes: limit });
    // Size = subject + html + to_name + attachment bytes + 1024 per attachment +
    // 6 per UTF-8 byte of its filename (the generated
    // text part is not counted). 'form.pdf' is 8 bytes: 48.
    const fixed = { subject: 'Size check', html: '<p>size</p>', to_name: 'Applicant' };
    const textBytes = Object.values(fixed).reduce((n, s) => n + Buffer.byteLength(s), 0);
    const room = limit - textBytes - 1024 - 6 * Buffer.byteLength('form.pdf');
    const pdfOf = (size) => Buffer.concat([PDF, Buffer.alloc(size - PDF.length, 0x20)]);
    const withPdf = (to, size) =>
      legacyBody({ ...fixed, to, attachments: [{ filename: 'form.pdf', content_base64: pdfOf(size).toString('base64') }] });

    const fitsTo = h.uniqueEmail();
    const fits = await postLegacy(withPdf(fitsTo, room), { key: small.key });
    assert.equal(fits.status, 200, JSON.stringify(fits.body));
    assert.equal(smtp.messagesTo(fitsTo).length, 1);

    const overTo = h.uniqueEmail();
    const over = await postLegacy(withPdf(overTo, room + 1), { key: small.key });
    assert.equal(over.status, 413);
    assert.deepEqual(over.body, { error: 'message too large' });

    const wayOverTo = h.uniqueEmail();
    const wayOver = await postLegacy(withPdf(wayOverTo, 3 * limit), { key: small.key });
    assert.equal(wayOver.status, 413);
    assert.deepEqual(wayOver.body, { error: 'message too large' });
    assert.equal(smtp.messagesTo(overTo).length + smtp.messagesTo(wayOverTo).length, 0);
  });

  it('refuses a "to" string with two addresses', T, async (t) => {
    if (!h.requireDb(t)) return;
    const [a, b] = [h.uniqueEmail(), h.uniqueEmail()];
    const res = await postLegacy(legacyBody({ to: `${a}, ${b}` }));
    assert.equal(res.status, 400);
    assert.deepEqual(res.body, { error: 'exactly one recipient required' });
    assert.equal(smtp.messagesTo(a).length + smtp.messagesTo(b).length, 0);
  });

  it('answers 401 before reading the body when no legacy key exists', T, async (t) => {
    if (!h.requireDb(t)) return;
    // Other test files keep legacy keys in the shared database, so this relay
    // sees none: its key query answers with no rows. A tiny body limit shows
    // the order: reading the body first would give 413.
    const noKeys = {
      ...deps,
      config: { ...deps.config, bodyLimitBytes: 1024 },
      db: {
        ...deps.db,
        query: (sql, params) => (/FROM api_keys k JOIN apps a/i.test(sql) ? Promise.resolve([]) : deps.db.query(sql, params)),
      },
    };
    const noKeysApp = h.createHttpApp(noKeys);
    const raw = legacyBody({ html: '<p>' + 'x'.repeat(4000) + '</p>' });
    const ts = nowTs();
    const res = await request(noKeysApp)
      .post('/send.php')
      .set('Content-Type', 'application/json')
      .set('X-Relay-Timestamp', ts)
      .set('X-Relay-Signature', phpSign(legacy.key, ts, raw))
      .send(raw);
    assert.equal(res.status, 401);
    assert.deepEqual(res.body, { error: 'invalid signature' });
    assert.equal(res.headers.connection, 'close');

    // The same request to the normal relay is read, and refused as too large.
    const limited = h.createHttpApp({ ...deps, config: { ...deps.config, bodyLimitBytes: 1024 } });
    const read = await request(limited)
      .post('/send.php')
      .set('Content-Type', 'application/json')
      .set('X-Relay-Timestamp', ts)
      .set('X-Relay-Signature', phpSign(legacy.key, ts, raw))
      .send(raw);
    assert.equal(read.status, 413);
    assert.deepEqual(read.body, { error: 'request too large' });
  });

  it('refuses a disabled legacy app with 403', T, async (t) => {
    if (!h.requireDb(t)) return;
    const disabled = await h.insertTestApp(deps, { smtp, legacySigning: true, enabled: false });
    const to = h.uniqueEmail();
    const res = await postLegacy(legacyBody({ to }), { key: disabled.key });
    assert.equal(res.status, 403);
    assert.deepEqual(res.body, { error: 'app disabled' });
    assert.equal(smtp.messagesTo(to).length, 0);
  });

  it('does not accept a legacy key as a Bearer key on /v1/send', T, async (t) => {
    if (!h.requireDb(t)) return;
    const res = await h.postV1(httpApp, legacy.key, { to: h.uniqueEmail(), subject: 's', text: 't' });
    assert.equal(res.status, 401);
    assert.deepEqual(res.body, { ok: false, error: 'invalid api key' });
  });

  it('refuses a hashed key on /v1/send once its app signs legacy requests', T, async (t) => {
    if (!h.requireDb(t)) return;
    // Normally unreachable (turning legacy signing on revokes every key); this
    // pins the guard in authenticateBearer itself.
    const { app, key } = await h.insertTestApp(deps, { smtp });
    const send = () => h.postV1(httpApp, key, { to: h.uniqueEmail(), subject: 's', text: 't' });
    assert.equal((await send()).status, 200);
    await appsRepo.updateApp(deps.db, app.id, { legacySigning: true }, deps.clock.now());
    const res = await send();
    assert.equal(res.status, 401);
    assert.deepEqual(res.body, { ok: false, error: 'invalid api key' });
  });

  it('answers GET /send.php with 405', T, async (t) => {
    if (!h.requireDb(t)) return;
    const res = await request(httpApp).get('/send.php');
    assert.equal(res.status, 405);
    assert.deepEqual(res.body, { error: 'method not allowed' });
  });
});
