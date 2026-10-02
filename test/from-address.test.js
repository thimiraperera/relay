'use strict';

// The sender cannot be spoofed: the From name and address come from the app's
// settings (a caller may only pick the app's From or one of its allowed
// alternatives), caller-supplied headers/envelope are ignored, and CR/LF in
// header-bound values never produce extra headers or recipients.

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const h = require('./support/helpers');

const T = { timeout: 30000 };
const PDF = Buffer.from('%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n', 'latin1');

function headerSection(raw) {
  const text = raw.toString('utf8');
  const end = text.indexOf('\r\n\r\n');
  return end === -1 ? text : text.slice(0, end);
}

// Header names as they appear at the start of a header line (folded
// continuation lines start with whitespace and are not header names).
function headerNames(raw) {
  return headerSection(raw)
    .split('\r\n')
    .filter((line) => /^[^\s:]+:/.test(line))
    .map((line) => line.slice(0, line.indexOf(':')).toLowerCase());
}

describe('From address and header safety', () => {
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

  function send(key, body) {
    return h.postV1(httpApp, key, { subject: 'From test', text: 'Hello', ...body });
  }

  it('always sends as the app From name and address', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { app, key } = await h.insertTestApp(deps, { smtp, fromName: 'Acme Billing' });
    const to = h.uniqueEmail();
    const res = await send(key, { to });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    const [msg] = smtp.messagesTo(to);
    assert.deepEqual(msg.parsed.from.value, [{ address: app.fromEmail, name: 'Acme Billing' }]);
    assert.equal(msg.envelope.mailFrom, app.fromEmail);
  });

  it('ignores a display name in the caller from', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { app, key } = await h.insertTestApp(deps, { smtp, fromName: 'Acme Billing' });
    const to = h.uniqueEmail();
    const res = await send(key, { to, from: `"CEO (urgent)" <${app.fromEmail.toUpperCase()}>` });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    const [msg] = smtp.messagesTo(to);
    assert.equal(msg.parsed.from.value[0].name, 'Acme Billing');
    assert.equal(msg.parsed.from.value[0].address.toLowerCase(), app.fromEmail.toLowerCase());
  });

  it('refuses a from address that is not allowed and delivers nothing', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { app, key } = await h.insertTestApp(deps, { smtp });
    const to = h.uniqueEmail();
    const res = await send(key, { to, from: 'ceo@other-company.example.com' });
    assert.equal(res.status, 400);
    assert.deepEqual(res.body, { ok: false, error: 'from not allowed' });
    assert.equal(smtp.messagesTo(to).length, 0);
    const rows = await h.listMessages(deps, app.id);
    assert.equal(rows.at(-1).status, 'rejected');
    assert.equal(rows.at(-1).error, 'from not allowed');
  });

  it('accepts an allowed alternative From (case-insensitive) with the app From name', T, async (t) => {
    if (!h.requireDb(t)) return;
    const alt = `billing.${h.uniqueId()}@relay-test.example.com`;
    const { key } = await h.insertTestApp(deps, { smtp, fromName: 'Acme', allowedFrom: [alt] });
    const to = h.uniqueEmail();
    const res = await send(key, { to, from: alt.toUpperCase() });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    const [msg] = smtp.messagesTo(to);
    assert.equal(msg.envelope.mailFrom.toLowerCase(), alt);
    assert.equal(msg.parsed.from.value[0].address.toLowerCase(), alt);
    assert.equal(msg.parsed.from.value[0].name, 'Acme');
  });

  it('ignores headers, sender and envelope fields in the body', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { app, key } = await h.insertTestApp(deps, { smtp });
    const to = h.uniqueEmail();
    const evil = h.uniqueEmail('evil', 'evil.example.com');
    const res = await send(key, {
      to,
      headers: { 'X-Injected': 'yes', From: evil, Bcc: evil, Sender: evil },
      sender: evil,
      envelope: { from: evil, to: [evil] },
      return_path: evil,
    });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    const [msg] = smtp.messagesTo(to);
    assert.deepEqual(msg.envelope.rcptTo, [to]);
    assert.equal(msg.envelope.mailFrom, app.fromEmail);
    assert.equal(msg.parsed.from.value[0].address, app.fromEmail);
    const names = headerNames(msg.raw);
    assert.ok(!names.includes('x-injected'));
    assert.ok(!names.includes('sender'));
    assert.ok(!names.includes('bcc'));
    assert.ok(!msg.raw.toString('utf8').includes(evil));
    assert.equal(smtp.messagesTo(evil).length, 0);
  });

  it('CR/LF in subject, reply_to, to name and filename add no headers or recipients', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { key } = await h.insertTestApp(deps, { smtp });
    const to = h.uniqueEmail('alice');
    const victim = h.uniqueEmail('victim', 'victim.example.com');
    const ls = String.fromCharCode(0x2028);
    const res = await send(key, {
      to: `"Alice\r\nBcc: ${victim}\r\nX-Injected: to" <${to}>`,
      reply_to: `"Support\r\nX-Injected: reply" <support@example.com>`,
      subject: `Hello\r\nBcc: ${victim}\r\nX-Injected: subject${ls}X-Line-Sep: 1`,
      attachments: [{ filename: `report\r\nX-Injected: file.pdf`, content_base64: h.b64(PDF) }],
    });
    assert.equal(res.status, 200, JSON.stringify(res.body));

    const [msg] = smtp.messagesTo(to);
    assert.deepEqual(msg.envelope.rcptTo, [to]);
    assert.equal(smtp.messagesTo(victim).length, 0);

    const names = headerNames(msg.raw);
    for (const forbidden of ['x-injected', 'x-line-sep', 'bcc']) {
      assert.ok(!names.includes(forbidden), `unexpected ${forbidden} header`);
    }
    assert.equal(msg.parsed.headers.has('x-injected'), false);
    assert.doesNotMatch(msg.parsed.subject, /[\r\n]/);
    assert.match(msg.parsed.subject, /^Hello /);
    assert.equal(msg.parsed.to.value.length, 1);
    assert.equal(msg.parsed.to.value[0].address, to);
    assert.doesNotMatch(msg.parsed.to.value[0].name, /[\r\n]/);
    assert.equal(msg.parsed.replyTo.value[0].address, 'support@example.com');
    assert.doesNotMatch(msg.parsed.replyTo.value[0].name, /[\r\n]/);
    assert.equal(msg.parsed.attachments.length, 1);
    assert.doesNotMatch(msg.parsed.attachments[0].filename, /[\r\n]/);
    assert.match(msg.parsed.attachments[0].filename, /\.pdf$/);
  });

  it('uses the chosen From as MAIL FROM and every to/cc/bcc address as RCPT TO', T, async (t) => {
    if (!h.requireDb(t)) return;
    const alt = `notify.${h.uniqueId()}@relay-test.example.com`;
    const { key } = await h.insertTestApp(deps, { smtp, allowedFrom: [alt] });
    const a = h.uniqueEmail('a');
    const b = h.uniqueEmail('b');
    const c = h.uniqueEmail('c');
    const d = h.uniqueEmail('d');
    const res = await send(key, { from: alt, to: [a, `B Person <${b}>`], cc: c, bcc: [d] });
    assert.equal(res.status, 200, JSON.stringify(res.body));

    const [msg] = smtp.messagesTo(a);
    assert.equal(msg.envelope.mailFrom, alt);
    assert.deepEqual([...msg.envelope.rcptTo].sort(), [a, b, c, d].sort());
    assert.deepEqual(
      msg.parsed.to.value.map((v) => v.address),
      [a, b]
    );
    assert.deepEqual(
      msg.parsed.cc.value.map((v) => v.address),
      [c]
    );
    assert.ok(!headerNames(msg.raw).includes('bcc'), 'Bcc recipients are not listed in the headers');
    assert.ok(!msg.raw.toString('utf8').includes(d));
  });

  it('uses the caller reply_to, else the app default', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { key } = await h.insertTestApp(deps, { smtp, replyToDefault: 'help@relay-test.example.com' });
    const to1 = h.uniqueEmail();
    assert.equal((await send(key, { to: to1 })).status, 200);
    assert.equal(smtp.messagesTo(to1)[0].parsed.replyTo.value[0].address, 'help@relay-test.example.com');

    const to2 = h.uniqueEmail();
    assert.equal((await send(key, { to: to2, reply_to: 'Desk <desk@example.com>' })).status, 200);
    assert.deepEqual(smtp.messagesTo(to2)[0].parsed.replyTo.value, [{ address: 'desk@example.com', name: 'Desk' }]);
  });

  it('refuses invalid addresses', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { key } = await h.insertTestApp(deps, { smtp });
    const cases = [
      [{ to: 'not an address' }, 'invalid to address'],
      [{ to: 'user@[127.0.0.1]' }, 'invalid to address'],
      [{ to: `a@example.com\r\nBcc: b@example.com` }, 'invalid to address'],
      [{ to: h.uniqueEmail(), cc: 'nope@' }, 'invalid cc address'],
      [{ to: h.uniqueEmail(), bcc: ['ok@example.com', 'bad'] }, 'invalid bcc address'],
      [{ to: h.uniqueEmail(), reply_to: 'a@example.com, b@example.com' }, 'invalid reply_to address'],
      [{ to: h.uniqueEmail(), from: 'not-an-address' }, 'invalid from address'],
    ];
    for (const [body, error] of cases) {
      const res = await send(key, body);
      assert.equal(res.status, 400, JSON.stringify(body));
      assert.deepEqual(res.body, { ok: false, error });
    }
  });
});
