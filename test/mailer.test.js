'use strict';

// The SMTP client (src/services/mailer.js) without a database:
// the connection options (TLS always verified, per-phase timeouts, exactly one
// resolved address), and its behaviour against local servers: TLS refusals,
// AUTH that is never skipped, the overall deadline, and which failures count
// as "outcome unknown" (the message data had started to flow, so the server
// may already have accepted the message; docs/SPEC.md decisions 1 and 5).

const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const { SMTPServer } = require('smtp-server');
const SMTPConnection = require('nodemailer/lib/smtp-connection');
const { buildConnectionOptions, resolveSmtpHost, sendMail } = require('../src/services/mailer');
const { buildMail } = require('../src/services/send');

const T = { timeout: 30000 };
const TLS_OPTIONS = { rejectUnauthorized: true, minVersion: 'TLSv1.2' };

function appWith(overrides = {}) {
  return {
    id: 1,
    smtpHost: 'smtp.example.com',
    smtpPort: 587,
    smtpEncryption: 'starttls',
    smtpUsername: '',
    fromEmail: 'sender@relay-test.example.com',
    fromName: 'Relay Test',
    ...overrides,
  };
}

function mailTo(to) {
  return {
    from: { name: 'Relay Test', address: 'sender@relay-test.example.com' },
    to: [{ address: to, name: '' }],
    subject: 'Mailer test',
    text: 'Hello from the mailer test',
    disableFileAccess: true,
    disableUrlAccess: true,
  };
}

function depsWith(config, extra = {}) {
  return { config: { smtpTimeoutMs: 5000, smtpSendDeadlineMs: 20000, ...config }, ...extra };
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

// A local smtp-server that records which hooks ran. `options` go to SMTPServer
// (secure, disabledCommands, ...). Without `secure`/`key`/`cert`, smtp-server
// uses its bundled self-signed certificate, which no client should trust.
async function startRecordingServer(options = {}) {
  const calls = { auth: 0, data: 0, rcpt: [] };
  const server = new SMTPServer({
    authOptional: true,
    allowInsecureAuth: true,
    logger: false,
    closeTimeout: 500,
    onAuth(auth, session, callback) {
      calls.auth++;
      callback(null, { user: auth.username });
    },
    onRcptTo(address, session, callback) {
      calls.rcpt.push(address.address);
      if (/^refused/i.test(address.address)) {
        return callback(Object.assign(new Error('No such user (test server)'), { responseCode: 550 }));
      }
      callback();
    },
    onData(stream, session, callback) {
      calls.data++;
      stream.on('data', () => {});
      stream.on('end', () => {
        if (options.dataCode) return callback(Object.assign(new Error('Rejected (test server)'), { responseCode: options.dataCode }));
        callback(null, 'Queued as mailer-test');
      });
    },
    ...options,
  });
  // A client that aborts the TLS handshake makes smtp-server emit 'error'.
  server.on('error', () => {});
  const port = await listen(server.server);
  return { port, calls, close: () => new Promise((resolve) => server.close(() => resolve())) };
}

// A hand-written SMTP server for the failure modes smtp-server cannot produce.
//   greet: false        accept the connection and never send the greeting
//   stallOn: 'RCPT'     go silent when that command arrives
//   afterData: 'drop'   destroy the socket once the final dot arrived
//              'silent' never answer the final dot
async function startScriptedServer({ greet = true, stallOn = null, afterData = 'silent' } = {}) {
  const sockets = new Set();
  const stats = { dataReceived: 0 };
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => {});
    if (!greet) return;
    socket.write('220 scripted.test ESMTP\r\n');
    let buf = '';
    let inData = false;
    let silent = false;
    socket.on('data', (chunk) => {
      if (silent) return;
      buf += chunk.toString('latin1');
      for (;;) {
        if (inData) {
          const end = buf.indexOf('\r\n.\r\n');
          if (end === -1) {
            buf = buf.slice(-4);
            return;
          }
          inData = false;
          silent = true;
          stats.dataReceived++;
          if (afterData === 'drop') socket.destroy();
          return;
        }
        const nl = buf.indexOf('\r\n');
        if (nl === -1) return;
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 2);
        const cmd = line.slice(0, 4).toUpperCase();
        if (stallOn && cmd === stallOn) {
          silent = true;
          return;
        }
        if (cmd === 'EHLO' || cmd === 'HELO') socket.write('250 scripted.test\r\n');
        else if (cmd === 'MAIL' || cmd === 'RCPT' || cmd === 'RSET' || cmd === 'NOOP') socket.write('250 OK\r\n');
        else if (cmd === 'DATA') {
          socket.write('354 Go ahead\r\n');
          inData = true;
        } else if (cmd === 'QUIT') socket.end('221 Bye\r\n');
        else socket.write('502 Unknown command\r\n');
      }
    });
  });
  const port = await listen(server);
  return {
    port,
    stats,
    close() {
      for (const s of sockets) s.destroy();
      return new Promise((resolve) => server.close(() => resolve()));
    },
  };
}

// → { err, ms }: sendMail must reject; the elapsed time is returned for the
// timeout checks.
async function sendExpectingFailure(deps, app, to = 'someone@example.com') {
  const started = Date.now();
  try {
    await sendMail(deps, { app, smtpPassword: 'test-password', mail: mailTo(to) });
  } catch (err) {
    return { err, ms: Date.now() - started };
  }
  assert.fail('sendMail resolved, expected a failure');
}

function assertSendError(err) {
  assert.equal(typeof err.smtpCode, 'string');
  assert.match(err.smtpCode, /^[A-Za-z0-9_.-]+$/);
  assert.equal(typeof err.detail, 'string');
  assert.doesNotMatch(err.detail, /[\r\n]/);
  assert.equal(typeof err.outcomeUnknown, 'boolean');
}

describe('buildConnectionOptions', () => {
  const config = { smtpTimeoutMs: 30000, smtpSendDeadlineMs: 50000 };

  it('maps each encryption to secure / requireTLS / ignoreTLS', () => {
    const cases = {
      ssl: { secure: true, requireTLS: false, ignoreTLS: false },
      starttls: { secure: false, requireTLS: true, ignoreTLS: false },
      none: { secure: false, requireTLS: false, ignoreTLS: true },
    };
    for (const [enc, want] of Object.entries(cases)) {
      const opts = buildConnectionOptions(appWith({ smtpEncryption: enc }), config, '192.0.2.10');
      assert.deepEqual({ secure: opts.secure, requireTLS: opts.requireTLS, ignoreTLS: opts.ignoreTLS }, want, enc);
    }
  });

  it('always verifies certificates with TLS 1.2 or newer', () => {
    for (const enc of ['ssl', 'starttls', 'none']) {
      const opts = buildConnectionOptions(appWith({ smtpEncryption: enc }), config, '192.0.2.10');
      assert.deepEqual(opts.tls, TLS_OPTIONS, enc);
    }
  });

  it('bounds every phase by SMTP_TIMEOUT_MS', () => {
    for (const t of [30000, 2000]) {
      const opts = buildConnectionOptions(appWith(), { ...config, smtpTimeoutMs: t }, '192.0.2.10');
      assert.equal(opts.connectionTimeout, t);
      assert.equal(opts.greetingTimeout, t);
      assert.equal(opts.socketTimeout, t);
    }
  });

  it('connects to the resolved address and checks the certificate against the host name', () => {
    const opts = buildConnectionOptions(appWith({ smtpHost: 'mail.example.com', smtpPort: 465 }), config, '192.0.2.10');
    assert.equal(opts.host, '192.0.2.10');
    assert.equal(opts.port, 465);
    assert.equal(opts.servername, 'mail.example.com');
    assert.equal(opts.logger, false);
  });

  it('sends no servername for an IP literal host', () => {
    for (const host of ['192.0.2.25', '2001:db8::25']) {
      const opts = buildConnectionOptions(appWith({ smtpHost: host }), config);
      assert.equal(opts.host, host);
      assert.equal('servername' in opts, false, host);
    }
  });

  it('never carries the SMTP credentials (they go to login())', () => {
    const opts = buildConnectionOptions(appWith({ smtpUsername: 'mailer' }), config, '192.0.2.10');
    assert.equal('auth' in opts, false);
    assert.ok(!JSON.stringify(opts).includes('mailer'));
  });
});

describe('buildMail (the message the mailer composes)', () => {
  const message = {
    to: [{ address: 'to@example.com', name: 'To' }],
    cc: [],
    bcc: [{ address: 'hidden@example.com', name: '' }],
    fromAddress: null,
    replyTo: null,
    subject: 'Subject',
    html: '<p>Hi</p>',
    text: 'Hi',
    attachments: [],
    clientMessageId: null,
    sizeBytes: 0,
  };

  it('turns off file and URL access and carries no envelope, sender or caller headers', () => {
    const mail = buildMail(appWith(), message, 'msg_0123456789abcdef01234567');
    assert.equal(mail.disableFileAccess, true);
    assert.equal(mail.disableUrlAccess, true);
    for (const field of ['envelope', 'sender', 'headers']) assert.equal(field in mail, false, field);
    assert.equal(mail.messageId, '<msg_0123456789abcdef01234567@relay-test.example.com>');
  });

  it('a mail that asks for a local file is refused before any connection is made', T, async () => {
    const made = [];
    const deps = depsWith(
      {},
      {
        smtpConnectionFactory(options) {
          made.push(options);
          return new SMTPConnection(options);
        },
      }
    );
    const mail = { ...mailTo('file@example.com'), attachments: [{ filename: 'secret.txt', path: __filename }] };
    const app = appWith({ smtpHost: '127.0.0.1', smtpPort: 9, smtpEncryption: 'none' });
    await assert.rejects(sendMail(deps, { app, smtpPassword: null, mail }), (err) => {
      assertSendError(err);
      assert.equal(err.outcomeUnknown, false);
      assert.match(err.detail, /file access/i);
      return true;
    });
    assert.equal(made.length, 0, 'no SMTP connection');
  });
});

describe('resolveSmtpHost', () => {
  it('uses an IP literal as it is', async () => {
    assert.equal(await resolveSmtpHost('127.0.0.1', 1000), '127.0.0.1');
    assert.equal(await resolveSmtpHost('::1', 1000), '::1');
  });

  it('fails with EDNS for a name that cannot resolve, within its time bound', T, async () => {
    const started = Date.now();
    await assert.rejects(resolveSmtpHost('no-such-host.invalid', 3000), (err) => {
      assert.equal(err.code, 'EDNS');
      assert.match(err.message, /no-such-host\.invalid/);
      return true;
    });
    assert.ok(Date.now() - started < 3000 + 2000, `took ${Date.now() - started} ms`);
  });
});

describe('sendMail against local servers', () => {
  const servers = [];

  after(async () => {
    for (const s of servers) await s.close();
  });

  async function recording(options) {
    const s = await startRecordingServer(options);
    servers.push(s);
    return s;
  }

  async function scripted(options) {
    const s = await startScriptedServer(options);
    servers.push(s);
    return s;
  }

  it('delivers through one connection to the resolved address', T, async () => {
    const server = await recording({ disabledCommands: ['STARTTLS'] });
    const made = [];
    const deps = depsWith(
      {},
      {
        smtpConnectionFactory(options) {
          made.push(options);
          return new SMTPConnection(options);
        },
      }
    );
    const app = appWith({ smtpHost: '127.0.0.1', smtpPort: server.port, smtpEncryption: 'none' });
    const info = await sendMail(deps, { app, smtpPassword: null, mail: mailTo('ok@example.com') });
    assert.deepEqual(info.accepted, ['ok@example.com']);
    assert.deepEqual(info.rejected, []);
    assert.match(info.response, /^250/);
    assert.equal(typeof info.messageId, 'string');
    assert.equal(made.length, 1, 'exactly one connection');
    assert.equal(made[0].host, '127.0.0.1');
    assert.deepEqual(made[0].tls, TLS_OPTIONS);
    assert.equal(server.calls.data, 1);
    assert.equal(server.calls.auth, 0, 'no AUTH without a username');
  });

  it('refuses STARTTLS that the server does not offer (ETLS) and sends nothing', T, async () => {
    const server = await recording({ disabledCommands: ['STARTTLS'] });
    const app = appWith({ smtpHost: '127.0.0.1', smtpPort: server.port, smtpEncryption: 'starttls', smtpUsername: 'mailer' });
    const { err } = await sendExpectingFailure(depsWith({}), app);
    assertSendError(err);
    assert.equal(err.smtpCode, 'ETLS');
    assert.equal(err.outcomeUnknown, false);
    assert.equal(server.calls.auth, 0, 'credentials never sent in clear text');
    assert.equal(server.calls.data, 0);
  });

  it('refuses an untrusted certificate after STARTTLS', T, async () => {
    const server = await recording({});
    const app = appWith({ smtpHost: '127.0.0.1', smtpPort: server.port, smtpEncryption: 'starttls', smtpUsername: 'mailer' });
    const { err } = await sendExpectingFailure(depsWith({}), app);
    assertSendError(err);
    assert.match(err.smtpCode, /^(ESOCKET|ETLS)$/);
    assert.equal(err.outcomeUnknown, false);
    assert.equal(server.calls.auth, 0);
    assert.equal(server.calls.data, 0);
  });

  it('refuses an untrusted certificate on implicit TLS (ssl) with ESOCKET', T, async () => {
    const server = await recording({ secure: true });
    const app = appWith({ smtpHost: '127.0.0.1', smtpPort: server.port, smtpEncryption: 'ssl', smtpUsername: 'mailer' });
    const { err } = await sendExpectingFailure(depsWith({}), app);
    assertSendError(err);
    assert.equal(err.smtpCode, 'ESOCKET');
    assert.equal(err.outcomeUnknown, false);
    assert.equal(server.calls.auth, 0);
    assert.equal(server.calls.data, 0);
  });

  it('fails (EAUTH) instead of sending unauthenticated when the server offers no AUTH', T, async () => {
    const server = await recording({ disabledCommands: ['STARTTLS', 'AUTH'] });
    const app = appWith({ smtpHost: '127.0.0.1', smtpPort: server.port, smtpEncryption: 'none', smtpUsername: 'mailer' });
    const { err } = await sendExpectingFailure(depsWith({}), app);
    assertSendError(err);
    assert.equal(err.smtpCode, 'EAUTH');
    assert.equal(err.outcomeUnknown, false);
    assert.equal(server.calls.data, 0);
  });

  it('a 550 at RCPT is a definite failure (EENVELOPE 550)', T, async () => {
    const server = await recording({ disabledCommands: ['STARTTLS'] });
    const app = appWith({ smtpHost: '127.0.0.1', smtpPort: server.port, smtpEncryption: 'none' });
    const { err } = await sendExpectingFailure(depsWith({}), app, 'refused@example.com');
    assertSendError(err);
    assert.equal(err.smtpCode, 'EENVELOPE');
    assert.equal(err.responseCode, 550);
    assert.equal(err.outcomeUnknown, false);
    assert.equal(server.calls.data, 0);
  });

  it('a 550 answer to the message data is a definite failure (EMESSAGE 550)', T, async () => {
    const server = await recording({ disabledCommands: ['STARTTLS'], dataCode: 550 });
    const app = appWith({ smtpHost: '127.0.0.1', smtpPort: server.port, smtpEncryption: 'none' });
    const { err } = await sendExpectingFailure(depsWith({}), app);
    assertSendError(err);
    assert.equal(err.smtpCode, 'EMESSAGE');
    assert.equal(err.responseCode, 550);
    assert.match(err.smtpResponse, /550/);
    assert.equal(err.outcomeUnknown, false);
  });

  it('a refused connection is a definite failure', T, async () => {
    // A port that was just free: nothing listens there any more.
    const probe = net.createServer();
    const port = await listen(probe);
    await new Promise((resolve) => probe.close(resolve));
    const app = appWith({ smtpHost: '127.0.0.1', smtpPort: port, smtpEncryption: 'none' });
    const { err } = await sendExpectingFailure(depsWith({ smtpTimeoutMs: 5000 }), app);
    assertSendError(err);
    assert.equal(err.outcomeUnknown, false);
    assert.equal(err.responseCode, undefined);
  });

  it('a greeting that never comes times out as a definite failure', T, async () => {
    const server = await scripted({ greet: false });
    const app = appWith({ smtpHost: '127.0.0.1', smtpPort: server.port, smtpEncryption: 'none' });
    const { err, ms } = await sendExpectingFailure(depsWith({ smtpTimeoutMs: 1500 }), app);
    assertSendError(err);
    assert.equal(err.smtpCode, 'ETIMEDOUT');
    assert.equal(err.outcomeUnknown, false);
    assert.ok(ms < 1500 + 3000, `took ${ms} ms`);
  });

  it('a stall at RCPT (before any message data) is a definite failure', T, async () => {
    const server = await scripted({ stallOn: 'RCPT' });
    const app = appWith({ smtpHost: '127.0.0.1', smtpPort: server.port, smtpEncryption: 'none' });
    const { err } = await sendExpectingFailure(depsWith({ smtpTimeoutMs: 1500 }), app);
    assertSendError(err);
    assert.equal(err.smtpCode, 'ETIMEDOUT');
    assert.equal(err.outcomeUnknown, false);
    assert.equal(server.stats.dataReceived, 0);
  });

  it('no reply to the final dot (socket timeout) has an unknown outcome', T, async () => {
    const server = await scripted({ afterData: 'silent' });
    const app = appWith({ smtpHost: '127.0.0.1', smtpPort: server.port, smtpEncryption: 'none' });
    const { err, ms } = await sendExpectingFailure(depsWith({ smtpTimeoutMs: 1500 }), app);
    assertSendError(err);
    assert.equal(err.smtpCode, 'ETIMEDOUT');
    assert.equal(err.outcomeUnknown, true);
    assert.equal(err.responseCode, undefined);
    assert.equal(server.stats.dataReceived, 1, 'the server had the whole message');
    assert.ok(ms >= 1000 && ms < 1500 + 3000, `took ${ms} ms`);
  });

  it('a connection dropped after the final dot has an unknown outcome', T, async () => {
    const server = await scripted({ afterData: 'drop' });
    const app = appWith({ smtpHost: '127.0.0.1', smtpPort: server.port, smtpEncryption: 'none' });
    const { err } = await sendExpectingFailure(depsWith({ smtpTimeoutMs: 5000 }), app);
    assertSendError(err);
    assert.equal(err.outcomeUnknown, true);
    assert.equal(err.responseCode, undefined);
    assert.equal(server.stats.dataReceived, 1);
  });

  it('the overall deadline ends a send that each phase timeout would let run on', T, async () => {
    const server = await scripted({ afterData: 'silent' });
    const app = appWith({ smtpHost: '127.0.0.1', smtpPort: server.port, smtpEncryption: 'none' });
    const deps = depsWith({ smtpTimeoutMs: 10000, smtpSendDeadlineMs: 1500 });
    const { err, ms } = await sendExpectingFailure(deps, app);
    assertSendError(err);
    assert.equal(err.smtpCode, 'ETIMEDOUT');
    assert.equal(err.outcomeUnknown, true, 'the deadline hit while the server had the message');
    assert.ok(ms >= 1000 && ms < 1500 + 2500, `took ${ms} ms`);
  });

  it('the deadline during RCPT is a definite failure', T, async () => {
    const server = await scripted({ stallOn: 'RCPT' });
    const app = appWith({ smtpHost: '127.0.0.1', smtpPort: server.port, smtpEncryption: 'none' });
    const deps = depsWith({ smtpTimeoutMs: 10000, smtpSendDeadlineMs: 1500 });
    const { err, ms } = await sendExpectingFailure(deps, app);
    assert.equal(err.smtpCode, 'ETIMEDOUT');
    assert.equal(err.outcomeUnknown, false);
    assert.ok(ms < 1500 + 2500, `took ${ms} ms`);
  });
});
