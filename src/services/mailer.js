'use strict';

// SMTP delivery through the app's own mailbox: one fresh connection per message
// to one resolved address, TLS verification on, every phase bounded by
// config.smtpTimeoutMs and the whole send by config.smtpSendDeadlineMs.
//
// nodemailer's public lower-level modules are driven directly (mail-composer
// builds the message, smtp-connection speaks SMTP) instead of createTransport,
// because the relay needs three things the transport hides:
//   - Where a failure happened. A network failure after the message data
//     started to flow may already have been delivered (outcomeUnknown); one
//     before that cannot have been.
//   - A deadline that really aborts. connection.close() destroys the socket and
//     the pending step settles at once. With a transport, close() left an
//     in-flight send running.
//   - Exactly one connect attempt. The transport resolves every A/AAAA record
//     and tries each one with a full connection timeout, so a firewalled host
//     with several records hung for minutes.

const dns = require('node:dns');
const net = require('node:net');
const { PassThrough, Readable } = require('node:stream');
const MailComposer = require('nodemailer/lib/mail-composer');
const SMTPConnection = require('nodemailer/lib/smtp-connection');
const { describeError } = require('../lib/logger');

const DNS_TRY_TIMEOUT_MS = 5000;
const DNS_TRIES = 2;
// After a successful send: how long QUIT may wait for the server's reply before
// the socket is closed anyway. The caller already has its result.
const QUIT_WAIT_MS = 5000;

const LINE_BREAKS = new RegExp('[\\x00-\\x1F\\x7F' + String.fromCharCode(0x85, 0x2028, 0x2029) + ']+', 'g');

function oneLine(value) {
  if (value === undefined || value === null) return '';
  return String(value).replace(LINE_BREAKS, ' ').trim();
}

function codedError(message, code) {
  const err = new Error(message);
  err.code = code;
  return err;
}

// Monotonic milliseconds, for timeouts only (never business time).
function elapsedSince(start) {
  return performance.now() - start;
}

// IP literal as is. Otherwise A and AAAA in parallel (falling back to the system
// resolver, which also reads the hosts file) and the first IPv4 address, else
// the first IPv6 address. The whole lookup is bounded by timeoutMs; any failure
// is code EDNS.
async function resolveSmtpHost(host, timeoutMs) {
  const name = String(host || '');
  if (net.isIP(name)) return name;

  const resolver = new dns.promises.Resolver({ timeout: Math.max(1, Math.min(timeoutMs, DNS_TRY_TIMEOUT_MS)), tries: DNS_TRIES });
  let abandoned = false;
  const none = () => [];
  async function lookup() {
    const [v4, v6] = await Promise.all([resolver.resolve4(name).catch(none), resolver.resolve6(name).catch(none)]);
    if (v4.length) return v4[0];
    if (v6.length) return v6[0];
    if (abandoned) throw codedError('lookup abandoned', 'ECANCELLED');
    const all = await dns.promises.lookup(name, { all: true });
    const pick = all.find((a) => a.family === 4) || all.find((a) => a.family === 6);
    if (!pick) throw codedError('no address records', 'ENOTFOUND');
    return pick.address;
  }

  let timer = null;
  const timeout = new Promise((resolve, reject) => {
    timer = setTimeout(() => reject(codedError(`timed out after ${timeoutMs} ms`, 'ETIMEOUT')), timeoutMs);
  });
  try {
    return await Promise.race([lookup(), timeout]);
  } catch (err) {
    throw codedError(`could not resolve ${name}: ${describeError(err)}`, 'EDNS');
  } finally {
    abandoned = true;
    clearTimeout(timer);
    resolver.cancel();
  }
}

// Options for one SMTPConnection to `address` (default: the configured host).
// Certificates are checked against the configured host name through
// `servername`, not against the address connected to. An IP literal is never
// passed as servername (Node DEP0123); the IP is then verified as such.
function buildConnectionOptions(app, config, address) {
  const t = config.smtpTimeoutMs;
  const enc = app.smtpEncryption;
  const options = {
    host: address || app.smtpHost,
    port: app.smtpPort,
    secure: enc === 'ssl',
    requireTLS: enc === 'starttls',
    ignoreTLS: enc === 'none',
    connectionTimeout: t,
    greetingTimeout: t,
    socketTimeout: t,
    tls: { rejectUnauthorized: true, minVersion: 'TLSv1.2' },
    logger: false,
  };
  if (!net.isIP(String(app.smtpHost || ''))) options.servername = app.smtpHost;
  return options;
}

// The composed message as a stream. SMTPConnection pipes it into its DATA stream
// only after the server accepted DATA (354); on an envelope error it pipes it
// into a PassThrough just to drain it. onDataStart marks the first case.
function messageStream(raw, onDataStart) {
  let pushed = false;
  const stream = new Readable({
    read() {
      if (pushed) return;
      pushed = true;
      this.push(raw);
      this.push(null);
    },
  });
  const pipe = stream.pipe;
  stream.pipe = function pipeMessage(destination, options) {
    if (!(destination instanceof PassThrough)) onDataStart();
    return pipe.call(this, destination, options);
  };
  return stream;
}

// connect (greeting, EHLO, STARTTLS) -> login -> MAIL/RCPT/DATA -> message data.
// Settles exactly once: a step's callback, the connection's 'error' or 'end'
// event (a closed connection drops pending callbacks) or the deadline, which
// closes the connection. The rejection carries .smtpPhase:
//   connect | auth | envelope (MAIL, RCPT, DATA command) | data (message sent)
function runSession(connection, { auth, envelope, raw, deadlineMs }) {
  return new Promise((resolve, reject) => {
    let phase = 'connect';
    let settled = false;
    let deadlineTimer = null;

    function finish(err, info) {
      if (settled) return;
      settled = true;
      clearTimeout(deadlineTimer);
      if (!err) return resolve(info);
      const out = err instanceof Error ? err : new Error(describeError(err));
      out.smtpPhase = phase;
      reject(out);
    }

    // Stays attached for the life of the connection: a late socket error (for
    // example while QUIT is pending) must not become an unhandled 'error'.
    connection.on('error', (err) => finish(err));
    // SMTPConnection emits 'end' when it is torn down; 'close' covers a
    // replacement from deps.smtpConnectionFactory that names it differently.
    const closed = () => finish(codedError('Connection closed unexpectedly', 'ECONNECTION'));
    connection.once('end', closed);
    connection.once('close', closed);

    deadlineTimer = setTimeout(() => {
      finish(codedError(`send deadline of ${deadlineMs} ms exceeded`, 'ETIMEDOUT'));
      forceClose(connection);
    }, Math.max(0, deadlineMs));

    function startSend() {
      if (settled) return;
      phase = 'envelope';
      const stream = messageStream(raw, () => {
        if (!settled) phase = 'data';
      });
      connection.send(envelope, stream, (err, info) => finish(err, info));
    }

    try {
      connection.connect((err) => {
        if (err) return finish(err);
        if (settled) return;
        if (!auth) return startSend();
        // Without AUTH in the EHLO reply, login() still tries AUTH PLAIN, and a
        // server that refuses it fails the send (EAUTH). It never goes on
        // unauthenticated.
        phase = 'auth';
        connection.login(auth, (loginErr) => {
          if (loginErr) return finish(loginErr);
          startSend();
        });
      });
    } catch (err) {
      finish(err);
    }
  });
}

// close() only half-closes the socket (end()) once the session has started, so a
// peer that never answers our FIN (the stalled server a deadline gave up on)
// would keep the socket, and the process, alive. Destroy it outright. The
// socket is a private field of SMTPConnection, hence the defensive checks.
function forceClose(connection) {
  try {
    connection.close();
  } catch {
    // already closed
  }
  try {
    const socket = connection._socket;
    if (socket && typeof socket.destroy === 'function' && !socket.destroyed) socket.destroy();
  } catch {
    // best effort
  }
}

function closeConnection(connection, sayGoodbye) {
  if (!sayGoodbye || connection.destroyed) {
    forceClose(connection);
    return;
  }
  try {
    connection.quit();
  } catch {
    forceClose(connection);
    return;
  }
  const timer = setTimeout(() => forceClose(connection), QUIT_WAIT_MS);
  timer.unref();
  connection.once('end', () => clearTimeout(timer));
}

// Error codes become part of the client-facing "smtp error: <code>" message, so
// keep them to identifier characters.
function errorCode(err) {
  const raw = err && err.code !== undefined && err.code !== null && err.code !== ''
    ? String(err.code)
    : err && err.responseCode
      ? String(err.responseCode)
      : 'ESEND';
  return raw.replace(/[^A-Za-z0-9_.-]/g, '').slice(0, 40) || 'ESEND';
}

// outcomeUnknown: the message data had started to flow and the failure carries
// no SMTP reply (network error, socket timeout, deadline), so the server may
// already have accepted the message.
function toSendError(err, phase) {
  const smtpCode = errorCode(err);
  const responseCode = err && Number.isInteger(err.responseCode) ? err.responseCode : undefined;
  const message = oneLine((err && err.message) || describeError(err) || 'send failed') || 'send failed';
  const out = new Error(`${smtpCode}${responseCode ? ' ' + responseCode : ''}: ${message}`);
  out.name = 'SmtpSendError';
  out.smtpCode = smtpCode;
  out.responseCode = responseCode;
  out.smtpResponse = oneLine(err && err.response);
  out.detail = out.message;
  out.phase = phase;
  out.outcomeUnknown = phase === 'data' && !responseCode;
  out.cause = err;
  return out;
}

function recipientsOf(list) {
  return Array.isArray(list) ? list.map((r) => String(r)) : [];
}

function rejectedErrorsOf(info) {
  if (!Array.isArray(info.rejectedErrors)) return [];
  return info.rejectedErrors.map((e) => ({
    recipient: e && e.recipient ? String(e.recipient) : '',
    response: oneLine(e && (e.response || e.message)),
    responseCode: e && Number.isInteger(e.responseCode) ? e.responseCode : undefined,
  }));
}

// mail: nodemailer message options (see send.js buildMail). Resolves with the
// SMTP result, including recipients the server refused while accepting others.
// deps.smtpConnectionFactory(options) may replace `new SMTPConnection(options)`.
async function sendMail(deps, { app, smtpPassword, mail }) {
  const { config } = deps;
  let phase = 'compose';
  let connection = null;
  let sent = false;
  try {
    const node = new MailComposer(mail).compile();
    // From the To/Cc/Bcc headers; Bcc never becomes a header of the built message.
    const envelope = node.getEnvelope();
    const messageId = node.messageId();
    const raw = await node.build();

    phase = 'dns';
    const started = performance.now();
    const deadlineMs = config.smtpSendDeadlineMs;
    const address = await resolveSmtpHost(app.smtpHost, Math.min(config.smtpTimeoutMs, deadlineMs));

    phase = 'connect';
    const options = buildConnectionOptions(app, config, address);
    connection = deps.smtpConnectionFactory ? deps.smtpConnectionFactory(options) : new SMTPConnection(options);
    const auth = app.smtpUsername ? { user: app.smtpUsername, pass: smtpPassword } : null;
    const info = await runSession(connection, {
      auth,
      envelope,
      raw,
      deadlineMs: Math.max(0, Math.round(deadlineMs - elapsedSince(started))),
    });
    sent = true;
    return {
      messageId,
      response: oneLine(info.response),
      accepted: recipientsOf(info.accepted),
      rejected: recipientsOf(info.rejected),
      rejectedErrors: rejectedErrorsOf(info),
    };
  } catch (err) {
    throw toSendError(err, err && err.smtpPhase ? err.smtpPhase : phase);
  } finally {
    if (connection) closeConnection(connection, sent);
  }
}

module.exports = { buildConnectionOptions, resolveSmtpHost, sendMail };
