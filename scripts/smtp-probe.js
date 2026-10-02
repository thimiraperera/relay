'use strict';

// Checks that this machine can reach an SMTP server, before Relay depends on it
// (README, "Step 0"). Run it on the hosting account itself:
//
//   node scripts/smtp-probe.js <host> <port> [--tls] [--no-ehlo] [--all]
//
// Port 465 or --tls: implicit TLS. Any other port: plain TCP. After the greeting
// the probe sends EHLO, reports whether STARTTLS and AUTH are offered and, when
// STARTTLS is offered, upgrades and checks the certificate the way Relay does
// (verified, TLS 1.2 or newer). It never logs in and never sends a message.
//
// The host name is resolved the way Relay resolves it (src/services/mailer.js
// resolveSmtpHost), and by default only the address Relay would connect to is
// tested. Every resolved address is listed; --all tests each one in turn.
//
// Exit code: 0 = reached an SMTP server, 1 = a problem was found, 2 = usage error.

const dns = require('node:dns');
const net = require('node:net');
const os = require('node:os');
const tls = require('node:tls');

const TIMEOUT_MS = 15000;
const DNS_TRY_TIMEOUT_MS = 5000;
const QUIT_WAIT_MS = 2000;
const MAX_REPLY_BYTES = 64 * 1024;
const PREVIEW_CHARS = 160;
const SECONDS = TIMEOUT_MS / 1000;
const LIST_WIDTH = 96;

// The login mechanisms Relay can use with a username and password, in the order
// nodemailer prefers them. When the server names none of them, nodemailer still
// tries PLAIN.
const RELAY_AUTH = Object.freeze(['PLAIN', 'LOGIN', 'CRAM-MD5']);

const USAGE = `Usage: node scripts/smtp-probe.js <host> <port> [--tls] [--no-ehlo] [--all]

Checks that this machine can open an SMTP connection to <host>:<port>.
Nothing is logged in to and no message is sent.
  --tls       implicit TLS (always used for port 465); other ports start in plain TCP
              and upgrade with STARTTLS when the server offers it
  --no-ehlo   only read the greeting; do not send EHLO or try STARTTLS
  --all       test every address the host name resolves to, one after another
              (by default only the address Relay would connect to is tested:
              the first IPv4 address, else the first IPv6 address)
Exit code: 0 reachable SMTP server, 1 problem found, 2 usage error.

Examples:
  node scripts/smtp-probe.js smtp.office365.com 587
  node scripts/smtp-probe.js mail.example.com 465
  node scripts/smtp-probe.js smtp.office365.com 587 --all
`;

const HOST_NAME = /^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;

class UsageError extends Error {}

// A failed step, printed as "<STEP> FAIL <message>" followed by the hints.
class ProbeError extends Error {
  constructor(step, message, hints = []) {
    super(message);
    this.step = step;
    this.hints = hints;
  }
}

function report(step, status, text) {
  process.stdout.write(`${step.padEnd(9)}${status.padEnd(6)}${text}\n`);
}

function hint(text) {
  process.stdout.write(`${' '.repeat(15)}${text}\n`);
}

// "IPv4: a, b, c" wrapped onto indented continuation lines.
function hintList(label, items) {
  const lead = `${label}: `;
  let line = lead;
  for (let i = 0; i < items.length; i++) {
    const piece = items[i] + (i < items.length - 1 ? ',' : '');
    if (line.length > lead.length && line.length + 1 + piece.length > LIST_WIDTH) {
      hint(line);
      line = ' '.repeat(lead.length) + piece;
    } else {
      line += (line.length > lead.length ? ' ' : '') + piece;
    }
  }
  hint(line);
}

function plural(n, one, many) {
  return `${n} ${n === 1 ? one : many}`;
}

// Printable form of untrusted bytes (decoded as latin1): a reply may be binary
// (another protocol on that port) or contain control characters.
function preview(text, max = PREVIEW_CHARS) {
  let out = '';
  for (const ch of text) {
    const c = ch.charCodeAt(0);
    if (c >= 0x20 && c < 0x7f) out += ch;
    else if (c === 0x0d) out += '\\r';
    else if (c === 0x0a) out += '\\n';
    else out += '\\x' + c.toString(16).padStart(2, '0');
    if (out.length >= max) return out.slice(0, max) + '...';
  }
  return out;
}

function parseArgs(argv) {
  const out = { host: null, port: null, tls: false, ehlo: true, all: false, help: false };
  const positional = [];
  for (const a of argv) {
    if (a === '--help' || a === '-h') out.help = true;
    else if (a === '--tls') out.tls = true;
    else if (a === '--no-ehlo') out.ehlo = false;
    else if (a === '--all') out.all = true;
    else if (a.startsWith('-')) throw new UsageError(`unknown option ${a}`);
    else positional.push(a);
  }
  if (out.help) return out;
  if (positional.length !== 2) {
    throw new UsageError('expected a host and a port, e.g. smtp.office365.com 587 (separated by a space)');
  }

  let host = positional[0].trim();
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
  if (host.endsWith('.') && !net.isIP(host)) host = host.slice(0, -1);
  if (!net.isIP(host) && !HOST_NAME.test(host)) {
    throw new UsageError(`"${positional[0]}" is not a host name or IP address`);
  }
  const portText = positional[1].trim();
  const port = Number(portText);
  if (!/^\d{1,5}$/.test(portText) || port < 1 || port > 65535) {
    throw new UsageError(`"${positional[1]}" is not a port number (1-65535)`);
  }

  out.host = host;
  out.port = port;
  if (port === 465) out.tls = true;
  return out;
}

function isLoopback(address) {
  return address === '::1' || address.startsWith('127.') || address.startsWith('::ffff:127.');
}

// The EHLO name nodemailer (and therefore Relay) uses: the machine's host name
// when it looks fully qualified, else an address literal.
function ehloName() {
  let name = '';
  try {
    name = os.hostname() || '';
  } catch {
    name = '';
  }
  if (!name || !name.includes('.')) return '[127.0.0.1]';
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(name)) return `[${name}]`;
  return name;
}

function withTimeout(promise, ms, onTimeout) {
  let timer = null;
  const timeout = new Promise((resolve, reject) => {
    timer = setTimeout(() => reject(onTimeout()), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

function settle(promise) {
  return promise.then(
    (value) => ({ value }),
    (error) => ({ error })
  );
}

function dnsProblem(err, host) {
  const code = (err && err.code) || 'unknown error';
  if (code === 'ENOTFOUND' || code === 'ENODATA' || code === 'NXDOMAIN') {
    return new ProbeError('DNS', `${host} does not resolve (${code})`, [
      'The host name does not exist or has no address. Check it for typos; use the SMTP host',
      'name your mail provider documents (e.g. smtp.office365.com, smtp.gmail.com, mail.<domain>).',
      'Relay would fail with EDNS for this mailbox.',
    ]);
  }
  return new ProbeError('DNS', `could not resolve ${host} (${code})`, [
    'The DNS server did not answer properly. Try again; if it keeps failing, ask the host',
    'whether outbound DNS works from this account. Relay would fail with EDNS.',
  ]);
}

function unique(list) {
  return Array.from(new Set(list));
}

// Resolves like Relay (src/services/mailer.js resolveSmtpHost): an IP literal as
// is; otherwise A and AAAA records in parallel through the DNS resolver, and only
// when neither returns an address the system resolver (which also reads the
// hosts file). Relay then makes exactly one connect attempt per send, to the
// first IPv4 address of the answer, else the first IPv6 address.
// → { v4, v6, chosen }
async function resolveHost(host) {
  if (net.isIP(host)) {
    return { v4: net.isIPv4(host) ? [host] : [], v6: net.isIPv6(host) ? [host] : [], chosen: host };
  }

  const resolver = new dns.promises.Resolver({ timeout: DNS_TRY_TIMEOUT_MS, tries: 2 });
  const timedOut = () => new ProbeError('DNS', `TIMEOUT after ${SECONDS} s resolving ${host}`, [
    'The DNS server did not answer. Relay would fail with EDNS.',
  ]);
  try {
    const [r4, r6] = await withTimeout(
      Promise.all([settle(resolver.resolve4(host)), settle(resolver.resolve6(host))]),
      TIMEOUT_MS,
      timedOut
    );
    let v4 = r4.value || [];
    let v6 = r6.value || [];
    if (!v4.length && !v6.length) {
      let found;
      try {
        found = await withTimeout(dns.promises.lookup(host, { all: true }), TIMEOUT_MS, timedOut);
      } catch (err) {
        if (err instanceof ProbeError) throw err;
        throw dnsProblem(err, host);
      }
      v4 = found.filter((a) => a.family === 4).map((a) => a.address);
      v6 = found.filter((a) => a.family === 6).map((a) => a.address);
    }
    v4 = unique(v4);
    v6 = unique(v6);
    if (!v4.length && !v6.length) throw dnsProblem({ code: 'ENODATA' }, host);
    return { v4, v6, chosen: v4.length ? v4[0] : v6[0] };
  } finally {
    resolver.cancel();
  }
}

// ctx.hasV4: the host name also has IPv4 addresses (Relay then never uses IPv6).
function connectProblem(err, target, address, ctx = {}) {
  const code = (err && err.code) || 'error';
  if (code === 'ECONNREFUSED') {
    return new ProbeError('CONNECT', `ECONNREFUSED: ${target} refused the connection`, [
      'Nothing is listening on that port, or a firewall rejected the connection.',
      'Check the port number (465 = SSL/TLS, 587 = STARTTLS, 25 = server-to-server).',
      'If the port is right, the hosting provider may be rejecting outbound SMTP: see README "Step 0".',
    ]);
  }
  if (code === 'EPERM' || code === 'EACCES') {
    return new ProbeError('CONNECT', `BLOCKED (${code}): this server's firewall did not allow the connection to ${target}`, [
      'Outbound SMTP is blocked for this account (for example cPanel "SMTP Restrictions").',
      'Ask the hosting provider to allow it: see README "Step 0" for the ticket wording.',
    ]);
  }
  if (code === 'ETIMEDOUT') return connectTimeout(target);
  if (code === 'ENETUNREACH' || code === 'EHOSTUNREACH' || code === 'EADDRNOTAVAIL') {
    let advice = 'The network path to that address is unavailable; check the host name.';
    if (net.isIPv6(address)) {
      advice = ctx.hasV4
        ? 'This server may have no IPv6 connectivity. Relay does not use this address, because the name also has IPv4 addresses.'
        : 'This server may have no IPv6 connectivity, and Relay would fail the same way. Use a host name that has an IPv4 address.';
    }
    return new ProbeError('CONNECT', `${code}: no route to ${target}`, [advice]);
  }
  return new ProbeError('CONNECT', `${code}: ${(err && err.message) || 'connection failed'}`);
}

function connectTimeout(target) {
  return new ProbeError('CONNECT', `TIMEOUT after ${SECONDS} s: no answer from ${target}`, [
    'This is probably blocked by the hosting provider\'s outbound firewall (or the server is down).',
    'Relay would fail with ETIMEDOUT for this mailbox. See README "Step 0" for the',
    'support ticket wording.',
  ]);
}

function connectTcp(address, port, ctx) {
  const target = `${net.isIPv6(address) ? `[${address}]` : address}:${port}`;
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const socket = net.connect({ host: address, port });
    const timer = setTimeout(() => {
      socket.destroy();
      reject(connectTimeout(target));
    }, TIMEOUT_MS);
    function onError(err) {
      clearTimeout(timer);
      socket.destroy();
      reject(connectProblem(err, target, address, ctx));
    }
    socket.once('error', onError);
    socket.once('connect', () => {
      clearTimeout(timer);
      socket.removeListener('error', onError);
      // From here the reply reader or the TLS socket wrapping this one reports
      // errors; this keeps a late error on the raw socket from crashing the probe.
      socket.on('error', () => {});
      resolve({ socket, target, ms: Date.now() - started });
    });
  });
}

function tlsProblem(err, { implicit }) {
  const code = (err && err.code) || '';
  const message = (err && err.message) || 'TLS handshake failed';
  if (/wrong version number|packet length too long|http request|unknown protocol/i.test(message)) {
    return new ProbeError('TLS', `the server did not answer with TLS (${code || 'EPROTO'})`, [
      implicit
        ? 'This port probably expects plain SMTP followed by STARTTLS: run again without --tls and'
        : 'The server announced STARTTLS but did not start TLS.',
      implicit ? 'use encryption "STARTTLS" in the app settings.' : '',
    ].filter(Boolean));
  }
  if (/unsupported protocol|protocol version|no protocols available/i.test(message)) {
    return new ProbeError('TLS', `the server only offers TLS older than 1.2 (${code || 'EPROTO'})`, [
      'Relay requires TLS 1.2 or newer. Ask the mail provider to enable it, or use another server.',
    ]);
  }
  if (code === 'ECONNRESET' || /socket hang up|disconnected/i.test(message)) {
    return new ProbeError('TLS', 'the connection was closed during the TLS handshake', [
      implicit ? 'If this port expects STARTTLS (usually 587 or 25), run again without --tls.' : '',
      'A firewall in between may also be cutting the connection.',
    ].filter(Boolean));
  }
  return new ProbeError('TLS', `${code ? code + ': ' : ''}${message}`);
}

// Starts TLS on a connected socket. Certificate problems do not abort the
// handshake here (rejectUnauthorized false) so they can be reported in detail;
// Relay itself rejects them. As in Relay, the certificate is checked against the
// host name (SNI), not against the address connected to.
function startTls(socket, host, { implicit }) {
  return new Promise((resolve, reject) => {
    const tlsSocket = tls.connect({
      socket,
      host,
      servername: net.isIP(host) ? undefined : host,
      rejectUnauthorized: false,
      minVersion: 'TLSv1.2',
    });
    const timer = setTimeout(() => {
      tlsSocket.destroy();
      reject(
        new ProbeError('TLS', `TIMEOUT after ${SECONDS} s during the TLS handshake`, [
          implicit ? 'If this port expects STARTTLS (usually 587 or 25), run again without --tls.' : '',
          'A firewall in between may also be holding the connection.',
        ].filter(Boolean))
      );
    }, TIMEOUT_MS);
    function onError(err) {
      clearTimeout(timer);
      tlsSocket.destroy();
      reject(tlsProblem(err, { implicit }));
    }
    tlsSocket.once('error', onError);
    tlsSocket.once('secureConnect', () => {
      clearTimeout(timer);
      tlsSocket.removeListener('error', onError);
      resolve(tlsSocket);
    });
  });
}

const CERT_PROBLEMS = Object.freeze({
  ERR_TLS_CERT_ALTNAME_INVALID: 'the certificate is not issued for this host name',
  DEPTH_ZERO_SELF_SIGNED_CERT: 'the certificate is self-signed',
  SELF_SIGNED_CERT_IN_CHAIN: 'the certificate chain contains a self-signed certificate',
  CERT_HAS_EXPIRED: 'the certificate has expired',
  CERT_NOT_YET_VALID: 'the certificate is not valid yet',
  UNABLE_TO_VERIFY_LEAF_SIGNATURE: 'the certificate chain is incomplete or from an unknown authority',
  UNABLE_TO_GET_ISSUER_CERT_LOCALLY: 'the certificate is from an unknown authority (or the chain is incomplete)',
  UNABLE_TO_GET_ISSUER_CERT: 'the certificate is from an unknown authority (or the chain is incomplete)',
});

function certificateNames(cert) {
  const names = [];
  if (typeof cert.subjectaltname === 'string') {
    for (const part of cert.subjectaltname.split(',')) {
      const m = /^\s*(?:DNS|IP Address):(.+)$/.exec(part);
      if (m) names.push(m[1].trim());
    }
  }
  if (!names.length && cert.subject && cert.subject.CN) names.push(String(cert.subject.CN));
  return names;
}

// Exact match or a one-label wildcard ("*.example.com" covers "a.example.com").
function nameCovers(name, host) {
  const n = name.toLowerCase();
  const h = host.toLowerCase();
  if (n === h) return true;
  if (!n.startsWith('*.')) return false;
  const dot = h.indexOf('.');
  return dot > 0 && h.slice(dot + 1) === n.slice(2);
}

function certificateSummary(cert, host) {
  // The name that covers the probed host first: big providers list dozens.
  const names = certificateNames(cert).sort((a, b) => Number(nameCovers(b, host)) - Number(nameCovers(a, host)));
  const shown = names.slice(0, 4).join(', ') + (names.length > 4 ? ` (+${names.length - 4} more)` : '');
  const issuer = cert.issuer ? cert.issuer.O || cert.issuer.CN || '' : '';
  const until = cert.valid_to ? new Date(cert.valid_to) : null;
  const parts = [`names: ${preview(shown || '(none)')}`];
  if (issuer) parts.push(`issuer: ${preview(String(issuer))}`);
  if (until && !Number.isNaN(until.getTime())) parts.push(`valid until ${until.toISOString().slice(0, 10)}`);
  return parts.join('; ');
}

// → certificate summary; throws when Relay would refuse the certificate.
function checkCertificate(tlsSocket, host) {
  const cert = tlsSocket.getPeerCertificate() || {};
  const summary = cert && Object.keys(cert).length ? certificateSummary(cert, host) : 'no certificate details';
  if (tlsSocket.authorized) return summary;
  const code = String(tlsSocket.authorizationError || 'UNKNOWN');
  const reason = CERT_PROBLEMS[code] || 'the certificate could not be verified';
  throw new ProbeError('TLS', `certificate not accepted: ${reason} (${code})`, [
    `Certificate ${summary}.`,
    'Relay always verifies certificates, so sending would fail with ESOCKET.',
    code === 'ERR_TLS_CERT_ALTNAME_INVALID'
      ? `Use a host name listed on the certificate instead of ${host} (on cPanel hosting often the server name).`
      : 'Ask the mail provider to install a valid certificate, or use a host name that has one.',
  ]);
}

// Reads SMTP replies from a socket: "250-..." continuation lines end with a
// "250 ..." line. The first bytes are checked so that another protocol on the
// port (a database, HTTP, a TLS-only port) is reported instead of awaited.
function createReplyReader(socket) {
  let buffer = '';
  let pending = null;
  let failure = null;

  function settlePending(fn) {
    if (!pending) return;
    const p = pending;
    pending = null;
    clearTimeout(p.timer);
    fn(p);
  }

  function fail(err) {
    if (!failure) failure = err;
    settlePending((p) => p.reject(p.wrap(failure)));
  }

  function notSmtp(step, sample) {
    return new ProbeError(step, `the port answered, but not with SMTP: "${preview(sample)}"`, [
      'An SMTP server greets with "220 ...". This is another service, or the wrong port.',
    ]);
  }

  function check() {
    if (!pending) return;
    if (buffer.length >= 4 && !/^\d{3}[ \-\r\n]/.test(buffer)) {
      settlePending((p) => p.reject(notSmtp(p.step, buffer)));
      return;
    }
    const lines = [];
    let rest = buffer;
    let idx;
    while ((idx = rest.indexOf('\n')) !== -1) {
      const line = rest.slice(0, idx).replace(/\r$/, '');
      rest = rest.slice(idx + 1);
      if (!/^\d{3}(?:[ -]|$)/.test(line)) {
        settlePending((p) => p.reject(notSmtp(p.step, line)));
        return;
      }
      lines.push(line);
      if (line.length === 3 || line[3] === ' ') {
        buffer = rest;
        settlePending((p) => p.resolve({ code: Number(line.slice(0, 3)), lines }));
        return;
      }
    }
  }

  function onData(chunk) {
    buffer += chunk.toString('latin1');
    if (buffer.length > MAX_REPLY_BYTES) {
      fail(new Error('reply too long'));
      return;
    }
    check();
  }
  function onError(err) {
    fail(err);
  }
  function onClose() {
    fail(Object.assign(new Error('connection closed'), { code: 'ECLOSED' }));
  }

  socket.on('data', onData);
  socket.on('error', onError);
  socket.on('close', onClose);

  function read(step, { timeoutHints = [] } = {}) {
    return new Promise((resolve, reject) => {
      const wrap = (err) => {
        if (err instanceof ProbeError) return err;
        if (err.code === 'ECLOSED') {
          return new ProbeError(step, 'the server closed the connection without replying', buffer
            ? [`It sent: "${preview(buffer)}"`]
            : ['Some servers do this when they refuse this client (blocked IP or too many connections).']);
        }
        if (err.code === 'ECONNRESET') return new ProbeError(step, 'the connection was reset by the server or a firewall');
        return new ProbeError(step, `${err.code ? err.code + ': ' : ''}${err.message}`);
      };
      if (failure) {
        reject(wrap(failure));
        return;
      }
      const timer = setTimeout(() => {
        settlePending((p) =>
          p.reject(
            buffer
              ? notSmtp(step, buffer)
              : new ProbeError(step, `TIMEOUT after ${SECONDS} s waiting for the server's reply`, timeoutHints)
          )
        );
      }, TIMEOUT_MS);
      pending = { step, resolve, reject, wrap, timer };
      check();
    });
  }

  function detach() {
    socket.removeListener('data', onData);
    socket.removeListener('error', onError);
    socket.removeListener('close', onClose);
    if (pending) settlePending((p) => p.reject(new ProbeError(p.step, 'reader detached')));
  }

  return { read, detach };
}

function replyText(reply) {
  return preview(reply.lines.map((l) => l.slice(4)).join(' | ').trim() || String(reply.code));
}

// Like nodemailer: every AUTH line counts ("AUTH LOGIN PLAIN" and the old
// "AUTH=LOGIN" form), mechanisms are split on spaces and "=". auth is null when
// no AUTH line was sent, else the list of mechanisms (possibly empty).
function parseEhlo(reply) {
  const extensions = reply.lines.slice(1).map((l) => l.slice(4).trim());
  let starttls = false;
  let auth = null;
  let size = null;
  for (const ext of extensions) {
    if (/^STARTTLS$/i.test(ext)) starttls = true;
    const a = /^AUTH(?:[\s=](.*))?$/i.exec(ext);
    if (a) {
      if (auth === null) auth = [];
      for (const m of (a[1] || '').split(/[\s=]+/)) {
        const mech = m.trim().toUpperCase();
        if (mech && !auth.includes(mech)) auth.push(mech);
      }
    }
    const s = /^SIZE(?:\s+(\d+))?$/i.exec(ext);
    if (s && s[1]) size = Number(s[1]);
  }
  return { starttls, auth, size };
}

// The offered mechanisms Relay can log in with, most preferred first.
function usableAuth(mechanisms) {
  return RELAY_AUTH.filter((m) => (mechanisms || []).includes(m));
}

async function command(socket, reader, step, line) {
  socket.write(line + '\r\n');
  return reader.read(step);
}

async function sendEhlo(socket, reader, name) {
  const reply = await command(socket, reader, 'EHLO', `EHLO ${name}`);
  if (reply.code !== 250) {
    throw new ProbeError('EHLO', `the server refused EHLO: ${reply.code} ${replyText(reply)}`, [
      'Relay would not be able to use this server. A 5xx reply often means this hosting',
      'server\'s IP address is blocked by the mail provider.',
    ]);
  }
  return parseEhlo(reply);
}

function describeSize(bytes) {
  if (!bytes) return null;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function authOffer(auth) {
  return auth.length ? `AUTH ${auth.join(' ')}` : 'AUTH';
}

async function quit(socket, reader) {
  try {
    socket.write('QUIT\r\n');
    await withTimeout(reader.read('QUIT'), QUIT_WAIT_MS, () => new Error('no reply to QUIT'));
  } catch {
    // The verdict is already known; a missing 221 changes nothing.
  }
}

const ADVICE = Object.freeze({
  ssl: 'use encryption "SSL/TLS" with this port in the app settings.',
  starttls: 'use encryption "STARTTLS" with this port in the app settings.',
  none: 'only encryption "none" would work on this port (not recommended).',
});

// The SMTP dialogue with one address: TCP (and TLS), greeting, EHLO, STARTTLS and
// EHLO again, AUTH, SIZE, QUIT. Prints one line per step.
// → { warnings, encryption }; throws a ProbeError at the first failed step.
async function probeAddress(opts, address, ctx) {
  const { host, port } = opts;
  const sockets = [];
  const warnings = [];
  const warn = (step, text) => {
    warnings.push(text);
    report(step, 'WARN', text);
  };
  let encryption = opts.tls ? 'ssl' : 'none';

  try {
    const { socket: tcp, target, ms } = await connectTcp(address, port, ctx);
    sockets.push(tcp);
    report('CONNECT', 'OK', `TCP connection to ${target} established in ${ms} ms`);

    let socket = tcp;
    if (opts.tls) {
      socket = await startTls(tcp, host, { implicit: true });
      sockets.push(socket);
      report('TLS', 'OK', `${socket.getProtocol()}; certificate ${checkCertificate(socket, host)}`);
    }

    let reader = createReplyReader(socket);
    const greeting = await reader.read('GREETING', {
      timeoutHints: [
        'Connected, but no greeting arrived. A firewall or proxy on the way may be accepting the',
        'connection and holding it (common for port 25, which many networks block this way).',
        ...(opts.tls ? [] : ['If this port uses implicit TLS (SSL/TLS, usually 465), run again with --tls.']),
      ],
    });
    if (greeting.code !== 220) {
      throw new ProbeError('GREETING', `the server refused the session: ${greeting.code} ${replyText(greeting)}`, [
        'The port is reachable, but the server will not talk to this machine. It may be blocking',
        'this hosting server\'s IP address (blocklist) or be overloaded; try again later or ask the provider.',
      ]);
    }
    report('GREETING', 'OK', `${greeting.code} ${replyText(greeting)}`);
    const greetingHost = (greeting.lines[0].slice(4).trim().split(/\s+/)[0] || '').toLowerCase();
    if (!isLoopback(address) && greetingHost && greetingHost === os.hostname().toLowerCase()) {
      warn('GREETING', 'The greeting comes from this machine itself: outbound SMTP is being redirected to the host\'s own mail server.');
    }

    if (!opts.ehlo) {
      await quit(socket, reader);
      return { warnings, encryption: null };
    }

    const name = ehloName();
    let ehlo = await sendEhlo(socket, reader, name);
    const offers = [ehlo.starttls ? 'STARTTLS' : null, ehlo.auth ? authOffer(ehlo.auth) : null]
      .filter(Boolean)
      .join(', ');
    report('EHLO', 'OK', `as ${name}; offers: ${offers || 'neither STARTTLS nor AUTH'}`);

    if (!opts.tls) {
      if (ehlo.starttls) {
        const reply = await command(socket, reader, 'STARTTLS', 'STARTTLS');
        if (reply.code !== 220) {
          throw new ProbeError('STARTTLS', `the server refused STARTTLS: ${reply.code} ${replyText(reply)}`);
        }
        reader.detach();
        socket = await startTls(socket, host, { implicit: false });
        sockets.push(socket);
        reader = createReplyReader(socket);
        report('STARTTLS', 'OK', `${socket.getProtocol()}; certificate ${checkCertificate(socket, host)}`);
        encryption = 'starttls';
        ehlo = await sendEhlo(socket, reader, name);
        report('EHLO', 'OK', `after STARTTLS; offers: ${ehlo.auth ? authOffer(ehlo.auth) : 'no AUTH'}`);
      } else {
        warn('STARTTLS', 'STARTTLS is not offered: only encryption "none" would work, which sends the password and messages in clear text.');
      }
    }

    if (ehlo.auth) {
      const usable = usableAuth(ehlo.auth);
      if (usable.length) {
        report('AUTH', 'OK', `username/password login offered (${usable.join(', ')}); Relay would use ${usable[0]}`);
      } else if (ehlo.auth.length) {
        warn('AUTH', `AUTH is offered only as ${ehlo.auth.join(' ')}; Relay logs in with PLAIN, LOGIN or CRAM-MD5 (it tries PLAIN when none of them is offered), so a username/password login will probably fail.`);
      } else {
        warn('AUTH', 'AUTH is offered without naming a mechanism; Relay would try PLAIN, which may fail.');
      }
    } else {
      report('AUTH', 'INFO', 'no login offered: leave the SMTP username empty if this server accepts mail without one.');
    }
    if (ehlo.size) report('SIZE', 'INFO', `the server accepts messages up to ${describeSize(ehlo.size)} (after MIME encoding)`);

    await quit(socket, reader);
    return { warnings, encryption };
  } finally {
    // Outermost first: destroying a raw socket while a TLS socket still wraps it
    // crashes Node 24 on Windows (segmentation fault).
    for (const s of sockets.reverse()) s.destroy();
  }
}

function printFailure(err) {
  report(err.step, 'FAIL', err.message);
  for (const h of err.hints) hint(h);
}

function resultLine(status, text) {
  process.stdout.write('\n');
  report('RESULT', status, text);
}

function reachableText(endpoint, opts, encryption, scope = '') {
  if (!opts.ehlo) return `${endpoint} is reachable from this machine${scope} and answers as an SMTP server.`;
  return `${endpoint} is reachable from this machine${scope}; ${ADVICE[encryption]}`;
}

// Default mode: the one address Relay would connect to.
async function probeOne(opts, resolved, endpoint) {
  const { v4, v6, chosen } = resolved;
  try {
    const { warnings, encryption } = await probeAddress(opts, chosen, { hasV4: v4.length > 0 });
    resultLine(warnings.length ? 'WARN' : 'OK', reachableText(endpoint, opts, encryption));
    const candidates = v4.length ? v4 : v6;
    if (candidates.length > 1) {
      const family = v4.length ? 'IPv4' : 'IPv6';
      hint(`Only ${chosen} was tested. Relay connects to the first ${family} address of each DNS answer, and that`);
      hint(`can change between lookups: run again with --all to test all ${candidates.length} ${family} addresses.`);
    }
    return 0;
  } catch (err) {
    if (!(err instanceof ProbeError)) throw err;
    printFailure(err);
    resultLine('FAIL', `${endpoint} cannot be used from this machine (see above).`);
    return 1;
  }
}

// --all: every resolved address in turn, IPv4 first. Relay only uses IPv6 when
// the name has no IPv4 address, so IPv6 failures then do not change the verdict.
async function probeAll(opts, resolved, endpoint) {
  const { v4, v6 } = resolved;
  const list = v4.map((address) => ({ address, family: 4 })).concat(v6.map((address) => ({ address, family: 6 })));
  const results = [];
  for (let i = 0; i < list.length; i++) {
    const { address, family } = list[i];
    const relayUses = family === 4 || !v4.length;
    const note = relayUses ? '' : '; not used by Relay while the name has IPv4 addresses';
    process.stdout.write(`\n[${i + 1}/${list.length}] ${address} (IPv${family}${note})\n`);
    try {
      const r = await probeAddress(opts, address, { hasV4: v4.length > 0 });
      results.push({ address, relayUses, ok: true, warnings: r.warnings, encryption: r.encryption });
    } catch (err) {
      if (!(err instanceof ProbeError)) throw err;
      printFailure(err);
      results.push({ address, relayUses, ok: false, failure: `${err.step} ${err.message}` });
    }
  }

  const used = results.filter((r) => r.relayUses);
  const unused = results.filter((r) => !r.relayUses);
  const usedFailed = used.filter((r) => !r.ok);
  const family = v4.length ? 'IPv4' : 'IPv6';
  process.stdout.write('\n');
  report('SUMMARY', usedFailed.length ? 'FAIL' : 'OK',
    `${used.length - usedFailed.length} of ${plural(used.length, `${family} address`, `${family} addresses`)} passed`);
  for (const r of usedFailed) hint(`${r.address}: ${r.failure}`);
  if (unused.length) {
    const unusedFailed = unused.filter((r) => !r.ok);
    report('SUMMARY', 'INFO',
      `${unused.length - unusedFailed.length} of ${plural(unused.length, 'IPv6 address', 'IPv6 addresses')} passed; ` +
        `Relay does not use ${unused.length === 1 ? 'it' : 'them'} while the name has IPv4 addresses`);
    for (const r of unusedFailed) hint(`${r.address}: ${r.failure}`);
  }

  if (usedFailed.length) {
    resultLine('FAIL', `${endpoint}: ${usedFailed.length} of ${used.length} ${family} addresses failed (see above).`);
    hint('Relay connects to the first address of each DNS answer, so sends fail whenever one of these comes first.');
    return 1;
  }
  const warnings = unique([].concat(...used.map((r) => r.warnings)));
  const encryptions = unique(used.map((r) => r.encryption));
  if (opts.ehlo && encryptions.length > 1) {
    resultLine('WARN', `${endpoint} is reachable on every address Relay may use, but STARTTLS is not offered on all of them (see above).`);
    return 0;
  }
  const scope = used.length > 1 ? ` on all ${used.length} ${family} addresses` : '';
  resultLine(warnings.length ? 'WARN' : 'OK', reachableText(endpoint, opts, encryptions[0], scope));
  return 0;
}

async function probe(opts) {
  const { host, port } = opts;
  const endpoint = net.isIPv6(host) ? `[${host}]:${port}` : `${host}:${port}`;
  const mode = opts.tls ? 'implicit TLS' : opts.ehlo ? 'plain TCP, then STARTTLS if offered' : 'plain TCP';
  process.stdout.write(`SMTP probe: ${host} port ${port} (${mode}), ${SECONDS} s timeout per step\n`);
  process.stdout.write(`Running on: ${os.hostname()}\n\n`);

  let resolved;
  try {
    resolved = await resolveHost(host);
  } catch (err) {
    if (!(err instanceof ProbeError)) throw err;
    printFailure(err);
    resultLine('FAIL', `${endpoint} cannot be used from this machine (see above).`);
    return 1;
  }

  const { v4, v6, chosen } = resolved;
  if (!net.isIP(host)) {
    let note = '';
    if (!v4.length) note = ' (no IPv4 address; Relay connects to the first IPv6 address)';
    else if (v4.length > 1) note = ` (first of ${v4.length} IPv4 addresses; Relay connects to this one)`;
    else if (v6.length) note = ' (Relay connects to the IPv4 address)';
    report('DNS', 'OK', `${host} -> ${chosen}${note}`);
    if (v4.length + v6.length > 1) {
      if (v4.length) hintList('IPv4', v4);
      if (v6.length) hintList('IPv6', v6);
    }
  }

  return opts.all ? probeAll(opts, resolved, endpoint) : probeOne(opts, resolved, endpoint);
}

async function main(argv) {
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (err) {
    if (!(err instanceof UsageError)) throw err;
    process.stderr.write(`smtp-probe: ${err.message}\n\n${USAGE}`);
    return 2;
  }
  if (opts.help) {
    process.stdout.write(USAGE);
    return 0;
  }
  return probe(opts);
}

if (require.main === module) {
  main(process.argv.slice(2)).then(
    (code) => {
      process.exitCode = code;
    },
    (err) => {
      process.stderr.write(`smtp-probe: unexpected error: ${err && err.stack ? err.stack : err}\n`);
      process.exitCode = 1;
    }
  );
}

// For tests; running the file is the normal use.
module.exports = { parseArgs, resolveHost, parseEhlo, usableAuth, probe, main, RELAY_AUTH };
