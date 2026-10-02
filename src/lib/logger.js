'use strict';

// Minimal logger. Everything goes to stderr because LiteSpeed's lsnode (what
// Namecheap runs) discards stdout unless LSNODE_CONSOLE_LOG is set; stderr ends
// up in the app's stderr.log. Set LOG_FILE to also append to a file you control.
//
// Rules: `msg` is a constant string; variable data goes in `meta` (JSON-escaped).
// Never log secrets, API keys, SMTP passwords or message bodies.

const fs = require('node:fs');
const path = require('node:path');

// Keep one entry per line so a hostile SMTP banner or header cannot forge entries.
const LINE_BREAKS = new RegExp('[\\r\\n' + String.fromCharCode(0x85, 0x2028, 0x2029) + ']+', 'g');

function oneLine(s) {
  return String(s).replace(LINE_BREAKS, ' | ');
}

// A readable one-line reason for any thrown value. Node reports a refused
// connection to "localhost" (tried on ::1 and 127.0.0.1) as an AggregateError
// whose message is empty, so fall back to the inner errors and the code.
function describeError(err) {
  if (err === null || err === undefined) return 'unknown error';
  if (typeof err !== 'object') return String(err);
  if (err.message) return err.code && !String(err.message).includes(err.code) ? `${err.code}: ${err.message}` : err.message;
  if (Array.isArray(err.errors) && err.errors.length) {
    const inner = err.errors.map((e) => describeError(e)).join('; ');
    return err.code ? `${err.code}: ${inner}` : inner;
  }
  return err.code || err.name || 'unknown error';
}

function serializeError(err) {
  const out = { message: describeError(err) };
  if (err.code) out.code = err.code;
  if (err.stack) out.stack = err.stack;
  return out;
}

function fmt(level, msg, meta) {
  let line = `${new Date().toISOString()} ${level} ${oneLine(msg)}`;
  if (meta !== undefined) {
    if (meta instanceof Error) line += ` ${oneLine(meta.stack || describeError(meta))}`;
    else {
      try {
        // JSON escapes the newlines inside stacks, so entries stay on one line.
        line += ` ${JSON.stringify(meta, (k, v) => (v instanceof Error ? serializeError(v) : v))}`;
      } catch {
        line += ' [unserializable meta]';
      }
    }
  }
  return line;
}

function createLogger({ silent = false, file } = {}) {
  let stream = null;
  function fileProblem(err) {
    stream = null;
    if (!silent) {
      process.stderr.write(fmt('WARN', 'LOG_FILE cannot be written; logging to stderr only', { path: file, code: err && err.code }) + '\n');
    }
  }
  if (file && !silent) {
    try {
      fs.mkdirSync(path.dirname(file), { recursive: true });
      stream = fs.createWriteStream(file, { flags: 'a' });
      stream.on('error', fileProblem);
    } catch (err) {
      fileProblem(err);
    }
  }
  function write(level, msg, meta) {
    if (silent) return;
    const line = fmt(level, msg, meta) + '\n';
    process.stderr.write(line);
    if (stream) stream.write(line);
  }
  return {
    info: (msg, meta) => write('INFO', msg, meta),
    warn: (msg, meta) => write('WARN', msg, meta),
    error: (msg, meta) => write('ERROR', msg, meta),
  };
}

module.exports = { createLogger, describeError };
