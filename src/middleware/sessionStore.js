'use strict';

// express-session store on the `sessions` table, shared by every Node process.
// Rows are keyed by sha256(sid) so a leaked database dump (or someone with
// read-only database access) does not hand out live session cookies.
// `expires` is unix seconds; expired rows are ignored here and deleted by the
// cleanup job.
//
// destroy() leaves a tombstone (data NULL) instead of deleting the row, and
// set() never revives a tombstone. Otherwise a request that was already in
// flight when the admin signed out (or when login/regenerate replaced the sid)
// would save its copy of the session at the end and silently undo the
// sign-out. Sids are random and never reused, so a tombstone only ever blocks
// the sid it was written for. It outlives any in-flight request (at least the
// idle lifetime) and the cleanup job deletes it once it expires.

const session = require('express-session');
const { sha256Hex } = require('../lib/crypto');

// Sessions that never signed in (login form, CSRF token) are kept short so
// anonymous visitors cannot pile up long-lived rows.
const ANONYMOUS_MAX_SECONDS = 30 * 60;

function rowId(sid) {
  return sha256Hex(String(sid));
}

function parseData(text) {
  if (typeof text !== 'string') return null; // tombstone (destroyed session)
  try {
    const data = JSON.parse(text);
    return data && typeof data === 'object' && !Array.isArray(data) ? data : null;
  } catch {
    return null;
  }
}

class MySqlSessionStore extends session.Store {
  constructor(deps) {
    super();
    this.deps = deps;
  }

  nowSeconds() {
    return Math.floor(this.deps.clock.now().getTime() / 1000);
  }

  expiresFor(sess) {
    const now = this.nowSeconds();
    const cookieExpires = sess && sess.cookie ? sess.cookie.expires : null;
    const at = cookieExpires ? new Date(cookieExpires).getTime() : NaN;
    let expires = Number.isFinite(at) ? Math.floor(at / 1000) : now + this.deps.config.sessionIdleMinutes * 60;
    if (!sess || (!sess.adminId && !sess.pendingAdminId)) {
      expires = Math.min(expires, now + ANONYMOUS_MAX_SECONDS);
    }
    return Math.max(0, expires);
  }

  // Calls cb exactly once (cb may be undefined: express-session passes none for
  // a destroy() without callback). A throwing callback is logged rather than
  // becoming an unhandled rejection or a second callback.
  settle(promise, cb, map) {
    promise
      .then(
        (result) => {
          if (cb) cb(null, map ? map(result) : undefined);
        },
        (err) => {
          if (cb) cb(err);
        }
      )
      .catch((err) => this.deps.logger.error('session store callback failed', { err }));
  }

  get(sid, cb) {
    const nowSeconds = this.nowSeconds();
    this.settle(
      this.deps.db.query('SELECT data, expires FROM sessions WHERE session_id = ?', [rowId(sid)]),
      cb,
      (rows) => {
        const row = rows[0];
        if (!row || Number(row.expires) <= nowSeconds) return null;
        // A corrupt row counts as no session; the client simply gets a new one.
        return parseData(row.data);
      }
    );
  }

  set(sid, sess, cb) {
    let data;
    try {
      data = JSON.stringify(sess);
    } catch (err) {
      if (cb) cb(err);
      return;
    }
    const expires = this.expiresFor(sess);
    // A tombstoned row stays as it is; both assignments test the stored data,
    // so the result is the same whichever one the server evaluates first.
    this.settle(
      this.deps.db.query(
        `INSERT INTO sessions (session_id, expires, data) VALUES (?, ?, ?)
         ON DUPLICATE KEY UPDATE expires = IF(data IS NULL, expires, ?), data = IF(data IS NULL, NULL, ?)`,
        [rowId(sid), expires, data, expires, data]
      ),
      cb
    );
  }

  destroy(sid, cb) {
    const keepUntil = this.nowSeconds() + this.deps.config.sessionIdleMinutes * 60;
    this.settle(
      this.deps.db.query('UPDATE sessions SET data = NULL, expires = GREATEST(expires, ?) WHERE session_id = ?', [
        keepUntil,
        rowId(sid),
      ]),
      cb
    );
  }

  touch(sid, sess, cb) {
    this.settle(
      this.deps.db.query('UPDATE sessions SET expires = ? WHERE session_id = ? AND data IS NOT NULL', [
        this.expiresFor(sess),
        rowId(sid),
      ]),
      cb
    );
  }
}

module.exports = { MySqlSessionStore, ANONYMOUS_MAX_SECONDS };
