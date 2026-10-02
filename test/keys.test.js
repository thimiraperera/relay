'use strict';

// API key lifecycle: create, regenerate with grace periods (none / 1 hour /
// 24 hours), revoke, and how keys are stored (hash for normal keys, encrypted
// for legacy-signing keys).

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const request = require('supertest');
const h = require('./support/helpers');
const keys = require('../src/services/keys');
const keysRepo = require('../src/repos/apiKeys');
const { listAudit } = require('../src/repos/audit');
const { decryptApiKey } = require('../src/lib/secrets');

const T = { timeout: 30000 };
const MINUTE = 60 * 1000;
const HOUR = 60 * MINUTE;
const ACTOR = Object.freeze({ id: null, email: 'keys-test', ip: '127.0.0.1' });
const KEY_FORMAT = /^rly_[A-Za-z0-9_-]{43}$/;

async function expectHttpError(promise, status, message) {
  await assert.rejects(promise, (err) => {
    assert.equal(err.status, status, `status of "${err.message}"`);
    assert.equal(err.message, message);
    return true;
  });
}

describe('API keys', () => {
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

  // → HTTP status of a minimal /v1/send with this key.
  async function sendWith(key) {
    const res = await h.postV1(httpApp, key, { to: h.uniqueEmail(), subject: 'Key check', text: 'hello' });
    if (res.status === 401) assert.deepEqual(res.body, { ok: false, error: 'invalid api key' });
    return res.status;
  }

  function regenerate(app, expectedActiveKeyId, graceSeconds) {
    return keys.regenerateKey(deps, { appId: app.id, graceSeconds, expectedActiveKeyId, actor: ACTOR });
  }

  // → HTTP status of a /send.php request signed with this (legacy) key.
  async function signedStatus(key) {
    const body = JSON.stringify({
      message_id: h.uniqueName('lg'),
      to: h.uniqueEmail(),
      subject: 'Legacy key check',
      html: '<p>key check</p>',
    });
    const ts = String(Math.floor(deps.clock.now().getTime() / 1000));
    const signature = 'sha256=' + crypto.createHmac('sha256', key).update(`${ts}.${body}`).digest('hex');
    const res = await request(httpApp)
      .post('/send.php')
      .set('Content-Type', 'application/json')
      .set('X-Relay-Timestamp', ts)
      .set('X-Relay-Signature', signature)
      .send(body);
    if (res.status === 401) assert.deepEqual(res.body, { error: 'invalid signature' });
    return res.status;
  }

  it('generates keys in the documented format', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { key } = await h.insertTestApp(deps, { smtp });
    assert.match(key, KEY_FORMAT);
    assert.equal(key.length, 47);
    assert.equal(await sendWith(key), 200);
  });

  it('refuses a second active key', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { app } = await h.insertTestApp(deps, { smtp });
    await expectHttpError(keys.createKey(deps, { appId: app.id, actor: ACTOR }), 409, 'app already has an active key');
  });

  it('regenerate with no grace period stops the old key immediately', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { app, key: oldKey, keyId } = await h.insertTestApp(deps, { smtp });
    const created = await regenerate(app, keyId, 0);
    assert.match(created.key, KEY_FORMAT);
    assert.equal(created.prefix, created.key.slice(0, 12));
    assert.equal(await sendWith(oldKey), 401);
    assert.equal(await sendWith(created.key), 200);
    const old = await keysRepo.getKey(deps.db, keyId);
    assert.ok(old.revokedAt instanceof Date);
  });

  it('a 1 hour grace period keeps the old key working for an hour', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { app, key: oldKey, keyId } = await h.insertTestApp(deps, { smtp });
    const { key: newKey } = await regenerate(app, keyId, 3600);
    assert.equal(await sendWith(oldKey), 200);
    deps.clock.advance(59 * MINUTE);
    assert.equal(await sendWith(oldKey), 200, 'old key at +59 min');
    assert.equal(await sendWith(newKey), 200);
    deps.clock.advance(2 * MINUTE);
    assert.equal(await sendWith(oldKey), 401, 'old key at +61 min');
    assert.equal(await sendWith(newKey), 200);
  });

  it('a 24 hour grace period keeps the old key working for a day', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { app, key: oldKey, keyId } = await h.insertTestApp(deps, { smtp });
    const { key: newKey } = await regenerate(app, keyId, 86400);
    deps.clock.advance(23 * HOUR + 59 * MINUTE);
    assert.equal(await sendWith(oldKey), 200, 'old key at +23 h 59 min');
    deps.clock.advance(2 * MINUTE);
    assert.equal(await sendWith(oldKey), 401, 'old key at +24 h 1 min');
    assert.equal(await sendWith(newKey), 200);
  });

  it('regenerate with no grace period also stops older grace keys', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { app, key: k1, keyId: id1 } = await h.insertTestApp(deps, { smtp });
    const k2 = await regenerate(app, id1, 3600);
    assert.equal(await sendWith(k1), 200, 'k1 in its grace period');
    const k3 = await regenerate(app, k2.id, 0);
    assert.equal(await sendWith(k1), 401);
    assert.equal(await sendWith(k2.key), 401);
    assert.equal(await sendWith(k3.key), 200);
  });

  it('a shorter grace period shortens older grace keys too', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { app, key: k1, keyId: id1 } = await h.insertTestApp(deps, { smtp });
    const k2 = await regenerate(app, id1, 86400);
    const k3 = await regenerate(app, k2.id, 3600);
    deps.clock.advance(30 * MINUTE);
    assert.equal(await sendWith(k1), 200);
    assert.equal(await sendWith(k2.key), 200);
    deps.clock.advance(31 * MINUTE);
    assert.equal(await sendWith(k1), 401, 'k1 no longer outlives the newest grace period');
    assert.equal(await sendWith(k2.key), 401);
    assert.equal(await sendWith(k3.key), 200);
  });

  it('refuses to regenerate when the keys changed since the page was loaded', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { app, keyId } = await h.insertTestApp(deps, { smtp });
    const stale = 'keys changed since the page was loaded; reload and try again';
    await expectHttpError(regenerate(app, keyId + 1000000, 0), 409, stale);
    await expectHttpError(regenerate(app, null, 0), 409, stale);

    const fresh = await regenerate(app, keyId, 3600);
    // A refreshed form re-posts the id it was rendered with.
    await expectHttpError(regenerate(app, keyId, 3600), 409, stale);
    const list = await keysRepo.listKeysForApp(deps.db, app.id);
    assert.equal(list.length, 2, 'the re-post created no third key');
    assert.equal(list[0].id, fresh.id);
  });

  it('accepts only the documented grace periods', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { app, keyId } = await h.insertTestApp(deps, { smtp });
    for (const bad of [60, 7200, -1, 'abc', null, undefined]) {
      await expectHttpError(regenerate(app, keyId, bad), 400, 'invalid grace period');
    }
    const created = await regenerate(app, keyId, '3600');
    assert.match(created.key, KEY_FORMAT);
  });

  it('revoke stops a key immediately', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { app, key, keyId } = await h.insertTestApp(deps, { smtp });
    assert.equal(await sendWith(key), 200);
    await keys.revokeKey(deps, { appId: app.id, keyId, actor: ACTOR });
    assert.equal(await sendWith(key), 401);
    // With no active key left, a new one can be created.
    const created = await keys.createKey(deps, { appId: app.id, actor: ACTOR });
    assert.equal(await sendWith(created.key), 200);
  });

  it('revoke refuses a key of another app', T, async (t) => {
    if (!h.requireDb(t)) return;
    const a = await h.insertTestApp(deps, { smtp });
    const b = await h.insertTestApp(deps, { smtp });
    await assert.rejects(keys.revokeKey(deps, { appId: a.app.id, keyId: b.keyId, actor: ACTOR }), (err) => {
      assert.equal(err.status, 404);
      return true;
    });
    assert.equal(await sendWith(b.key), 200);
  });

  it('stores only the prefix and a SHA-256 hash of a normal key', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { key, keyId } = await h.insertTestApp(deps, { smtp });
    const [row] = await deps.db.query('SELECT * FROM api_keys WHERE id = ?', [keyId]);
    assert.equal(row.key_hash, crypto.createHash('sha256').update(key).digest('hex'));
    assert.equal(row.key_enc, null);
    assert.equal(row.prefix, key.slice(0, 12));
    for (const [column, value] of Object.entries(row)) {
      if (typeof value === 'string') {
        assert.ok(!value.includes(key.slice(12)), `column ${column} must not contain the key`);
      }
    }
  });

  it('stores a legacy key encrypted so that it decrypts again', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { app, key, keyId } = await h.insertTestApp(deps, { smtp, legacySigning: true });
    const [row] = await deps.db.query('SELECT * FROM api_keys WHERE id = ?', [keyId]);
    assert.equal(row.key_hash, null);
    assert.equal(typeof row.key_enc, 'string');
    assert.ok(!row.key_enc.includes(key.slice(12)), 'ciphertext must not contain the key');
    assert.equal(decryptApiKey(deps.config, app.id, row.key_enc), key);
    assert.throws(() => decryptApiKey(deps.config, app.id + 1, row.key_enc), 'bound to its app');
  });

  it('a legacy key keeps signing during its grace period', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { app, key: oldKey, keyId } = await h.insertTestApp(deps, { smtp, legacySigning: true });
    const { key: newKey } = await regenerate(app, keyId, 3600);

    assert.equal(await signedStatus(oldKey), 200);
    assert.equal(await signedStatus(newKey), 200);
    deps.clock.advance(61 * MINUTE);
    assert.equal(await signedStatus(oldKey), 401);
    assert.equal(await signedStatus(newKey), 200);
  });

  it('revoke stops a legacy key signing immediately', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { app, key, keyId } = await h.insertTestApp(deps, { smtp, legacySigning: true });
    assert.equal(await signedStatus(key), 200);
    await keys.revokeKey(deps, { appId: app.id, keyId, actor: ACTOR });
    assert.equal(await signedStatus(key), 401);
    // A new key is again stored encrypted and signs.
    const created = await keys.createKey(deps, { appId: app.id, actor: ACTOR });
    assert.equal(await signedStatus(created.key), 200);
    assert.equal(await signedStatus(key), 401, 'the revoked key stays dead');
  });

  it('regenerate with no grace period stops the old legacy key', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { app, key: oldKey, keyId } = await h.insertTestApp(deps, { smtp, legacySigning: true });
    const created = await regenerate(app, keyId, 0);
    assert.equal(await signedStatus(oldKey), 401);
    assert.equal(await signedStatus(created.key), 200);
  });

  it('revoking a legacy grace key stops it while the new key keeps signing', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { app, key: oldKey, keyId } = await h.insertTestApp(deps, { smtp, legacySigning: true });
    const created = await regenerate(app, keyId, 3600);
    assert.equal(await signedStatus(oldKey), 200, 'in its grace period');
    await keys.revokeKey(deps, { appId: app.id, keyId, actor: ACTOR });
    assert.equal(await signedStatus(oldKey), 401);
    assert.equal(await signedStatus(created.key), 200);
  });

  // authenticateLegacy directly: every valid legacy key is
  // checked (the HMACs run as WebCrypto jobs off the main thread) and the key
  // that signed the exact bytes wins.
  const TS = Object.freeze({ text: '1700000000', seconds: 1700000000 });
  const legacySig = (key, rawBody, tsText = TS.text) =>
    crypto.createHmac('sha256', key).update(`${tsText}.`).update(rawBody).digest();
  const legacyRawBody = () => Buffer.from(JSON.stringify({ to: h.uniqueEmail(), subject: 'S', html: '<p>x</p>' }));

  it('authenticateLegacy finds the app whose key signed the body, among several', T, async (t) => {
    if (!h.requireDb(t)) return;
    const apps = [];
    for (let i = 0; i < 3; i++) apps.push(await h.insertTestApp(deps, { smtp, legacySigning: true }));
    const body = legacyRawBody();
    for (const target of apps) {
      const auth = await keys.authenticateLegacy(deps, { timestamp: TS, sigBuf: legacySig(target.key, body), rawBody: body });
      assert.equal(auth.app.id, target.app.id);
      assert.equal(auth.apiKey.id, target.keyId);
    }
    const tampered = Buffer.from(body.toString().replace('<p>x</p>', '<p>y</p>'));
    const refused = [
      { timestamp: TS, sigBuf: legacySig(apps[0].key, body), rawBody: tampered },
      { timestamp: TS, sigBuf: crypto.randomBytes(32), rawBody: body },
      { timestamp: { text: '1700000001', seconds: 1700000001 }, sigBuf: legacySig(apps[1].key, body), rawBody: body },
      { timestamp: TS, sigBuf: legacySig(apps[2].key, body).subarray(0, 31), rawBody: body },
    ];
    for (const args of refused) await expectHttpError(keys.authenticateLegacy(deps, args), 401, 'invalid signature');
  });

  it('authenticateLegacy skips a key that cannot be decrypted and still checks the others', T, async (t) => {
    if (!h.requireDb(t)) return;
    const broken = await h.insertTestApp(deps, { smtp, legacySigning: true });
    const good = await h.insertTestApp(deps, { smtp, legacySigning: true });
    await deps.db.query('UPDATE api_keys SET key_enc = ? WHERE id = ?', ['v1:not-a-valid-payload', broken.keyId]);
    const warnings = [];
    const quiet = () => {};
    const watched = { ...deps, logger: { info: quiet, error: quiet, warn: (msg, meta) => warnings.push({ msg, meta }) } };
    try {
      const body = legacyRawBody();
      const auth = await keys.authenticateLegacy(watched, { timestamp: TS, sigBuf: legacySig(good.key, body), rawBody: body });
      assert.equal(auth.app.id, good.app.id);
      assert.ok(
        warnings.some((w) => w.msg === 'legacy api key could not be decrypted' && w.meta.keyId === broken.keyId),
        JSON.stringify(warnings)
      );
      await expectHttpError(
        keys.authenticateLegacy(watched, { timestamp: TS, sigBuf: legacySig(broken.key, body), rawBody: body }),
        401,
        'invalid signature'
      );
    } finally {
      // Other test files share the database: do not leave an undecryptable valid key behind.
      await keys.revokeKey(deps, { appId: broken.app.id, keyId: broken.keyId, actor: ACTOR });
    }
  });

  it('lists keys without their hash or ciphertext', T, async (t) => {
    if (!h.requireDb(t)) return;
    const normal = await h.insertTestApp(deps, { smtp });
    const legacy = await h.insertTestApp(deps, { smtp, legacySigning: true });
    for (const { app, key } of [normal, legacy]) {
      const list = await keysRepo.listKeysForApp(deps.db, app.id);
      assert.equal(list.length, 1);
      assert.equal(list[0].prefix, key.slice(0, 12));
      assert.equal('keyHash' in list[0], false);
      assert.equal('keyEnc' in list[0], false);
      assert.ok(!JSON.stringify(list).includes(key.slice(12)));
    }
  });

  it('records key changes in the audit log without the key', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { app, keyId } = await h.insertTestApp(deps, { smtp });
    const created = await regenerate(app, keyId, 86400);
    const { rows } = await listAudit(deps.db, { targetType: 'app', targetId: String(app.id), limit: 10, offset: 0 });
    const actions = rows.map((r) => r.action);
    assert.ok(actions.includes('key.create'));
    assert.ok(actions.includes('key.regenerate'));
    const regen = rows.find((r) => r.action === 'key.regenerate');
    assert.equal(regen.details.prefix, created.prefix);
    assert.equal(regen.details.graceSeconds, 86400);
    assert.ok(!JSON.stringify(rows).includes(created.key.slice(12)));
  });

  // Key changes lock only their own app's row, so admins working on different
  // apps at the same moment must not block or deadlock each other.
  it('creates keys for several apps at the same time', T, async (t) => {
    if (!h.requireDb(t)) return;
    const apps = [];
    for (let i = 0; i < 4; i++) apps.push((await h.insertTestApp(deps, { smtp, withKey: false })).app);
    const results = await Promise.allSettled(apps.map((app) => keys.createKey(deps, { appId: app.id, actor: ACTOR })));
    const failures = results.filter((r) => r.status === 'rejected').map((r) => r.reason.code || r.reason.message);
    assert.deepEqual(failures, []);
  });

  it('regenerates keys of several apps at the same time', T, async (t) => {
    if (!h.requireDb(t)) return;
    const created = [];
    for (let i = 0; i < 4; i++) created.push(await h.insertTestApp(deps, { smtp }));
    const results = await Promise.allSettled(created.map(({ app, keyId }) => regenerate(app, keyId, 3600)));
    const failures = results.filter((r) => r.status === 'rejected').map((r) => r.reason.code || r.reason.message);
    assert.deepEqual(failures, []);
  });

  // A send records the key's last use (touchKeyUsage) without the app row lock,
  // so it can change a key row between a key change's plain read and its
  // UPDATE. At REPEATABLE READ, MariaDB with innodb_snapshot_isolation=ON (the
  // default from 11.6) refuses that UPDATE with ER_CHECKREAD (1020).
  it('regenerates and revokes a key that a request touches meanwhile', T, async (t) => {
    if (!h.requireDb(t)) return;
    let isolation = null;
    try {
      [{ isolation }] = await deps.db.query('SELECT @@innodb_snapshot_isolation AS isolation');
    } catch {
      // MySQL, or MariaDB before 10.6.18: the variable does not exist.
    }
    if (Number(isolation) !== 1) {
      t.skip('innodb_snapshot_isolation is not on for this server');
      return;
    }
    // Own pool: its transaction function is wrapped below.
    const local = h.createTestDeps({ clock: h.createFakeClock() });
    const original = local.db.transaction;
    let touchId = null;
    let touches = 0;
    // After the first plain read of api_keys in every key transaction (retries
    // included), another connection records a use of `touchId`.
    local.db.transaction = (fn, options) =>
      original((tx) => {
        let done = false;
        return fn({
          ...tx,
          async query(sql, params) {
            const out = await tx.query(sql, params);
            if (!done && touchId !== null && /FROM api_keys/i.test(sql) && !/FOR UPDATE/i.test(sql)) {
              done = true;
              touches++;
              await keysRepo.touchKeyLastUsed(local.db, touchId, new Date(local.clock.now().getTime() + touches * 1000));
            }
            return out;
          },
        });
      }, options);
    try {
      const { app, keyId } = await h.insertTestApp(local, { smtp });
      touchId = keyId;
      const created = await keys.regenerateKey(local, { appId: app.id, graceSeconds: 3600, expectedActiveKeyId: keyId, actor: ACTOR });
      assert.ok(touches >= 1, 'the use was recorded inside the regenerate transaction');
      const old = await keysRepo.getKey(local.db, keyId);
      assert.ok(old.expiresAt instanceof Date, 'the old key got its grace expiry');
      assert.ok(old.lastUsedAt instanceof Date);

      touchId = created.id;
      assert.equal(await keys.revokeKey(local, { appId: app.id, keyId: created.id, actor: ACTOR }), true);
      assert.ok((await keysRepo.getKey(local.db, created.id)).revokedAt instanceof Date);
    } finally {
      local.db.transaction = original;
      await local.db.close();
    }
  });

  it('records when a key was last used', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { app, key, keyId } = await h.insertTestApp(deps, { smtp });
    assert.equal((await keysRepo.getKey(deps.db, keyId)).lastUsedAt, null);
    assert.equal(await sendWith(key), 200);
    await h.waitFor(async () => (await keysRepo.getKey(deps.db, keyId)).lastUsedAt !== null, {
      what: 'last_used_at to be recorded',
    });
    const [appRow] = await deps.db.query('SELECT last_used_at FROM apps WHERE id = ?', [app.id]);
    assert.ok(appRow.last_used_at instanceof Date);
  });
});
