'use strict';

// The admin interface through its real forms: sign-in with CSRF, throttling and
// two-factor codes, session lifetime and sign-out, re-authentication, app
// create/update (SMTP password rules, stale forms, legacy signing), API key
// pages, the test email, the counts on the apps list and stats pages, and the
// audit log. Each agent sends its own X-Forwarded-For so the per-IP login
// limits of parallel test runs never meet.

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const http = require('node:http');
const request = require('supertest');
const h = require('./support/helpers');
const admins = require('../src/services/admins');
const keysService = require('../src/services/keys');
const adminsRepo = require('../src/repos/admins');
const appsRepo = require('../src/repos/apps');
const keysRepo = require('../src/repos/apiKeys');
const { listAudit } = require('../src/repos/audit');
const { countsForDay, statsByDay } = require('../src/repos/messages');
const { hitWindow, peekWindow } = require('../src/services/rateLimit');
const authRoutes = require('../src/routes/admin/auth');
const { ipRateKey } = require('../src/lib/clientIp');
const { incrementCounter } = require('../src/repos/rateCounters');
const { decryptSmtpPassword, encryptSmtpPassword } = require('../src/lib/secrets');
const { sha256Hex } = require('../src/lib/crypto');
const { localDay } = require('../src/lib/time');
const { totpAt } = require('../src/lib/totp');

const T = { timeout: 60000 };
const MINUTE = 60 * 1000;
const HOUR = 60 * MINUTE;
const INVALID_FORM = 'Invalid or expired form. Reload and try again.';
const THROTTLED = 'Too many attempts. Try again later.';
const FORM_EXPIRED = 'The sign-in form expired. Sign in again.';
const KEY_PATTERN = /rly_[A-Za-z0-9_-]{43}/;

function csrfFrom(html) {
  const m = /name="_csrf" value="([^"]+)"/.exec(html);
  assert.ok(m, 'the page has a _csrf field');
  return m[1];
}

// The settings form's version token (stale-form check).
function versionFrom(html) {
  const m = /name="expected_updated_at" value="([^"]*)"/.exec(html);
  assert.ok(m, 'the settings form carries expected_updated_at');
  return m[1];
}

function appIdFrom(location) {
  const m = /^\/admin\/apps\/(\d+)$/.exec(location || '');
  assert.ok(m, `redirect to an app page, got ${location}`);
  return Number(m[1]);
}

// relay_sid cookie (from a Set-Cookie header) → the session id it signs.
function sidFrom(res) {
  const cookie = (res.headers['set-cookie'] || []).find((c) => c.startsWith('relay_sid='));
  assert.ok(cookie, 'a relay_sid cookie was set');
  const raw = decodeURIComponent(cookie.split(';')[0].slice('relay_sid='.length));
  assert.ok(raw.startsWith('s:'));
  return raw.slice(2, raw.lastIndexOf('.'));
}

function locationOf(res) {
  return new URL(res.headers.location, 'http://relay.test');
}

// A six-digit code that is valid for none of the steps `steps`.
function wrongCode(secret, steps) {
  const valid = new Set(steps.map((s) => totpAt(secret, s)));
  let code = 0;
  while (valid.has(String(code).padStart(6, '0'))) code++;
  return String(code).padStart(6, '0');
}

// Form helpers bound to a relay (ctx.deps / ctx.httpApp are filled in later, by
// a before() hook or by withOwnRelay).
function toolsFor(ctx) {
  async function createAdmin() {
    const email = h.uniqueEmail('admin', 'relay-test.example.com');
    const password = `Correct horse ${h.uniqueId()}`;
    await admins.createAdmin(ctx.deps, { email, name: 'Test Admin', password, actor: h.SYSTEM_ACTOR });
    const row = await adminsRepo.getAdminByEmail(ctx.deps.db, email);
    return { id: row.id, email, password };
  }

  function newAgent() {
    return request.agent(ctx.httpApp).set('X-Forwarded-For', h.uniqueIp());
  }

  async function login(agent, email, password) {
    const page = await agent.get('/admin/login');
    assert.equal(page.status, 200);
    return agent.post('/admin/login').type('form').send({ _csrf: csrfFrom(page.text), email, password });
  }

  async function signedIn(admin) {
    const agent = newAgent();
    const res = await login(agent, admin.email, admin.password);
    assert.equal(res.status, 303, res.text);
    assert.equal(res.headers.location, '/admin');
    return agent;
  }

  // Loads `pagePath` for its CSRF token, then submits the form to `action`.
  async function submit(agent, pagePath, action, fields) {
    const page = await agent.get(pagePath);
    assert.equal(page.status, 200, `GET ${pagePath}`);
    return agent.post(action).type('form').send({ _csrf: csrfFrom(page.text), ...fields });
  }

  return { createAdmin, newAgent, login, signedIn, submit };
}

// A separate relay (own pool, fake clock at real now, config overrides) for
// tests that move the clock far or need other settings.
async function withOwnRelay(configOverrides, fn) {
  const ctx = {};
  ctx.deps = h.createTestDeps({ clock: h.createFakeClock(new Date()), configOverrides });
  ctx.httpApp = h.createHttpApp(ctx.deps);
  try {
    return await fn({ ...ctx, ...toolsFor(ctx) });
  } finally {
    await ctx.deps.db.close();
  }
}

describe('admin interface', () => {
  const ctx = {};
  const { createAdmin, newAgent, login, signedIn, submit } = toolsFor(ctx);
  let deps;
  let smtp;
  let httpApp;
  let owner; // the admin most tests act as

  before(async () => {
    if (!h.dbAvailable()) return;
    smtp = await h.startSmtpServer();
    // Real time: express-session computes cookie expiry from the real clock.
    deps = h.createTestDeps({ clock: h.createFakeClock(new Date()) });
    httpApp = h.createHttpApp(deps);
    ctx.deps = deps;
    ctx.httpApp = httpApp;
    owner = await createAdmin();
  });

  after(async () => {
    if (smtp) await smtp.close();
    if (deps) await deps.db.close();
  });

  function appForm(overrides = {}) {
    return {
      name: h.uniqueName('Form app'),
      notes: '',
      enabled: '1',
      smtp_host: '127.0.0.1',
      smtp_port: String(smtp.port),
      smtp_encryption: 'none',
      smtp_username: '',
      smtp_password: '',
      from_email: h.uniqueEmail('noreply', 'relay-test.example.com'),
      from_name: 'Form App',
      allowed_from: '',
      reply_to_default: '',
      limit_per_minute: '30',
      limit_per_day: '1000',
      max_message_mb: '10',
      max_recipients: '50',
      ip_allowlist: '',
      ...overrides,
    };
  }

  async function createAppViaForm(agent, overrides) {
    const form = appForm(overrides);
    const res = await submit(agent, '/admin/apps/new', '/admin/apps', form);
    assert.equal(res.status, 303, res.text);
    return { id: appIdFrom(res.headers.location), form };
  }

  // Submits the app's settings form as the page renders it: CSRF token and the
  // version token of the settings it was loaded with.
  async function saveSettings(agent, id, fields) {
    const page = await agent.get(`/admin/apps/${id}`);
    assert.equal(page.status, 200);
    return agent
      .post(`/admin/apps/${id}`)
      .type('form')
      .send({ _csrf: csrfFrom(page.text), expected_updated_at: versionFrom(page.text), ...fields });
  }

  async function auditFor(appId) {
    const { rows } = await listAudit(deps.db, { targetType: 'app', targetId: String(appId), limit: 50, offset: 0 });
    return rows;
  }

  async function adminAudit(adminId, action) {
    const { rows } = await listAudit(deps.db, { targetType: 'admin', targetId: String(adminId), limit: 100, offset: 0 });
    return rows.filter((r) => r.action === action);
  }

  it('requires a valid CSRF token to sign in', T, async (t) => {
    if (!h.requireDb(t)) return;
    const agent = newAgent();
    const page = await agent.get('/admin/login');
    assert.equal(page.status, 200);
    assert.match(page.headers['content-security-policy'], /default-src 'self'/);
    assert.equal(page.headers['x-frame-options'], 'DENY');
    const token = csrfFrom(page.text);

    const missing = await agent.post('/admin/login').type('form').send({ email: owner.email, password: owner.password });
    assert.equal(missing.status, 403);
    assert.ok(missing.text.includes(INVALID_FORM));

    const wrong = await agent
      .post('/admin/login')
      .type('form')
      .send({ _csrf: token.slice(1) + 'x', email: owner.email, password: owner.password });
    assert.equal(wrong.status, 403);
    assert.ok(wrong.text.includes(INVALID_FORM));
    assert.ok(!wrong.text.includes(FORM_EXPIRED), 'a wrong token is not an expired form');

    const badPassword = await agent
      .post('/admin/login')
      .type('form')
      .send({ _csrf: token, email: owner.email, password: 'wrong password!' });
    assert.ok(badPassword.status >= 400 && badPassword.status < 500, `status ${badPassword.status}`);
    assert.ok(badPassword.text.includes('Invalid email or password.'));

    const unknown = await agent
      .post('/admin/login')
      .type('form')
      .send({ _csrf: token, email: h.uniqueEmail('nobody'), password: 'whatever password' });
    assert.ok(unknown.text.includes('Invalid email or password.'), 'same message for an unknown email');

    const ok = await agent
      .post('/admin/login')
      .type('form')
      .send({ _csrf: token, email: owner.email.toUpperCase(), password: owner.password });
    assert.equal(ok.status, 303);
    assert.equal(ok.headers.location, '/admin');

    const home = await agent.get('/admin');
    assert.equal(home.status, 200);
    assert.ok(home.text.includes('action="/admin/logout"'), 'signed-in layout with the logout form');
    assert.equal(home.headers['cache-control'], 'no-store');
  });

  it('redirects to the login page without a session', T, async (t) => {
    if (!h.requireDb(t)) return;
    const agent = newAgent();
    const home = await agent.get('/admin');
    assert.equal(home.status, 302);
    assert.ok(home.headers.location.startsWith('/admin/login'));
    const logs = await agent.get('/admin/logs');
    assert.equal(logs.status, 302);
    const target = locationOf(logs);
    assert.equal(target.pathname, '/admin/login');
    assert.equal(target.searchParams.get('next'), '/admin/logs');
  });

  it('refused anonymous requests create no session', T, async (t) => {
    if (!h.requireDb(t)) return;
    // Only this file creates sessions with a CSRF token, and its tests run one
    // at a time (cleanup.test.js inserts and deletes token-less rows meanwhile).
    const count = async () => (await deps.db.query("SELECT COUNT(*) AS n FROM sessions WHERE data LIKE '%csrfToken%'"))[0].n;
    const before = await count();
    const ip = h.uniqueIp();
    for (const [method, path] of [
      ['post', '/admin/apps'],
      ['post', '/admin/logout'],
      ['put', '/admin/apps'],
      ['options', '/admin/apps'],
    ]) {
      const res = await request(httpApp)[method](path).set('X-Forwarded-For', ip).type('form').send({ name: 'x' });
      assert.ok(res.status === 401 || res.status === 403 || res.status === 404, `${method} ${path}: ${res.status}`);
      assert.equal(res.headers['set-cookie'], undefined, `${method} ${path} sets no cookie`);
    }
    assert.ok((await count()) <= before, 'no sessions row was added');
  });

  it('requires the CSRF token on every admin form', T, async (t) => {
    if (!h.requireDb(t)) return;
    const agent = await signedIn(owner);
    const page = await agent.get('/admin/apps/new');
    const token = csrfFrom(page.text);
    const refused = appForm();

    const missing = await agent.post('/admin/apps').type('form').send(refused);
    assert.equal(missing.status, 403);
    assert.ok(missing.text.includes(INVALID_FORM));
    const wrong = await agent
      .post('/admin/apps')
      .type('form')
      .send({ ...refused, _csrf: crypto.randomBytes(32).toString('base64url') });
    assert.equal(wrong.status, 403);
    const crossSite = await agent
      .post('/admin/apps')
      .set('Origin', 'https://evil.example.com')
      .type('form')
      .send({ ...refused, _csrf: token });
    assert.equal(crossSite.status, 403);
    const rows = await deps.db.query('SELECT COUNT(*) AS n FROM apps WHERE name = ?', [refused.name]);
    assert.equal(rows[0].n, 0, 'refused forms created nothing');

    const viaHeader = appForm();
    const accepted = await agent.post('/admin/apps').set('X-CSRF-Token', token).type('form').send(viaHeader);
    assert.equal(accepted.status, 303, accepted.text);
    appIdFrom(accepted.headers.location);
  });

  it('locks one account from one IP after 10 wrong passwords', T, async (t) => {
    if (!h.requireDb(t)) return;
    const a = await createAdmin();
    const agent = newAgent();
    // login() is a GET plus a POST; 11 of them stay under the 30/min page limiter.
    for (let i = 0; i < 10; i++) {
      const res = await login(agent, a.email, `wrong password ${i}`);
      assert.equal(res.status, 401, `attempt ${i + 1}`);
    }
    const blocked = await login(agent, a.email, a.password);
    assert.equal(blocked.status, 429);
    assert.ok(blocked.text.includes(THROTTLED));
    const audits = await adminAudit(a.id, 'auth.login_throttled');
    assert.equal(audits.length, 1);
    assert.equal(audits[0].details.bucket, 'account_ip');
    // The account itself is not locked: the same password from another IP works.
    assert.equal((await login(newAgent(), a.email, a.password)).status, 303);
  });

  it('a crafted email cannot fill another IP\'s bucket for a real admin', T, async (t) => {
    if (!h.requireDb(t)) return;
    const victim = await createAdmin();
    const victimIp = h.uniqueIp();
    const attacker = newAgent();
    const page = await attacker.get('/admin/login');
    for (let i = 0; i < 10; i++) {
      const res = await attacker
        .post('/admin/login')
        .type('form')
        .send({ _csrf: csrfFrom(page.text), email: `${victim.email}:ip:${victimIp}`, password: `guess ${i}` });
      assert.equal(res.status, 401, `attempt ${i + 1}`);
    }
    const agent = request.agent(httpApp).set('X-Forwarded-For', victimIp);
    const res = await login(agent, victim.email, victim.password);
    assert.equal(res.status, 303, 'the victim signs in from their own IP');
  });

  it('keys the sign-in IP buckets by the IPv4 address or the IPv6 /48', () => {
    const req = (ip) => ({ ip });
    assert.equal(authRoutes.LOGIN_V6_PREFIX, 48);
    assert.equal(authRoutes.loginIpKey(req('203.0.113.9')), '203.0.113.9', 'IPv4 unchanged');
    assert.equal(authRoutes.loginIpKey(req('::ffff:203.0.113.9')), '203.0.113.9');
    assert.equal(authRoutes.loginIpKey(req('2001:db8:abcd:12::1')), '2001:db8:abcd::/48');
    assert.equal(authRoutes.loginIpKey(req('2001:DB8:ABCD:FF00:1:2:3:4')), '2001:db8:abcd::/48');
    assert.equal(authRoutes.loginIpKey(req('2001:db8:abce::1')), '2001:db8:abce::/48');
    assert.equal(authRoutes.loginIpKey(req(undefined)), null);
    // Every other per-IP limit keeps the /64 default.
    assert.equal(ipRateKey('2001:db8:abcd:12::1'), '2001:db8:abcd:12::/64');
    assert.equal(ipRateKey('2001:db8:abcd:12::1', { v6Prefix: 48 }), '2001:db8:abcd::/48');
    assert.equal(ipRateKey('203.0.113.9', { v6Prefix: 48 }), '203.0.113.9');
    assert.throws(() => ipRateKey('2001:db8::1', { v6Prefix: 56 }), RangeError);
  });

  it('counts IPv6 sign-ins per /48 and keeps no relay-wide bucket', T, async (t) => {
    if (!h.requireDb(t)) return;
    const WINDOW = 15 * 60;
    // Two random /48s in the documentation range, written as ipRateKey writes
    // them (no leading zeros), so parallel runs never share one.
    const pick = () => (1 + (crypto.randomBytes(2).readUInt16BE(0) % 0xfffe)).toString(16);
    const block = pick();
    const otherBlock = block === 'ffff' ? '1' : (parseInt(block, 16) + 1).toString(16);
    // Address i of the /48 sits in its own /64.
    const inBlock = (i) => `2001:db8:${block}:${(i + 1).toString(16)}::${(i + 7).toString(16)}`;
    const ipKey = `2001:db8:${block}::/48`;
    const email = h.uniqueEmail('nobody', 'relay-test.example.com');
    // Exhaust this email's account+IP bucket for the /48
    // up front, so no attempt below needs a bcrypt compare.
    for (let i = 0; i < 10; i++) await hitWindow(deps, `login:acctip:${ipKey}:${email}`, 10, WINDOW);
    const agent = request.agent(httpApp);
    const token = csrfFrom((await agent.get('/admin/login').set('X-Forwarded-For', inBlock(100))).text);
    const statuses = [];
    for (let i = 0; i < 21; i++) {
      const res = await agent
        .post('/admin/login')
        .set('X-Forwarded-For', inBlock(i))
        .type('form')
        .send({ _csrf: token, email, password: `guess ${i}` });
      statuses.push(res.status);
    }
    // 1-20: allowed by the IP bucket, refused by the account bucket; 21: refused
    // by the IP bucket. 21 different /64s, one /48 bucket.
    assert.deepEqual([...new Set(statuses)], [429], statuses.join(','));
    assert.equal((await peekWindow(deps, `login:ip:${ipKey}`, 20, WINDOW)).count, 21);

    // Another /64 of the same /48 is refused before its password is checked,
    const sameBlock = await login(request.agent(httpApp).set('X-Forwarded-For', inBlock(500)), owner.email, owner.password);
    assert.equal(sameBlock.status, 429);
    assert.ok(sameBlock.text.includes(THROTTLED));
    // while the next /48 and IPv4 clients sign in as usual.
    const nextBlock = request.agent(httpApp).set('X-Forwarded-For', `2001:db8:${otherBlock}:1::1`);
    assert.equal((await login(nextBlock, owner.email, owner.password)).status, 303, 'another /48 signs in');
    assert.equal((await login(newAgent(), owner.email, owner.password)).status, 303, 'IPv4 clients sign in');

    // There is no relay-wide sign-in bucket any more.
    const [{ n }] = await deps.db.query("SELECT COUNT(*) AS n FROM rate_counters WHERE k LIKE 'login:global%'");
    assert.equal(Number(n), 0);
  });

  it('limits the sign-in pages to 30 requests per minute per IP', T, async (t) => {
    if (!h.requireDb(t)) return;
    const ip = h.uniqueIp();
    for (let i = 0; i < 30; i++) {
      const res = await request(httpApp).get('/admin/login').set('X-Forwarded-For', ip);
      assert.equal(res.status, 200, `request ${i + 1}`);
    }
    const limited = await request(httpApp).get('/admin/login').set('X-Forwarded-For', ip);
    assert.equal(limited.status, 429);
    assert.match(limited.headers['content-type'], /text\/plain/);
    assert.ok(Number(limited.headers['retry-after']) >= 1);
    assert.equal(limited.headers['set-cookie'], undefined, 'a limited request stores no session');
    const refusedPost = await request(httpApp).post('/admin/login').set('X-Forwarded-For', ip).type('form').send({});
    assert.equal(refusedPost.status, 429, 'refused forms count too');
  });

  it('a password reset ends every session of that admin (session epoch)', T, async (t) => {
    if (!h.requireDb(t)) return;
    const other = await createAdmin();
    const ownerAgent = await signedIn(owner);
    const otherAgent = await signedIn(other);
    assert.equal((await otherAgent.get('/admin/logs')).status, 200);
    const epochBefore = (await adminsRepo.getAdmin(deps.db, other.id)).sessionEpoch;

    const newPassword = `Brand new password ${h.uniqueId()}`;
    const res = await submit(ownerAgent, '/admin/users', `/admin/users/${other.id}/reset-password`, {
      new_password: newPassword,
      current_password: owner.password,
    });
    assert.equal(res.status, 303, res.text);
    assert.equal(res.headers.location, '/admin/users');
    assert.ok((await adminsRepo.getAdmin(deps.db, other.id)).sessionEpoch > epochBefore);

    const kicked = await otherAgent.get('/admin/logs');
    assert.equal(kicked.status, 302);
    const target = locationOf(kicked);
    assert.equal(target.pathname, '/admin/login');
    assert.equal(target.searchParams.get('next'), '/admin/logs');
    assert.equal((await otherAgent.get('/admin')).status, 302, 'the old session stays dead');

    assert.equal((await ownerAgent.get('/admin')).status, 200, 'the acting admin stays signed in');
    const oldLogin = await login(newAgent(), other.email, other.password);
    assert.notEqual(oldLogin.status, 303);
    const newLogin = await login(newAgent(), other.email, newPassword);
    assert.equal(newLogin.status, 303);

    const { rows } = await listAudit(deps.db, { targetType: 'admin', targetId: String(other.id), limit: 20, offset: 0 });
    const reset = rows.find((r) => r.action === 'admin.password_reset');
    assert.ok(reset, 'admin.password_reset audited');
    assert.equal(reset.adminUserId, owner.id);
    assert.ok(!JSON.stringify(reset.details).includes(newPassword));
  });

  it('a password reset requires the current password of the acting admin', T, async (t) => {
    if (!h.requireDb(t)) return;
    const other = await createAdmin();
    const ownerAgent = await signedIn(owner);
    const epochBefore = (await adminsRepo.getAdmin(deps.db, other.id)).sessionEpoch;
    const res = await submit(ownerAgent, '/admin/users', `/admin/users/${other.id}/reset-password`, {
      new_password: `Another new password ${h.uniqueId()}`,
      current_password: 'not my password',
    });
    assert.ok(res.status < 500, `status ${res.status}`);
    assert.equal((await adminsRepo.getAdmin(deps.db, other.id)).sessionEpoch, epochBefore);
    assert.equal((await login(newAgent(), other.email, other.password)).status, 303, 'old password still works');
    assert.equal((await adminAudit(owner.id, 'auth.reauth_failed')).length, 1, 'the wrong password is audited');
  });

  it('enabling or disabling an admin requires the current password', T, async (t) => {
    if (!h.requireDb(t)) return;
    const boss = await createAdmin();
    const other = await createAdmin();
    const agent = await signedIn(boss);
    const isDisabled = async () => (await adminsRepo.getAdmin(deps.db, other.id)).disabled;
    const change = (action, fields) => submit(agent, '/admin/users', `/admin/users/${other.id}/${action}`, fields);

    for (const fields of [{}, { current_password: 'not my password' }]) {
      const res = await change('disable', fields);
      assert.equal(res.status, 303);
      assert.equal(res.headers.location, '/admin/users');
      assert.equal(await isDisabled(), false, JSON.stringify(fields));
      assert.ok((await agent.get('/admin/users')).text.includes('flash-error'));
    }
    assert.equal((await change('disable', { current_password: boss.password })).status, 303);
    assert.equal(await isDisabled(), true);
    assert.equal((await login(newAgent(), other.email, other.password)).status, 401, 'a disabled admin cannot sign in');

    assert.equal((await change('enable', {})).status, 303);
    assert.equal(await isDisabled(), true, 'not enabled without the password');
    assert.equal((await change('enable', { current_password: boss.password })).status, 303);
    assert.equal(await isDisabled(), false);

    const disabledRow = (await adminAudit(other.id, 'admin.disable'))[0];
    const enabledRow = (await adminAudit(other.id, 'admin.enable'))[0];
    assert.equal(disabledRow.adminUserId, boss.id);
    assert.equal(enabledRow.adminUserId, boss.id);
    assert.equal((await adminAudit(boss.id, 'auth.reauth_failed')).length, 1);
  });

  it('checks at most 10 of 15 concurrent wrong re-authentications', T, async (t) => {
    if (!h.requireDb(t)) return;
    const me = await createAdmin();
    // A server that already listens: supertest then does not start one per request.
    const server = http.createServer(httpApp);
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    try {
      const agent = request.agent(server).set('X-Forwarded-For', h.uniqueIp());
      assert.equal((await login(agent, me.email, me.password)).status, 303);
      const token = csrfFrom((await agent.get('/admin/account')).text);
      const attempt = (password) =>
        agent.post('/admin/account/totp/setup').type('form').send({ _csrf: token, current_password: password });

      const results = await Promise.all(Array.from({ length: 15 }, (_, i) => attempt(`wrong password ${i}`)));
      const wrong = results.filter((r) => r.text.includes('Your current password is not correct.')).length;
      const throttled = results.filter((r) => r.text.includes(THROTTLED)).length;
      assert.ok(results.every((r) => r.status === 400), results.map((r) => r.status).join(','));
      assert.equal(wrong + throttled, 15);
      assert.ok(wrong >= 1 && wrong <= 10, `${wrong} passwords were checked`);
      // One process runs an admin's re-authentications one at a time, so it
      // checks exactly the budget: no concurrent guess slips past the peek.
      assert.equal(wrong, 10, 'one process checks exactly 10');
      assert.equal((await adminAudit(me.id, 'auth.reauth_failed')).length, wrong);
      assert.equal((await adminAudit(me.id, 'auth.reauth_throttled')).length, 1);

      // The limit holds for the right password too, until the window ends.
      const right = await attempt(me.password);
      assert.equal(right.status, 400);
      assert.ok(right.text.includes(THROTTLED));
      assert.equal((await adminsRepo.getAdmin(deps.db, me.id)).totpSecretEnc, null, 'no setup was started');
      assert.equal((await adminAudit(me.id, 'auth.reauth_throttled')).length, 1, 'audited once per episode');
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  it('correct re-authentications never use up the budget', T, async (t) => {
    if (!h.requireDb(t)) return;
    const me = await createAdmin();
    const row = await adminsRepo.getAdmin(deps.db, me.id);
    const actor = { id: me.id, email: me.email, ip: '203.0.113.7' };
    const budgetUsed = async () => (await peekWindow(deps, `reauth:${me.id}`, admins.REAUTH_LIMIT, 15 * 60)).count;
    for (let i = 0; i < 12; i++) {
      assert.equal(await admins.reauthenticate(deps, row, me.password, actor), null, `correct attempt ${i + 1}`);
    }
    assert.equal(await budgetUsed(), 0, 'successes are not counted');
    // A wrong password is still counted and audited; the right one still passes.
    assert.equal(await admins.reauthenticate(deps, row, 'not my password', actor), 'Your current password is not correct.');
    assert.equal(await budgetUsed(), 1);
    assert.equal(await admins.reauthenticate(deps, row, me.password, actor), null);
    assert.equal(await budgetUsed(), 1);
    assert.equal((await adminAudit(me.id, 'auth.reauth_failed')).length, 1);
    assert.equal((await adminAudit(me.id, 'auth.reauth_throttled')).length, 0);
  });

  it('a correct re-authentication is not refused because two sign-ins are being checked', T, async (t) => {
    if (!h.requireDb(t)) return;
    const me = await createAdmin();
    const agent = await signedIn(me);
    const token = csrfFrom((await agent.get('/admin/account')).text);
    // Two sign-ins in progress: both slots of the sign-in bcrypt gate taken.
    let release;
    const held = new Promise((resolve) => {
      release = resolve;
    });
    const holders = [admins.withCompareSlot(() => held), admins.withCompareSlot(() => held)];
    try {
      assert.equal((await admins.withCompareSlot(async () => true)).busy, true, 'the sign-in gate is full');
      const signIn = await login(newAgent(), owner.email, owner.password);
      assert.equal(signIn.status, 429, 'a third sign-in is refused meanwhile');

      const row = await adminsRepo.getAdmin(deps.db, me.id);
      assert.equal(await admins.reauthenticate(deps, row, me.password, null), null);
      const setup = await agent
        .post('/admin/account/totp/setup')
        .type('form')
        .send({ _csrf: token, current_password: me.password });
      assert.equal(setup.status, 200, setup.text);
      assert.ok(!setup.text.includes(THROTTLED));
      assert.notEqual((await adminsRepo.getAdmin(deps.db, me.id)).totpSecretEnc, null, 'the setup started');
    } finally {
      release(false);
      await Promise.all(holders);
    }
  });

  it('changing your own password keeps this session and ends the others', T, async (t) => {
    if (!h.requireDb(t)) return;
    const me = await createAdmin();
    const here = await signedIn(me);
    const elsewhere = await signedIn(me);
    const newPassword = `My next password ${h.uniqueId()}`;
    const res = await submit(here, '/admin/account', '/admin/account/password', {
      current_password: me.password,
      new_password: newPassword,
      confirm_password: newPassword,
    });
    assert.equal(res.status, 303, res.text);
    assert.equal((await here.get('/admin')).status, 200);
    assert.equal((await elsewhere.get('/admin')).status, 302);
    assert.equal((await login(newAgent(), me.email, newPassword)).status, 303);
  });

  it('signing out ends the session', T, async (t) => {
    if (!h.requireDb(t)) return;
    const agent = await signedIn(owner);
    const res = await submit(agent, '/admin', '/admin/logout', {});
    assert.equal(res.status, 303);
    assert.ok(res.headers.location.startsWith('/admin/login'));
    assert.equal((await agent.get('/admin')).status, 302);
  });

  it('a request still in flight cannot undo a sign-out', T, async (t) => {
    if (!h.requireDb(t)) return;
    const me = await createAdmin();
    const agent = newAgent();
    const signIn = await login(agent, me.email, me.password);
    assert.equal(signIn.status, 303);
    const rowId = sha256Hex(sidFrom(signIn));
    const { app } = await h.insertTestApp(deps, { smtp });
    const token = csrfFrom((await agent.get(`/admin/apps/${app.id}`)).text);

    smtp.setStall(true);
    let inFlight;
    try {
      // Saves its session (a flash message) only when the SMTP answer comes.
      inFlight = agent
        .post(`/admin/apps/${app.id}/test`)
        .type('form')
        .send({ _csrf: token, to: h.uniqueEmail() })
        .then((r) => r);
      await h.waitFor(() => smtp.stalledCount === 1, { what: 'the test email to reach DATA' });
      const out = await agent.post('/admin/logout').type('form').send({ _csrf: token });
      assert.equal(out.status, 303);
      assert.ok(out.headers.location.startsWith('/admin/login'));
    } finally {
      smtp.setStall(false);
    }
    const late = await inFlight;
    assert.equal(late.status, 303);

    // The late response may hand the old cookie back; it must not work.
    assert.equal((await agent.get('/admin')).status, 302);
    const [row] = await deps.db.query('SELECT data FROM sessions WHERE session_id = ?', [rowId]);
    assert.ok(row, 'the destroyed session is kept as a tombstone');
    assert.equal(row.data, null);
  });

  it('creates an app and clears the SMTP password when the SMTP server changes', T, async (t) => {
    if (!h.requireDb(t)) return;
    const agent = await signedIn(owner);
    const first = 'first-secret-' + h.uniqueId();
    const created = await createAppViaForm(agent, { smtp_username: 'mailer', smtp_password: first });
    const id = created.id;
    // Later submissions start from the saved settings with the password field blank.
    const form = { ...created.form, smtp_password: '' };

    let app = await appsRepo.getApp(deps.db, id);
    assert.equal(app.name, form.name);
    assert.equal(app.smtpUsername, 'mailer');
    assert.equal(decryptSmtpPassword(deps.config, app), first);
    assert.ok(!app.smtpPasswordEnc.includes(first));

    const page = await agent.get(`/admin/apps/${id}`);
    assert.equal(page.status, 200);
    assert.ok(page.text.includes('App created — generate an API key'));
    assert.ok(!page.text.includes(first), 'the password is never shown again');

    // Host change without a new password: the stored password is cleared.
    const moved = await saveSettings(agent, id, { ...form, smtp_host: 'localhost' });
    assert.equal(moved.status, 303, moved.text);
    assert.equal(moved.headers.location, `/admin/apps/${id}`);
    app = await appsRepo.getApp(deps.db, id);
    assert.equal(app.smtpHost, 'localhost');
    assert.equal(app.smtpPasswordEnc, null);
    const update = (await auditFor(id)).find((r) => r.action === 'app.update');
    assert.equal(update.details.smtpPassword, '[cleared]');
    assert.deepEqual(update.details.smtpHost, { from: '127.0.0.1', to: 'localhost' });

    // Server change together with a new password: stored for the new settings.
    const second = 'second-secret-' + h.uniqueId();
    const back = await saveSettings(agent, id, { ...form, smtp_port: '2525', smtp_password: second });
    assert.equal(back.status, 303, back.text);
    app = await appsRepo.getApp(deps.db, id);
    assert.equal(app.smtpPort, 2525);
    assert.equal(decryptSmtpPassword(deps.config, app), second);

    // Password only.
    const third = 'third-secret-' + h.uniqueId();
    const pwOnly = await saveSettings(agent, id, { ...form, smtp_port: '2525', smtp_password: third });
    assert.equal(pwOnly.status, 303);
    app = await appsRepo.getApp(deps.db, id);
    assert.equal(decryptSmtpPassword(deps.config, app), third);
    assert.ok((await auditFor(id)).some((r) => r.action === 'app.smtp_password_change'));

    // Blank password and no server change: the password is kept.
    const keep = await saveSettings(agent, id, { ...form, smtp_port: '2525', notes: 'kept password' });
    assert.equal(keep.status, 303);
    app = await appsRepo.getApp(deps.db, id);
    assert.equal(app.notes, 'kept password');
    assert.equal(decryptSmtpPassword(deps.config, app), third);

    const audit = JSON.stringify(await auditFor(id));
    for (const secret of [first, second, third]) assert.ok(!audit.includes(secret), 'no password in the audit log');
    const shown = await agent.get(`/admin/apps/${id}`);
    for (const secret of [first, second, third]) assert.ok(!shown.text.includes(secret));
  });

  // docs/SPEC.md decision 7, kept in step with the password's encryption context
  // (secrets.smtpContext): exactly a change that would make the stored password
  // undecryptable clears it.
  it('clears the SMTP password on an encryption or username change, not on a host case change', T, async (t) => {
    if (!h.requireDb(t)) return;
    const agent = await signedIn(owner);
    const first = 'enc-secret-' + h.uniqueId();
    const created = await createAppViaForm(agent, { smtp_username: 'mailer', smtp_password: first });
    const id = created.id;
    const form = { ...created.form, smtp_password: '', smtp_encryption: 'starttls' };
    const lastUpdate = async () => (await auditFor(id)).find((r) => r.action === 'app.update');

    // Encryption only.
    assert.equal((await saveSettings(agent, id, form)).status, 303);
    assert.equal((await appsRepo.getApp(deps.db, id)).smtpPasswordEnc, null);
    let update = await lastUpdate();
    assert.equal(update.details.smtpPassword, '[cleared]');
    assert.deepEqual(update.details.smtpEncryption, { from: 'none', to: 'starttls' });

    // Username only.
    const second = 'user-secret-' + h.uniqueId();
    assert.equal((await saveSettings(agent, id, { ...form, smtp_password: second })).status, 303);
    assert.equal(decryptSmtpPassword(deps.config, await appsRepo.getApp(deps.db, id)), second);
    assert.equal((await saveSettings(agent, id, { ...form, smtp_username: 'mailer2' })).status, 303);
    assert.equal((await appsRepo.getApp(deps.db, id)).smtpPasswordEnc, null);
    update = await lastUpdate();
    assert.equal(update.details.smtpPassword, '[cleared]');

    // Host spelled in another case: the same server, the password stays usable.
    const third = 'case-secret-' + h.uniqueId();
    const mixed = 'Mail.Relay-Test.Example.com';
    const app = await appsRepo.getApp(deps.db, id);
    await appsRepo.updateApp(
      deps.db,
      id,
      { smtpHost: mixed, smtpPasswordEnc: encryptSmtpPassword(deps.config, { ...app, smtpHost: mixed }, third) },
      deps.clock.now()
    );
    const lower = { ...form, smtp_username: 'mailer2', smtp_host: mixed.toLowerCase() };
    assert.equal((await saveSettings(agent, id, lower)).status, 303);
    const kept = await appsRepo.getApp(deps.db, id);
    assert.equal(kept.smtpHost.toLowerCase(), mixed.toLowerCase());
    assert.equal(decryptSmtpPassword(deps.config, kept), third, 'kept and still decryptable');
  });

  it('refuses a settings form loaded before another save (409 flash, nothing changed)', T, async (t) => {
    if (!h.requireDb(t)) return;
    const agent = await signedIn(owner);
    const password = 'stale-secret-' + h.uniqueId();
    const { id, form } = await createAppViaForm(agent, { smtp_username: 'mailer', smtp_password: password });
    const base = { ...form, smtp_password: '' };

    // Admin A loads the form...
    const stalePage = await agent.get(`/admin/apps/${id}`);
    const staleFields = { _csrf: csrfFrom(stalePage.text), expected_updated_at: versionFrom(stalePage.text) };
    // ...admin B saves a change first...
    const fresh = await saveSettings(agent, id, { ...base, notes: 'saved by B' });
    assert.equal(fresh.status, 303);
    const afterB = await appsRepo.getApp(deps.db, id);

    // ...then A submits the old form (with a host change that would clear the password).
    const stale = await agent
      .post(`/admin/apps/${id}`)
      .type('form')
      .send({ ...base, ...staleFields, notes: 'saved by A', smtp_host: 'stale.example.com' });
    assert.equal(stale.status, 303);
    assert.equal(stale.headers.location, `/admin/apps/${id}`);
    const shown = await agent.get(`/admin/apps/${id}`);
    assert.ok(shown.text.includes('flash-error'));
    assert.match(shown.text, /changed since/i);

    const app = await appsRepo.getApp(deps.db, id);
    assert.equal(app.notes, 'saved by B');
    assert.equal(app.smtpHost, '127.0.0.1');
    assert.equal(decryptSmtpPassword(deps.config, app), password, 'the password was not cleared');
    assert.equal(app.updatedAt.getTime(), afterB.updatedAt.getTime());

    // A form without the version token is refused the same way.
    const noToken = await agent
      .post(`/admin/apps/${id}`)
      .type('form')
      .send({ ...base, _csrf: staleFields._csrf, notes: 'no token' });
    assert.equal(noToken.status, 303);
    assert.equal((await appsRepo.getApp(deps.db, id)).notes, 'saved by B');
  });

  it('turning legacy signing on or off revokes every key of the app', T, async (t) => {
    if (!h.requireDb(t)) return;
    const agent = await signedIn(owner);
    const { id, form } = await createAppViaForm(agent);
    const base = { ...form, smtp_password: '' };
    const { key: bearerKey } = await keysService.createKey(deps, { appId: id, actor: h.SYSTEM_ACTOR });
    const sendV1 = (key) => h.postV1(httpApp, key, { to: h.uniqueEmail(), subject: 's', text: 't' });
    const sendLegacy = (key) =>
      h.postLegacy(
        httpApp,
        deps,
        key,
        JSON.stringify({ message_id: h.uniqueName('tog'), to: h.uniqueEmail(), subject: 's', html: '<p>t</p>' })
      );
    const allRevoked = async () => (await keysRepo.listKeysForApp(deps.db, id)).every((k) => k.revokedAt !== null);
    const revokeAll = async () => (await auditFor(id)).filter((r) => r.action === 'key.revoke_all');
    assert.equal((await sendV1(bearerKey)).status, 200);

    const on = await saveSettings(agent, id, { ...base, legacy_signing: '1' });
    assert.equal(on.status, 303, on.text);
    assert.equal((await appsRepo.getApp(deps.db, id)).legacySigning, true);
    assert.ok(await allRevoked());
    assert.equal((await sendV1(bearerKey)).status, 401);
    const [enabled] = await revokeAll();
    assert.equal(enabled.details.reason, 'legacy signing enabled');
    assert.ok(enabled.details.count >= 1);
    assert.equal(enabled.adminUserId, owner.id);

    // A key created now is a legacy (signing) key.
    const { key: legacyKey } = await keysService.createKey(deps, { appId: id, actor: h.SYSTEM_ACTOR });
    assert.equal((await sendLegacy(legacyKey)).status, 200);

    const off = await saveSettings(agent, id, { ...base });
    assert.equal(off.status, 303, off.text);
    assert.equal((await appsRepo.getApp(deps.db, id)).legacySigning, false);
    assert.ok(await allRevoked());
    const disabled = (await revokeAll()).find((r) => r.details.reason === 'legacy signing disabled');
    assert.ok(disabled, 'key.revoke_all audited for turning it off');
    assert.equal((await sendLegacy(legacyKey)).status, 401);

    // Turning it on again does not bring the old legacy key back.
    assert.equal((await saveSettings(agent, id, { ...base, legacy_signing: '1' })).status, 303);
    assert.equal((await sendLegacy(legacyKey)).status, 401);
  });

  it('re-shows the form with errors for invalid settings', T, async (t) => {
    if (!h.requireDb(t)) return;
    const agent = await signedIn(owner);
    const form = appForm({ from_email: 'not-an-email', smtp_port: '99999' });
    const res = await submit(agent, '/admin/apps/new', '/admin/apps', form);
    assert.ok(res.status >= 400 && res.status < 500, `status ${res.status}`);
    assert.ok(res.text.includes(form.name), 'submitted values are kept');
    const rows = await deps.db.query('SELECT COUNT(*) AS n FROM apps WHERE name = ?', [form.name]);
    assert.equal(rows[0].n, 0);
  });

  it('shows a new API key once, then only its prefix', T, async (t) => {
    if (!h.requireDb(t)) return;
    const agent = await signedIn(owner);
    const { id } = await createAppViaForm(agent);

    const created = await submit(agent, `/admin/apps/${id}`, `/admin/apps/${id}/keys`, {});
    assert.equal(created.status, 200, created.text);
    assert.equal(created.headers['cache-control'], 'no-store');
    const key = KEY_PATTERN.exec(created.text)[0];
    const [row] = await deps.db.query('SELECT key_hash, prefix FROM api_keys WHERE app_id = ?', [id]);
    assert.equal(row.key_hash, crypto.createHash('sha256').update(key).digest('hex'));

    const page = await agent.get(`/admin/apps/${id}`);
    assert.ok(!page.text.includes(key), 'the full key is not shown again');
    assert.ok(page.text.includes(key.slice(0, 12)), 'the prefix is shown');

    const to = h.uniqueEmail();
    const sent = await h.postV1(httpApp, key, { to, subject: 'Key from the admin page', text: 'hi' });
    assert.equal(sent.status, 200, JSON.stringify(sent.body));
    assert.equal(smtp.messagesTo(to).length, 1);

    // A second "generate" while a key is active: flash + redirect, no new key.
    const again = await submit(agent, `/admin/apps/${id}`, `/admin/apps/${id}/keys`, {});
    assert.equal(again.status, 303);
    assert.equal(again.headers.location, `/admin/apps/${id}`);
    const afterAgain = await agent.get(`/admin/apps/${id}`);
    assert.ok(afterAgain.text.includes('flash-error'));
    assert.equal((await keysRepo.listKeysForApp(deps.db, id)).length, 1);

    // Regenerate with a 1 hour grace period through the page's own form.
    const expected = /name="expected_key_id" value="(\d+)"/.exec(afterAgain.text);
    assert.ok(expected, 'the regenerate form carries the active key id');
    const regen = await agent
      .post(`/admin/apps/${id}/keys/regenerate`)
      .type('form')
      .send({ _csrf: csrfFrom(afterAgain.text), grace: '3600', expected_key_id: expected[1] });
    assert.equal(regen.status, 200, regen.text);
    assert.equal(regen.headers['cache-control'], 'no-store');
    const newKey = KEY_PATTERN.exec(regen.text)[0];
    assert.notEqual(newKey, key);
    for (const k of [key, newKey]) {
      const res = await h.postV1(httpApp, k, { to: h.uniqueEmail(), subject: 'Grace', text: 'hi' });
      assert.equal(res.status, 200, 'old and new key work during the grace period');
    }

    // Re-submitting the same form (browser refresh) creates no further key.
    const replay = await agent
      .post(`/admin/apps/${id}/keys/regenerate`)
      .type('form')
      .send({ _csrf: csrfFrom(afterAgain.text), grace: '3600', expected_key_id: expected[1] });
    assert.equal(replay.status, 303);
    assert.equal((await keysRepo.listKeysForApp(deps.db, id)).length, 2);
  });

  it('sends a test email and reports the result', T, async (t) => {
    if (!h.requireDb(t)) return;
    const agent = await signedIn(owner);
    // Disabled apps can still send test emails.
    const { id, form } = await createAppViaForm(agent, { enabled: '' });
    assert.equal((await appsRepo.getApp(deps.db, id)).enabled, false);

    const to = h.uniqueEmail('test-recipient');
    const res = await submit(agent, `/admin/apps/${id}`, `/admin/apps/${id}/test`, { to });
    assert.equal(res.status, 303);
    assert.equal(res.headers.location, `/admin/apps/${id}`);
    const [msg] = smtp.messagesTo(to);
    assert.ok(msg, 'the test email was delivered');
    assert.equal(msg.parsed.subject, `Relay test: ${form.name}`);
    assert.equal(msg.parsed.from.value[0].address, form.from_email);
    assert.ok((await agent.get(`/admin/apps/${id}`)).text.includes('flash-success'));

    const rows = await h.listMessages(deps, id);
    assert.equal(rows.at(-1).source, 'test');
    assert.equal(rows.at(-1).status, 'sent');
    const audited = (await auditFor(id)).find((r) => r.action === 'app.test_email');
    assert.deepEqual(audited.details, { to, ok: true });
    assert.equal(audited.adminUserId, owner.id);

    smtp.setFailure(550);
    let failed;
    try {
      failed = await submit(agent, `/admin/apps/${id}`, `/admin/apps/${id}/test`, { to: h.uniqueEmail() });
    } finally {
      smtp.setFailure(null);
    }
    assert.equal(failed.status, 303);
    const failPage = await agent.get(`/admin/apps/${id}`);
    assert.ok(failPage.text.includes('flash-error'));
    assert.ok(failPage.text.includes('550'));
    assert.equal((await h.listMessages(deps, id)).at(-1).status, 'failed');

    const invalid = await submit(agent, `/admin/apps/${id}`, `/admin/apps/${id}/test`, { to: 'not an address' });
    assert.equal(invalid.status, 303);
    assert.ok((await agent.get(`/admin/apps/${id}`)).text.includes('flash-error'));
  });

  it("shows today's sent and failed counts on the apps list and the stats page", T, async (t) => {
    if (!h.requireDb(t)) return;
    const agent = await signedIn(owner);
    const { app, key } = await h.insertTestApp(deps, { smtp });
    const send = (to) => h.postV1(httpApp, key, { to, subject: 's', text: 't' });
    assert.equal((await send(h.uniqueEmail())).status, 200);
    smtp.setFailure(550);
    try {
      assert.equal((await send(h.uniqueEmail())).status, 502);
    } finally {
      smtp.setFailure(null);
    }
    assert.equal((await send('not an address')).status, 400);
    // One more sent message turned into an unknown outcome.
    const unknown = await send(h.uniqueEmail());
    assert.equal(unknown.status, 200);
    await deps.db.query("UPDATE messages SET status = 'unknown' WHERE public_id = ?", [unknown.body.id]);

    const today = localDay(deps.clock.now(), deps.config.timezone);
    assert.deepEqual((await countsForDay(deps.db, today)).get(app.id), { sent: 1, failed: 3 });
    assert.deepEqual(await statsByDay(deps.db, { fromDay: today, toDay: today, appId: app.id }), [
      { day: today, appId: app.id, appName: app.name, sent: 1, failed: 1, rejected: 1, unknown: 1 },
    ]);

    const list = await agent.get('/admin');
    assert.equal(list.status, 200);
    const row = list.text.split('<tr>').find((chunk) => chunk.includes(`href="/admin/apps/${app.id}"`));
    assert.ok(row, 'the app has a row on the apps list');
    assert.match(row, /status=sent[^"]*">1<\/a>/, 'sent today: 1');
    assert.match(row, /status=failed[^"]*"><span class="badge badge-off">3<\/span>/, 'failed today: 3');

    const stats = await agent.get(`/admin/stats?app=${app.id}`);
    assert.equal(stats.status, 200);
    assert.ok(stats.text.includes('failed 1 · rejected 1 · unknown 1'), 'the failed breakdown');
    const totals = stats.text.slice(stats.text.indexOf('<tfoot>'));
    assert.ok(totals.includes('<strong>1</strong>'), 'total sent');
    assert.ok(totals.includes('<strong>3</strong>'), 'total failed');
  });

  it('shows sign-in attempts as anonymous in the audit log, CLI actions as system', T, async (t) => {
    if (!h.requireDb(t)) return;
    const agent = await signedIn(owner);
    const attempted = h.uniqueEmail('intruder', 'relay-test.example.com');
    const failedLogin = await login(newAgent(), attempted, 'wrong password');
    assert.equal(failedLogin.status, 401);
    const created = await createAdmin(); // admin.create by the system actor

    // Parallel test files write audit rows too: look through a few pages.
    async function findRow(predicate) {
      for (let page = 1; page <= 10; page++) {
        const res = await agent.get(`/admin/audit?page=${page}`);
        assert.equal(res.status, 200);
        const found = res.text.split('<tr>').find(predicate);
        if (found) return found;
      }
      return null;
    }
    const anonymous = await findRow((c) => c.includes('auth.login_failed') && c.includes(attempted));
    assert.ok(anonymous, 'the failed sign-in is listed');
    assert.ok(anonymous.includes('anonymous'));
    assert.doesNotMatch(anonymous, /\bsystem\b/);

    const target = new RegExp(`admin #${created.id}\\s*<`);
    const system = await findRow((c) => c.includes('admin.create') && target.test(c));
    assert.ok(system, 'the CLI-style admin creation is listed');
    assert.match(system, /\bsystem\b/);
    assert.ok(!system.includes('anonymous'));
  });

  it('renders the other admin pages', T, async (t) => {
    if (!h.requireDb(t)) return;
    const ip = h.uniqueIp();
    const agent = request.agent(httpApp).set('X-Forwarded-For', ip);
    assert.equal((await login(agent, owner.email, owner.password)).status, 303);
    const { app } = await h.insertTestApp(deps, { smtp });
    for (const path of [
      '/admin',
      '/admin/logs',
      `/admin/logs?status=failed&app=${app.id}`,
      '/admin/stats',
      '/admin/stats?days=90',
      '/admin/audit',
      '/admin/users',
      '/admin/account',
      '/admin/system',
      `/admin/apps/${app.id}`,
    ]) {
      const res = await agent.get(path);
      assert.equal(res.status, 200, `GET ${path}`);
      assert.match(res.headers['content-type'], /text\/html/);
      assert.equal(res.headers['cache-control'], 'no-store', path);
    }
    // Rejected requests over an app's flood ceiling are only counted
    // (rejdrop:<appId>:<day>); the System page lists today's count per app.
    const now = deps.clock.now();
    const dropKey = `rejdrop:${app.id}:${localDay(now, deps.config.timezone)}`;
    for (let i = 0; i < 2; i++) await incrementCounter(deps.db, dropKey, new Date(now.getTime() + 72 * HOUR));
    const system = await agent.get('/admin/system');
    assert.equal(system.status, 200);
    assert.match(system.text, new RegExp(`href="/admin/apps/${app.id}">[^<]*</a> <span class="mono">2</span>`));

    const ipCheck = await agent.get('/admin/system/ip-check');
    assert.equal(ipCheck.status, 200);
    assert.deepEqual(ipCheck.body, { ip });
    assert.equal((await agent.get('/admin/apps/999999999')).status, 404);
  });
});

describe('two-factor sign-in', () => {
  const ctx = {};
  const { createAdmin, newAgent, login, signedIn } = toolsFor(ctx);
  let tfa; // { id, email, password } with two-factor on
  let secret;

  const stepNow = () => Math.floor(ctx.deps.clock.now().getTime() / 30000);

  async function codeStep(agent, code) {
    const page = await agent.get('/admin/login/2fa');
    assert.equal(page.status, 200, 'GET /admin/login/2fa');
    return agent.post('/admin/login/2fa').type('form').send({ _csrf: csrfFrom(page.text), code });
  }

  async function passwordStep(admin) {
    const agent = newAgent();
    const res = await login(agent, admin.email, admin.password);
    assert.equal(res.status, 303);
    assert.equal(res.headers.location, '/admin/login/2fa');
    return agent;
  }

  before(async () => {
    if (!h.dbAvailable()) return;
    ctx.deps = h.createTestDeps({ clock: h.createFakeClock(new Date()) });
    ctx.httpApp = h.createHttpApp(ctx.deps);
    // A fresh admin: turning two-factor on bumps the session epoch.
    tfa = await createAdmin();
    // Turned on through the real account forms (setup, then a code).
    const agent = await signedIn(tfa);
    const account = await agent.get('/admin/account');
    const setup = await agent
      .post('/admin/account/totp/setup')
      .type('form')
      .send({ _csrf: csrfFrom(account.text), current_password: tfa.password });
    assert.equal(setup.status, 200);
    secret = /<span id="totp-secret" hidden>([A-Z2-7]+)<\/span>/.exec(setup.text)[1];
    const enable = await agent
      .post('/admin/account/totp/enable')
      .type('form')
      .send({ _csrf: csrfFrom(setup.text), code: totpAt(secret, stepNow()) });
    assert.equal(enable.status, 303);
    assert.equal((await adminsRepo.getAdmin(ctx.deps.db, tfa.id)).totpEnabled, true);
  });

  after(async () => {
    if (ctx.deps) await ctx.deps.db.close();
  });

  it('a password alone does not sign in a two-factor admin', T, async (t) => {
    if (!h.requireDb(t)) return;
    const agent = await passwordStep(tfa);
    const home = await agent.get('/admin');
    assert.equal(home.status, 302);
    assert.equal(locationOf(home).pathname, '/admin/login');
  });

  it('refuses a wrong code, signs in with a valid one, and never accepts a code twice', T, async (t) => {
    if (!h.requireDb(t)) return;
    // The enable step used the current step's code; the next step's is still valid (window 1).
    const s = stepNow();
    const code = totpAt(secret, s + 1);
    const agent = await passwordStep(tfa);
    const failedBefore = (await listAudit(ctx.deps.db, { targetType: 'admin', targetId: String(tfa.id), limit: 100, offset: 0 }))
      .rows.filter((r) => r.action === 'auth.totp_failed').length;
    const wrong = await codeStep(agent, wrongCode(secret, [s - 1, s, s + 1]));
    assert.equal(wrong.status, 401);
    const failedAfter = (await listAudit(ctx.deps.db, { targetType: 'admin', targetId: String(tfa.id), limit: 100, offset: 0 }))
      .rows.filter((r) => r.action === 'auth.totp_failed').length;
    assert.equal(failedAfter, failedBefore + 1, 'auth.totp_failed audited');

    const ok = await codeStep(agent, code);
    assert.equal(ok.status, 303);
    assert.equal(ok.headers.location, '/admin');
    assert.equal((await agent.get('/admin')).status, 200);

    // The same code in another session (a replay) is refused.
    const other = await passwordStep(tfa);
    const replay = await codeStep(other, code);
    assert.equal(replay.status, 401);
    assert.equal((await other.get('/admin')).status, 302);
  });

  it('one fresh code sent by three sessions at once signs in exactly one', T, async (t) => {
    if (!h.requireDb(t)) return;
    ctx.deps.clock.advance(2 * 30000);
    const code = totpAt(secret, stepNow());
    const agents = [];
    for (let i = 0; i < 3; i++) agents.push(await passwordStep(tfa));
    const pages = await Promise.all(agents.map((a) => a.get('/admin/login/2fa')));
    const results = await Promise.all(
      agents.map((a, i) => a.post('/admin/login/2fa').type('form').send({ _csrf: csrfFrom(pages[i].text), code }))
    );
    assert.deepEqual(
      results.map((r) => r.status).sort(),
      [303, 401, 401]
    );
  });

  it('sends the code page back to the password step without a pending sign-in', T, async (t) => {
    if (!h.requireDb(t)) return;
    const res = await newAgent().get('/admin/login/2fa');
    assert.equal(res.status, 303);
    assert.equal(locationOf(res).pathname, '/admin/login');
  });

  it('a pending sign-in expires after 5 minutes', T, async (t) => {
    if (!h.requireDb(t)) return;
    const agent = await passwordStep(tfa);
    const page = await agent.get('/admin/login/2fa');
    ctx.deps.clock.advance(5 * MINUTE + 1000);
    const res = await agent
      .post('/admin/login/2fa')
      .type('form')
      .send({ _csrf: csrfFrom(page.text), code: totpAt(secret, stepNow()) });
    assert.equal(res.status, 303);
    assert.equal(locationOf(res).pathname, '/admin/login');
    assert.equal((await agent.get('/admin')).status, 302);
  });

  it('limits code attempts to 10 per 15 minutes per admin', T, async (t) => {
    if (!h.requireDb(t)) return;
    const a = await createAdmin();
    const aSecret = await admins.beginTotpSetup(ctx.deps, { adminId: a.id, actor: h.SYSTEM_ACTOR });
    const s = stepNow();
    await admins.enableTotp(ctx.deps, { adminId: a.id, code: totpAt(aSecret, s), actor: h.SYSTEM_ACTOR });
    const agent = await passwordStep(a);
    const wrong = wrongCode(aSecret, [s - 1, s, s + 1]);
    for (let i = 0; i < 10; i++) assert.equal((await codeStep(agent, wrong)).status, 401, `code ${i + 1}`);
    const limited = await codeStep(agent, totpAt(aSecret, s + 1));
    assert.equal(limited.status, 429, 'even a valid code is refused now');
    assert.ok(limited.text.includes(THROTTLED));
    const { rows } = await listAudit(ctx.deps.db, { targetType: 'admin', targetId: String(a.id), limit: 100, offset: 0 });
    const throttled = rows.filter((r) => r.action === 'auth.login_throttled');
    assert.equal(throttled.length, 1);
    assert.equal(throttled[0].details.bucket, 'totp');
  });

  it('turning two-factor off needs the password and ends the other sessions', T, async (t) => {
    if (!h.requireDb(t)) return;
    const b = await createAdmin();
    const bSecret = await admins.beginTotpSetup(ctx.deps, { adminId: b.id, actor: h.SYSTEM_ACTOR });
    await admins.enableTotp(ctx.deps, { adminId: b.id, code: totpAt(bSecret, stepNow()), actor: h.SYSTEM_ACTOR });
    // Two full sign-ins, each with the code of a later time step.
    const signIn = async () => {
      ctx.deps.clock.advance(30000);
      const agent = await passwordStep(b);
      const res = await codeStep(agent, totpAt(bSecret, stepNow()));
      assert.equal(res.status, 303);
      return agent;
    };
    const here = await signIn();
    const elsewhere = await signIn();
    assert.equal((await elsewhere.get('/admin')).status, 200);

    const account = await here.get('/admin/account');
    const refused = await here
      .post('/admin/account/totp/disable')
      .type('form')
      .send({ _csrf: csrfFrom(account.text), current_password: 'not my password' });
    assert.equal(refused.status, 400);
    assert.equal((await adminsRepo.getAdmin(ctx.deps.db, b.id)).totpEnabled, true);

    const off = await here
      .post('/admin/account/totp/disable')
      .type('form')
      .send({ _csrf: csrfFrom(account.text), current_password: b.password });
    assert.equal(off.status, 303);
    const row = await adminsRepo.getAdmin(ctx.deps.db, b.id);
    assert.equal(row.totpEnabled, false);
    assert.equal(row.totpSecretEnc, null, 'the secret is deleted');
    assert.equal((await here.get('/admin')).status, 200, 'this session stays signed in');
    assert.equal((await elsewhere.get('/admin')).status, 302, 'the other session ends');

    const passwordOnly = await login(newAgent(), b.email, b.password);
    assert.equal(passwordOnly.status, 303);
    assert.equal(passwordOnly.headers.location, '/admin', 'no code step any more');
    const { rows } = await listAudit(ctx.deps.db, { targetType: 'admin', targetId: String(b.id), limit: 50, offset: 0 });
    assert.ok(rows.some((r) => r.action === 'admin.totp_disable'));
  });

  it('claims each time step at most once (claimTotpStep)', T, async (t) => {
    if (!h.requireDb(t)) return;
    const a = await createAdmin();
    const now = ctx.deps.clock.now();
    const s = stepNow();
    assert.equal((await adminsRepo.getAdmin(ctx.deps.db, a.id)).totpLastStep, null);
    assert.equal(await adminsRepo.claimTotpStep(ctx.deps.db, a.id, s, now), true, 'no step used yet');
    assert.equal(await adminsRepo.claimTotpStep(ctx.deps.db, a.id, s, now), false, 'the same step again');
    assert.equal(await adminsRepo.claimTotpStep(ctx.deps.db, a.id, s - 1, now), false, 'an older step');
    assert.equal(await adminsRepo.claimTotpStep(ctx.deps.db, a.id, s + 1, now), true, 'a newer step');
    assert.equal((await adminsRepo.getAdmin(ctx.deps.db, a.id)).totpLastStep, s + 1);
  });
});

describe('session lifetime', () => {
  it('ends a session after SESSION_ABSOLUTE_HOURS even while it is in use', T, async (t) => {
    if (!h.requireDb(t)) return;
    // An idle limit longer than the absolute one, so only the absolute rule can
    // end the session. (The store row's expiry follows the cookie, which
    // express-session computes from the real clock.)
    await withOwnRelay({ sessionIdleMinutes: 24 * 60 }, async (relay) => {
      const agent = await relay.signedIn(await relay.createAdmin());
      relay.deps.clock.advance(relay.deps.config.sessionAbsoluteHours * HOUR - MINUTE);
      assert.equal((await agent.get('/admin')).status, 200, 'still valid just before the limit');
      relay.deps.clock.advance(2 * MINUTE);
      const res = await agent.get('/admin/logs');
      assert.equal(res.status, 302);
      const target = locationOf(res);
      assert.equal(target.pathname, '/admin/login');
      assert.equal(target.searchParams.get('expired'), '1');
      assert.equal(target.searchParams.get('next'), '/admin/logs');
      assert.equal((await agent.get('/admin')).status, 302, 'the session stays dead');
    });
  });

  it('does not honour a session row whose expiry has passed', T, async (t) => {
    if (!h.requireDb(t)) return;
    await withOwnRelay(undefined, async (relay) => {
      const admin = await relay.createAdmin();
      const agent = relay.newAgent();
      const res = await relay.login(agent, admin.email, admin.password);
      assert.equal(res.status, 303);
      assert.equal((await agent.get('/admin')).status, 200);
      const rowId = sha256Hex(sidFrom(res));
      const past = Math.floor(relay.deps.clock.now().getTime() / 1000) - 1;
      const updated = await relay.deps.db.query('UPDATE sessions SET expires = ? WHERE session_id = ?', [past, rowId]);
      assert.equal(updated.affectedRows, 1);
      const home = await agent.get('/admin');
      assert.equal(home.status, 302);
      assert.equal(locationOf(home).pathname, '/admin/login');
    });
  });

  it('ends a session after SESSION_IDLE_MINUTES without requests', T, async (t) => {
    if (!h.requireDb(t)) return;
    await withOwnRelay(undefined, async (relay) => {
      const agent = await relay.signedIn(await relay.createAdmin());
      relay.deps.clock.advance((relay.deps.config.sessionIdleMinutes - 1) * MINUTE);
      assert.equal((await agent.get('/admin')).status, 200);
      relay.deps.clock.advance((relay.deps.config.sessionIdleMinutes + 1) * MINUTE);
      assert.equal((await agent.get('/admin')).status, 302);
    });
  });

  it('shows an expired sign-in form again instead of the 403 page', T, async (t) => {
    if (!h.requireDb(t)) return;
    await withOwnRelay(undefined, async (relay) => {
      const admin = await relay.createAdmin();
      const agent = relay.newAgent();

      // Within 30 minutes the form still works.
      let page = await agent.get('/admin/login');
      relay.deps.clock.advance(29 * MINUTE);
      const inTime = await agent
        .post('/admin/login')
        .type('form')
        .send({ _csrf: csrfFrom(page.text), email: admin.email, password: admin.password });
      assert.equal(inTime.status, 303);

      // After 30 minutes the anonymous session behind the form is gone.
      const late = relay.newAgent();
      page = await late.get('/admin/login');
      relay.deps.clock.advance(31 * MINUTE);
      const expired = await late
        .post('/admin/login')
        .type('form')
        .send({ _csrf: csrfFrom(page.text), email: admin.email.toUpperCase(), password: admin.password, next: '/admin/logs' });
      assert.equal(expired.status, 403);
      assert.ok(expired.text.includes(FORM_EXPIRED));
      assert.ok(!expired.text.includes(INVALID_FORM));
      assert.ok(expired.text.includes(`value="${admin.email}"`), 'the typed email is kept');
      const fresh = csrfFrom(expired.text);
      assert.notEqual(fresh, csrfFrom(page.text));

      const retry = await late
        .post('/admin/login')
        .type('form')
        .send({ _csrf: fresh, email: admin.email, password: admin.password, next: '/admin/logs' });
      assert.equal(retry.status, 303);
      assert.equal(retry.headers.location, '/admin/logs');
    });
  });
});
