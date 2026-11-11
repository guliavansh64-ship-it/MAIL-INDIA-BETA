'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const crypto = require('node:crypto');
const { createApp, hashKey } = require('../src/app');
const { createLocalDatabase } = require('../src/local-dev');
const { createFirebaseAuth } = require('../src/firebase-sync');
const { SystemMailError } = require('../src/system-mail');

function fixture(options = {}) {
  const db = createLocalDatabase();
  const user = { uid: 'member', email: 'member@example.com', email_verified: false, auth_time: Math.floor(Date.now() / 1000) };
  let sessionsCreated = 0;
  const auth = {
    async verifyIdToken(token) {
      if (token === 'unverified') return { ...user };
      if (token === 'verified') return { ...user, email_verified: true };
      if (token === 'missing-claim') { const result = { ...user }; delete result.email_verified; return result; }
      throw new Error('Invalid ID token');
    },
    async verifySessionCookie(token) {
      if (token === 'old-unverified-session') return { ...user };
      if (token === 'verified-session') return { ...user, email_verified: true };
      throw new Error('Invalid session');
    },
    async createSessionCookie(token) { assert.equal(token, 'verified'); sessionsCreated++; return 'verified-session'; },
    async revokeRefreshTokens() {}
  };
  const systemMailer = options.systemMailer || { async sendVerificationEmail() { return { messageId: 'test-message' }; } };
  const app = createApp({ db, auth, publicConfig: { firebaseApiKey: 'test-firebase-web-key' }, ...options, systemMailer });
  return { app, db, auth, user, systemMailer, sessionsCreated: () => sessionsCreated };
}
const bearer = token => ({ Authorization: 'Bearer ' + token });

test('unverified onboarding saves profile without granting a session, wallet or app access', async () => {
  const { app, db, sessionsCreated } = fixture();
  let res = await request(app).post('/api/session/bootstrap').set(bearer('unverified')).send({ name: 'Pending Member' });
  assert.equal(res.status, 200);
  assert.equal(res.body.user.emailVerified, false);
  assert.equal(res.body.user.admin, false);
  assert.equal(res.headers['set-cookie'], undefined);
  assert.equal(db.root.users.member.emailVerified, false);
  assert.equal(db.root.wallets, undefined);
  for (const token of ['unverified', 'missing-claim']) {
    res = await request(app).post('/api/session/login').set(bearer(token));
    assert.equal(res.status, 403);
    assert.equal(res.body.error, 'EMAIL_NOT_VERIFIED');
    assert.equal(res.headers['set-cookie'], undefined);
  }
  assert.equal(sessionsCreated(), 0);
  for (const endpoint of ['/api/session/status', '/api/me', '/api/profile', '/api/keys', '/api/contacts', '/api/payments/history', '/api/admin/users', '/api/gmail/status']) {
    res = await request(app).get(endpoint).set(bearer('unverified'));
    assert.equal(res.status, 403, endpoint);
    assert.equal(res.body.error, 'EMAIL_NOT_VERIFIED', endpoint);
  }
});

test('old unverified cookies and session bearer tokens cannot restore access', async () => {
  const { app } = fixture();
  for (const headers of [{ Cookie: 'mb_session=old-unverified-session' }, bearer('old-unverified-session')]) {
    for (const endpoint of ['/api/session/status', '/api/me', '/api/gmail/status']) {
      const res = await request(app).get(endpoint).set(headers);
      assert.equal(res.status, 403);
      assert.equal(res.body.error, 'EMAIL_NOT_VERIFIED');
    }
  }
  const connect = await request(app).get('/oauth/gmail/connect').set(bearer('unverified'));
  assert.equal(connect.status, 302);
  assert.match(connect.headers.location, /account\.html\?error=/);
  const mutation = await request(app).post('/api/gmail/disconnect').set('Cookie', 'mb_session=old-unverified-session');
  assert.equal(mutation.status, 403);
  assert.equal(mutation.body.error, 'EMAIL_NOT_VERIFIED');
});

test('a refreshed verified ID token permits login and reports verified status', async () => {
  const { app, db, sessionsCreated } = fixture();
  await request(app).post('/api/session/bootstrap').set(bearer('unverified'));
  let res = await request(app).post('/api/session/bootstrap').set(bearer('verified'));
  assert.equal(res.body.user.emailVerified, true);
  assert.equal(db.root.users.member.emailVerified, true);
  res = await request(app).post('/api/session/login').set(bearer('verified'));
  assert.equal(res.status, 200);
  assert.equal(res.body.emailVerified, true);
  assert.equal(sessionsCreated(), 1);
  const cookie = res.headers['set-cookie'].map(value => value.split(';')[0]).join('; ');
  for (const endpoint of ['/api/session/status', '/api/me']) {
    res = await request(app).get(endpoint).set('Cookie', cookie);
    assert.equal(res.status, 200);
    assert.equal(res.body.user.emailVerified, true);
  }
});

test('an existing API key is denied until the stored account is verified', async () => {
  const { app, db } = fixture();
  const key = 'mb_live_' + crypto.randomBytes(32).toString('base64url');
  await db.ref('users/member').set({ email: 'member@example.com', status: 'active', emailVerified: false });
  await db.ref('key_index/' + hashKey(key)).set({ uid: 'member', keyId: 'old-key', status: 'active' });
  let res = await request(app).get('/v1/account/balance').set(bearer(key));
  assert.equal(res.status, 403);
  assert.equal(res.body.error, 'EMAIL_NOT_VERIFIED');
  await request(app).post('/api/session/bootstrap').set(bearer('verified'));
  res = await request(app).get('/v1/account/balance').set(bearer(key));
  assert.equal(res.status, 200);
});

test('verification email requires an authentic unverified Firebase ID token', async t => {
  const { app, systemMailer } = fixture();
  const send = t.mock.method(systemMailer, 'sendVerificationEmail', async () => { throw new Error('Must not send'); });
  for (const body of [{ email: 'arbitrary@example.com' }, { idToken: 'invalid' }, { idToken: 'old-unverified-session' }]) {
    const res = await request(app).post('/api/auth/send-verification-email').send(body);
    assert.equal(res.status, 401);
    assert.equal(res.body.success, false);
  }
  const verified = await request(app).post('/api/auth/send-verification-email').set(bearer('verified'));
  assert.equal(verified.status, 409);
  assert.equal(verified.body.error, 'EMAIL_ALREADY_VERIFIED');
  assert.equal(send.mock.callCount(), 0);
});

test('verification dispatch awaits one Gmail mailer response and uses token identity without leaking links', async t => {
  const { app, systemMailer } = fixture();
  let release;
  let announce;
  const started = new Promise(resolve => { announce = resolve; });
  const send = t.mock.method(systemMailer, 'sendVerificationEmail', async options => {
    assert.deepEqual(options, { email: 'member@example.com' });
    announce();
    return new Promise(resolve => { release = () => resolve({ messageId: 'private-provider-id', actionLink: 'https://example.test/?oobCode=private-action-code', smtpResponse: 'private-provider-response' }); });
  });
  t.mock.method(globalThis, 'fetch', async () => { throw new Error('Verification route must use the injected Gmail mailer'); });
  let completed = false;
  const pending = request(app).post('/api/auth/send-verification-email').set(bearer('unverified')).send({ email: 'attacker@example.com', idToken: 'ignored-body-token' }).then(res => { completed = true; return res; });
  await started;
  assert.equal(completed, false);
  release();
  const res = await pending;
  assert.equal(res.status, 200);
  assert.equal(res.body.success, true);
  assert.equal(res.body.email, 'member@example.com');
  assert.equal(res.body.provider, 'gmail_smtp');
  assert.deepEqual(Object.keys(res.body).sort(), ['email', 'message', 'provider', 'success']);
  assert.equal(JSON.stringify(res.body).includes('private-'), false);
  assert.equal(send.mock.callCount(), 1);
});

test('verification accepts body ID tokens and throttles repeated sends for that user', async t => {
  const { app, systemMailer } = fixture();
  const send = t.mock.method(systemMailer, 'sendVerificationEmail', async () => ({ messageId: 'sent-once' }));
  const first = await request(app).post('/api/auth/send-verification-email').send({ idToken: 'unverified' });
  assert.equal(first.status, 200);
  const second = await request(app).post('/api/auth/send-verification-email').set(bearer('unverified'));
  assert.equal(second.status, 429);
  assert.equal(second.body.error, 'RATE_LIMIT_EXCEEDED');
  assert.ok(Number(second.headers['retry-after']) > 0);
  assert.equal(send.mock.callCount(), 1);
});

test('Gmail setup and provider failures never report verification success', async t => {
  for (const [code, status] of [['SYSTEM_SENDER_UNAVAILABLE', 503], ['SMTP_AUTH_FAILED', 502], ['SYSTEM_SENDER_QUOTA_EXCEEDED', 429], ['VERIFICATION_LINK_FAILED', 503]]) {
    await t.test(code, async () => {
      const { app } = fixture({ systemMailer: { async sendVerificationEmail() { throw new SystemMailError(code, 'Safe setup or mail failure.', status); } } });
      const res = await request(app).post('/api/auth/send-verification-email').set(bearer('unverified'));
      assert.equal(res.status, status);
      assert.equal(res.body.success, false);
      assert.equal(res.body.error, code);
      if (status === 429) assert.equal(res.headers['retry-after'], '60');
    });
  }
  await t.test('unexpected failure is sanitized', async () => {
    const { app } = fixture({ systemMailer: { async sendVerificationEmail() { throw new Error('private-password and private-action-link'); } } });
    const res = await request(app).post('/api/auth/send-verification-email').set(bearer('unverified'));
    assert.equal(res.status, 502);
    assert.equal(res.body.success, false);
    assert.equal(res.body.error, 'VERIFICATION_SEND_FAILED');
    assert.equal(JSON.stringify(res.body).includes('private-'), false);
  });
});

test('unknown SMTP outcomes are exposed without claiming delivery or leaking provider details', async () => {
  const { app } = fixture({ systemMailer: { async sendVerificationEmail() {
    throw new SystemMailError('SMTP_OUTCOME_UNCERTAIN', 'Check your inbox before requesting another email.', 502, true);
  } } });
  const res = await request(app).post('/api/auth/send-verification-email').set(bearer('unverified'));
  assert.equal(res.status, 502);
  assert.equal(res.body.success, false);
  assert.equal(res.body.error, 'SMTP_OUTCOME_UNCERTAIN');
  assert.equal(res.body.uncertain, true);
});

test('unavailable Admin credentials are a setup error and never call the mailer', async t => {
  const { app, auth, systemMailer } = fixture();
  t.mock.method(auth, 'verifyIdToken', async () => { throw Object.assign(new Error('Credential details stay internal'), { code: 'AUTH_UNAVAILABLE' }); });
  const send = t.mock.method(systemMailer, 'sendVerificationEmail', async () => {});
  const res = await request(app).post('/api/auth/send-verification-email').set(bearer('unverified'));
  assert.equal(res.status, 503);
  assert.equal(res.body.error, 'AUTH_UNAVAILABLE');
  assert.equal(res.body.success, false);
  assert.equal(send.mock.callCount(), 0);
});

test('health reflects Admin connection failure while public Firebase setup remains available', async () => {
  const connections = {
    database: { provider: 'firebase-realtime-database', state: 'unavailable', configured: false, reason: 'ADMIN_CREDENTIALS_UNAVAILABLE', checkedAt: Date.now() },
    authentication: { provider: 'firebase-auth', state: 'unavailable', configured: false, reason: 'ADMIN_CREDENTIALS_UNAVAILABLE' }
  };
  const { app } = fixture({
    connectionStatus: () => connections,
    sendingConfig: { enabled: true }, sendQueue: { async add() {} },
    publicConfig: { firebaseConfig: { apiKey: 'public-web-key', projectId: 'configured-project', databaseURL: 'https://configured-project-default-rtdb.firebaseio.com' } }
  });
  const degraded = await request(app).get('/api/health');
  assert.equal(degraded.status, 503);
  assert.equal(degraded.body.status, 'degraded');
  assert.equal(degraded.body.database.reason, 'ADMIN_CREDENTIALS_UNAVAILABLE');
  assert.equal(degraded.body.sending, 'unavailable');
  const config = await request(app).get('/api/config');
  assert.equal(config.status, 200);
  assert.equal(config.body.firebaseConfig.projectId, 'configured-project');
  assert.equal(config.body.firebaseConfig.apiKey, 'public-web-key');
  connections.database.state = 'connected';
  connections.database.reason = null;
  connections.authentication.state = 'ready';
  connections.authentication.reason = null;
  const ready = await request(app).get('/api/health');
  assert.equal(ready.status, 200);
  assert.equal(ready.body.status, 'ok');
  assert.equal(ready.body.database.state, 'connected');
});

test('a failed verification dispatch can be retried before the successful-send cooldown', async t => {
  const { app, systemMailer } = fixture();
  let attempts = 0;
  const send = t.mock.method(systemMailer, 'sendVerificationEmail', async () => {
    attempts++;
    if (attempts === 1) throw new SystemMailError('SMTP_CONNECTION_FAILED', 'Could not connect to Gmail SMTP.', 502);
    return { messageId: 'successful-retry' };
  });
  const failed = await request(app).post('/api/auth/send-verification-email').set(bearer('unverified'));
  assert.equal(failed.status, 502);
  assert.equal(failed.body.success, false);
  const retry = await request(app).post('/api/auth/send-verification-email').set(bearer('unverified'));
  assert.equal(retry.status, 200);
  assert.equal(retry.body.email, 'member@example.com');
  const throttled = await request(app).post('/api/auth/send-verification-email').set(bearer('unverified'));
  assert.equal(throttled.status, 429);
  assert.equal(throttled.body.error, 'RATE_LIMIT_EXCEEDED');
  assert.equal(send.mock.callCount(), 2);
});

test('verification dispatch validates a signed token without waiting for the database', async t => {
  const jwt = require('jsonwebtoken');
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const keyId = 'local-verification-key';
  const idToken = jwt.sign({
    sub: 'pending-member',
    email: 'pending@example.com',
    email_verified: false,
    auth_time: Math.floor(Date.now() / 1000)
  }, privateKey, {
    algorithm: 'RS256', keyid: keyId, audience: 'verification-test-project',
    issuer: 'https://securetoken.google.com/verification-test-project', expiresIn: '5m'
  });
  let databaseReads = 0;
  const db = { ref() { return { get() { databaseReads++; return new Promise(() => {}); } }; } };
  const auth = createFirebaseAuth({ projectId: 'verification-test-project', db });
  let dispatchRequests = 0;
  const systemMailer = { async sendVerificationEmail(options) { assert.deepEqual(options, { email: 'pending@example.com' }); dispatchRequests++; return { messageId: 'signed-token-mail' }; } };
  const app = createApp({ db, auth, systemMailer, publicConfig: { firebaseApiKey: 'test-key' } });
  const timeoutDurations = [];
  const createTimeout = AbortSignal.timeout;
  t.mock.method(AbortSignal, 'timeout', duration => {
    timeoutDurations.push(duration);
    return createTimeout.call(AbortSignal, duration);
  });
  let certificateRequests = 0;
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    if (String(url).includes('/robot/v1/metadata/x509/')) {
      certificateRequests++;
      assert.ok(options.signal instanceof AbortSignal);
      return {
        ok: true, headers: { get: () => 'max-age=0' },
        json: async () => ({ [keyId]: publicKey.export({ type: 'spki', format: 'pem' }) })
      };
    }
    throw new Error('Unexpected network request: only certificate fetching is mocked.');
  });
  const res = await request(app).post('/api/auth/send-verification-email')
    .set(bearer(idToken)).timeout({ response: 1500, deadline: 2000 });
  assert.equal(res.status, 200);
  assert.equal(res.body.email, 'pending@example.com');
  assert.equal(databaseReads, 0);
  assert.equal(certificateRequests, 1);
  assert.equal(dispatchRequests, 1);
  assert.ok(timeoutDurations.includes(10_000));
});

test('custom session signing rejects false and missing verification claims', async () => {
  const db = createLocalDatabase({ users: { pending: { email: 'pending@example.com' }, verified: { email: 'verified@example.com', emailVerified: true } } });
  const auth = createFirebaseAuth({ projectId: 'test-project', db, sessionSecret: crypto.randomBytes(32).toString('hex') });
  await assert.rejects(auth.createSessionCookie({ uid: 'pending', email: 'pending@example.com' }), /verified email/);
  await assert.rejects(auth.createSessionCookie({ uid: 'pending', email_verified: false }), /verified email/);
  await assert.rejects(auth.createSessionCookie('pending'), /verified email/);
  await assert.rejects(auth.createSessionCookie('unknown'), /verified email/);
  const cookie = await auth.createSessionCookie('verified');
  assert.equal((await auth.verifySessionCookie(cookie)).email_verified, true);
});

test('Google sign-in fails closed without an explicitly verified provider email', async t => {
  for (const condition of [{ ok: true, verified_email: false }, { ok: true }, { ok: false, verified_email: true }]) {
    const { app, db } = fixture();
    const state = crypto.randomBytes(12).toString('hex');
    await db.ref('oauth_states/' + state).set({ type: 'google_signin', expiresAt: Date.now() + 60_000 });
    const fetchMock = t.mock.method(globalThis, 'fetch', async url => {
      if (String(url).includes('oauth2.googleapis.com/token')) return { ok: true, json: async () => ({ access_token: 'google-test-token' }) };
      assert.match(String(url), /oauth2\/v2\/userinfo/);
      return { ok: condition.ok, json: async () => ({ id: 'google-member', email: 'member@example.com', ...condition }) };
    });
    const res = await request(app).get('/oauth/google/callback?code=test-code&state=' + state);
    assert.equal(res.status, 302);
    assert.match(res.headers.location, /account\.html\?error=/);
    assert.equal(res.headers['set-cookie'], undefined);
    assert.equal(db.root.users, undefined);
    assert.equal(db.root.wallets, undefined);
    fetchMock.mock.restore();
  }
});

test('GET /api/auth/verify-action renders error page on missing email', async () => {
  const { app } = fixture();
  const res = await request(app).get('/api/auth/verify-action');
  assert.equal(res.status, 400);
  assert.match(res.text, /Invalid Verification Link/);
});

test('GET /api/auth/verify-action marks user verified and renders branded success page', async () => {
  const { app, db } = fixture();
  await db.ref('users/member').set({ email: 'member@example.com', emailVerified: false });
  const res = await request(app).get('/api/auth/verify-action?code=oob123&email=member@example.com');
  assert.equal(res.status, 200);
  assert.match(res.text, /Email Verified Successfully!/);
  assert.match(res.text, /MAIL INDIA/);
  assert.match(res.text, /account\.html\?verified=/);
  const snap = await db.ref('users/member').get();
  assert.equal(snap.val().emailVerified, true);
});
