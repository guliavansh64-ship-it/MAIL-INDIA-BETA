'use strict';
const { test, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const crypto = require('node:crypto');
const { createApp } = require('../src/app');
const {
  toBase64Url,
  buildMimeMessage,
  refreshAccessToken,
  getValidAccessToken,
  sendRawGmailMessage,
  sendViaConnectedGmail,
  disconnectUserGmail
} = require('../src/gmail-api');
const { encryptCredentials, decryptCredentials } = require('../src/sending');

function memoryDb() {
  const root = {
    users: {
      userA: { uid: 'userA', email: 'alice@example.com', status: 'active', email_verified: true, name: 'Alice' },
      userB: { uid: 'userB', email: 'bob@example.com', status: 'active', email_verified: true, name: 'Bob' },
      adminUid: { uid: 'adminUid', email: 'guliavansh64@gmail.com', status: 'active', email_verified: true, name: 'Admin', admin: true }
    },
    wallets: {
      userA: { balance: 10, reserved: 0, purchased: 10, consumed: 0, sendRequests: {} },
      userB: { balance: 10, reserved: 0, purchased: 10, consumed: 0, sendRequests: {} }
    },
    oauth_states: {},
    gmail_connections: {},
    key_index: {},
    user_api_keys: {},
    sender_accounts: {},
    sender_assignments: {},
    suppression_list: {}
  };

  function get(p) {
    return p.split('/').filter(Boolean).reduce((v, k) => v?.[k], root);
  }

  function put(p, v) {
    const a = p.split('/').filter(Boolean), k = a.pop();
    let x = root;
    for (const n of a) x = x[n] ??= {};
    if (v === null || v === undefined) delete x[k];
    else x[k] = structuredClone(v);
  }

  function snap(v, key) {
    return {
      key,
      val: () => structuredClone(v),
      forEach: f => Object.entries(v || {}).forEach(([k, x]) => f(snap(x, k)))
    };
  }

  return {
    root,
    data() { return root; },
    ref(p = '') {
      return {
        async get() { return snap(get(p)); },
        async set(v) { put(p, v); },
        async remove() { put(p, null); },
        async update(obj) {
          for (const [k, v] of Object.entries(obj)) {
            put([p, k].filter(Boolean).join('/'), v);
          }
        },
        async transaction(fn) {
          let v = fn(structuredClone(get(p)));
          if (v === undefined) return { committed: false };
          put(p, v);
          return { committed: true, snapshot: snap(v) };
        }
      };
    }
  };
}

const encKey = crypto.randomBytes(32).toString('base64');
process.env.SENDER_ENCRYPTION_KEY = encKey;
process.env.GOOGLE_CLIENT_ID = 'test-google-client-id';
process.env.GOOGLE_CLIENT_SECRET = 'test-google-client-secret';

const fakeAuth = {
  async verifyIdToken(token) {
    if (token === 'userA') return { uid: 'userA', email: 'alice@example.com', email_verified: true };
    if (token === 'userB') return { uid: 'userB', email: 'bob@example.com', email_verified: true };
    if (token === 'adminUser') return { uid: 'adminUid', email: 'guliavansh64@gmail.com', email_verified: true, admin: true };
    throw new Error('invalid id token');
  },
  async verifySessionCookie(cookie) {
    if (cookie === 'session_userA') return { uid: 'userA', email: 'alice@example.com', email_verified: true };
    if (cookie === 'session_userB') return { uid: 'userB', email: 'bob@example.com', email_verified: true };
    if (cookie === 'session_admin') return { uid: 'adminUid', email: 'guliavansh64@gmail.com', email_verified: true, admin: true };
    if (cookie.startsWith('session_google_')) {
      const uid = cookie.replace('session_', '');
      return { uid, email: 'newuser@gmail.com', email_verified: true };
    }
    throw new Error('invalid session');
  },
  async createSessionCookie(tokenOrUser) {
    const uid = typeof tokenOrUser === 'object' && tokenOrUser !== null ? tokenOrUser.uid : tokenOrUser;
    return 'session_' + uid;
  }
};

const originalFetch = globalThis.fetch;

test('RFC 2822 MIME message formatting and Base64URL encoding', async () => {
  const mime = await buildMimeMessage({
    from: '"MailBridge System" <test@mailbridge.in>',
    to: 'customer@example.com',
    cc: 'team@example.com',
    subject: 'MIME Verification',
    text: 'Hello from RFC 2822',
    html: '<p>Hello from RFC 2822</p>'
  });

  assert.ok(Buffer.isBuffer(mime));
  const rawString = mime.toString('utf8');
  assert.ok(rawString.includes('MailBridge System <test@mailbridge.in>'));
  assert.ok(rawString.includes('To: customer@example.com'));
  assert.ok(rawString.includes('Cc: team@example.com'));
  assert.ok(rawString.includes('Subject: MIME Verification'));

  // Test RFC 4648 Base64URL encoding
  const b64url = toBase64Url(mime);
  assert.equal(typeof b64url, 'string');
  assert.ok(!b64url.includes('+'), 'Must not contain +');
  assert.ok(!b64url.includes('/'), 'Must not contain /');
  assert.ok(!b64url.includes('='), 'Must not contain padding =');
});

test('Google token refresh exchanges refresh token for fresh access token', async () => {
  globalThis.fetch = async (url, opts) => {
    if (url.toString().includes('oauth2.googleapis.com/token')) {
      return {
        ok: true,
        json: async () => ({
          access_token: 'fresh-mock-access-token-123',
          expires_in: 3600,
          token_type: 'Bearer'
        })
      };
    }
    throw new Error('unexpected fetch: ' + url);
  };

  try {
    const tokens = await refreshAccessToken({
      clientId: 'cid',
      clientSecret: 'csec',
      refreshToken: 'mock-refresh-token'
    });

    assert.equal(tokens.accessToken, 'fresh-mock-access-token-123');
    assert.equal(tokens.expiresIn, 3600);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('Google token refresh handles invalid_grant and revokes connection', async () => {
  globalThis.fetch = async (url) => {
    if (url.toString().includes('oauth2.googleapis.com/token')) {
      return {
        ok: false,
        json: async () => ({
          error: 'invalid_grant',
          error_description: 'Token has been expired or revoked.'
        })
      };
    }
    throw new Error('unexpected fetch: ' + url);
  };

  try {
    await assert.rejects(
      async () => {
        await refreshAccessToken({
          clientId: 'cid',
          clientSecret: 'csec',
          refreshToken: 'revoked-token'
        });
      },
      (err) => {
        assert.equal(err.code, 'GMAIL_TOKEN_REVOKED');
        return true;
      }
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('GET /oauth/google/start initiates Google Sign-In with state and standard scopes', async () => {
  const db = memoryDb();
  const app = createApp({ db, auth: fakeAuth, sendingConfig: { encryptionKey: encKey } });

  const res = await request(app).get('/oauth/google/start');
  assert.equal(res.status, 302);
  const location = res.headers.location;
  assert.ok(location.startsWith('https://accounts.google.com/o/oauth2/v2/auth'));

  const parsed = new URL(location);
  const state = parsed.searchParams.get('state');
  assert.ok(state);
  assert.equal(parsed.searchParams.get('scope'), 'openid email profile');
  assert.equal(parsed.searchParams.get('client_id'), 'test-google-client-id');

  // Verify state persisted in database
  const stateRecord = (await db.ref(`oauth_states/${state}`).get()).val();
  assert.ok(stateRecord);
  assert.equal(stateRecord.type, 'google_signin');
});

test('GET /oauth/google/callback validates state, provisions user, grants 10 credits and sets session cookies', async () => {
  const db = memoryDb();
  const app = createApp({ db, auth: fakeAuth, sendingConfig: { encryptionKey: encKey } });

  // Store a valid sign-in state
  const testState = 'valid-test-state-abc';
  await db.ref(`oauth_states/${testState}`).set({
    type: 'google_signin',
    createdAt: Date.now(),
    expiresAt: Date.now() + 600000
  });

  globalThis.fetch = async (url) => {
    const urlStr = url.toString();
    if (urlStr.includes('oauth2.googleapis.com/token')) {
      return {
        ok: true,
        json: async () => ({ access_token: 'mock-google-signin-token' })
      };
    }
    if (urlStr.includes('googleapis.com/oauth2/v2/userinfo')) {
      return {
        ok: true,
        json: async () => ({
          id: '123456789', verified_email: true,
          email: 'newuser@gmail.com',
          name: 'New Google User',
          picture: 'https://lh3.googleusercontent.com/photo.jpg'
        })
      };
    }
    throw new Error('unexpected URL: ' + urlStr);
  };

  try {
    const res = await request(app)
      .get(`/oauth/google/callback?code=mock-auth-code&state=${testState}`);

    assert.equal(res.status, 302);
    assert.ok(res.headers.location.includes('/dashboard.html?auth=google_success&welcome=1'));

    // Verify session cookies set
    const cookies = res.headers['set-cookie'] || [];
    assert.ok(cookies.some(c => c.includes('mb_session=')));
    assert.ok(cookies.some(c => c.includes('mb_csrf=')));

    // Verify session is immediately active and authenticated for API requests
    const cookieHeader = cookies.map(c => c.split(';')[0]).join('; ');
    const statusRes = await request(app).get('/api/session/status').set('Cookie', cookieHeader);
    assert.equal(statusRes.status, 200);
    assert.equal(statusRes.body.success, true);
    assert.ok(statusRes.body.csrf);

    const meRes = await request(app).get('/api/me').set('Cookie', cookieHeader);
    assert.equal(meRes.status, 200);
    assert.equal(meRes.body.user.email, 'newuser@gmail.com');
    assert.equal(meRes.body.wallet.balance, 10);

    // Verify user profile created
    const userSnap = await db.ref('users/google_123456789').get();
    const newUser = userSnap.val();
    assert.ok(newUser);
    assert.equal(newUser.email, 'newuser@gmail.com');
    assert.equal(newUser.name, 'New Google User');
    assert.equal(newUser.picture, 'https://lh3.googleusercontent.com/photo.jpg');

    // Verify wallet provisioned with 10 free credits
    const walletSnap = await db.ref('wallets/google_123456789').get();
    const wallet = walletSnap.val();
    assert.ok(wallet);
    assert.equal(wallet.balance, 10);
    assert.equal(wallet.purchased, 10);

    // Verify state was invalidated (one-time use)
    const stateAfter = (await db.ref(`oauth_states/${testState}`).get()).val();
    assert.ok(!stateAfter, 'OAuth state should be invalidated after use');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('GET /oauth/google/callback blocks Google login if account was created with email and password', async () => {
  const db = memoryDb();
  // Existing account created with email and password
  await db.ref('users/user_pwd_123').set({
    email: 'existingpwduser@gmail.com',
    authProvider: 'password',
    name: 'Password User',
    status: 'active',
    createdAt: Date.now()
  });

  const app = createApp({ db, auth: fakeAuth, sendingConfig: { encryptionKey: encKey } });

  const testState = 'pwd-test-state-xyz';
  await db.ref(`oauth_states/${testState}`).set({
    type: 'google_signin',
    createdAt: Date.now(),
    expiresAt: Date.now() + 600000
  });

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    const urlStr = url.toString();
    if (urlStr.includes('oauth2.googleapis.com/token')) {
      return {
        ok: true,
        json: async () => ({ access_token: 'mock-google-token' })
      };
    }
    if (urlStr.includes('googleapis.com/oauth2/v2/userinfo')) {
      return {
        ok: true,
        json: async () => ({
          id: '987654321',
          verified_email: true,
          email: 'existingpwduser@gmail.com',
          name: 'Google Impersonator'
        })
      };
    }
    throw new Error('unexpected URL: ' + urlStr);
  };

  try {
    const res = await request(app)
      .get(`/oauth/google/callback?code=mock-code&state=${testState}`);

    assert.equal(res.status, 302);
    assert.ok(res.headers.location.includes('/account.html?error='));
    const decodedUrl = decodeURIComponent(res.headers.location);
    assert.ok(decodedUrl.includes('This account was created with email and password'));

    // Assert that no session cookies were created
    const cookies = res.headers['set-cookie'] || [];
    assert.ok(!cookies.some(c => c.includes('mb_session=')));

    // Assert that the user profile was NOT overwritten with googleId
    const userSnap = await db.ref('users/user_pwd_123').get();
    const userVal = userSnap.val();
    assert.equal(userVal.authProvider, 'password');
    assert.equal(userVal.googleId, undefined);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('GET /oauth/gmail/connect requires authentication and requests gmail.send offline scope', async () => {
  const db = memoryDb();
  const app = createApp({ db, auth: fakeAuth, sendingConfig: { encryptionKey: encKey } });

  // Unauthenticated request redirects to sign-in
  const unauthRes = await request(app).get('/oauth/gmail/connect');
  assert.equal(unauthRes.status, 302);
  assert.ok(unauthRes.headers.location.includes('/account.html'));

  // Authenticated request redirects to Google consent
  const authRes = await request(app)
    .get('/oauth/gmail/connect')
    .set('Cookie', 'mb_session=session_userA');

  assert.equal(authRes.status, 302);
  const location = authRes.headers.location;
  assert.ok(location.startsWith('https://accounts.google.com/o/oauth2/v2/auth'));

  const parsed = new URL(location);
  assert.equal(parsed.searchParams.get('access_type'), 'offline');
  assert.equal(parsed.searchParams.get('prompt'), 'consent');
  assert.ok(parsed.searchParams.get('scope').includes('https://www.googleapis.com/auth/gmail.send'));

  const state = parsed.searchParams.get('state');
  const stateRecord = (await db.ref(`oauth_states/${state}`).get()).val();
  assert.ok(stateRecord);
  assert.equal(stateRecord.type, 'gmail_connect');
  assert.equal(stateRecord.uid, 'userA');
});

test('GET /oauth/gmail/callback encrypts refresh token with AES-256-GCM and never stores plaintext', async () => {
  const db = memoryDb();
  const app = createApp({ db, auth: fakeAuth, sendingConfig: { encryptionKey: encKey } });

  const testState = 'gmail-connect-state-xyz';
  await db.ref(`oauth_states/${testState}`).set({
    type: 'gmail_connect',
    uid: 'userA',
    createdAt: Date.now(),
    expiresAt: Date.now() + 600000
  });

  const rawRefreshToken = 'secret-raw-google-refresh-token-999';

  globalThis.fetch = async (url) => {
    const urlStr = url.toString();
    if (urlStr.includes('oauth2.googleapis.com/token')) {
      return {
        ok: true,
        json: async () => ({
          access_token: 'mock-gmail-access-token',
          refresh_token: rawRefreshToken,
          scope: 'openid email profile https://www.googleapis.com/auth/gmail.send'
        })
      };
    }
    if (urlStr.includes('googleapis.com/oauth2/v2/userinfo')) {
      return {
        ok: true,
        json: async () => ({
          id: 'userA_google_id',
          email: 'alice.workspace@gmail.com',
          name: 'Alice Workspace'
        })
      };
    }
    throw new Error('unexpected fetch: ' + urlStr);
  };

  try {
    const res = await request(app)
      .get(`/oauth/gmail/callback?code=mock-gmail-code&state=${testState}`);

    assert.equal(res.status, 302);
    assert.ok(res.headers.location.includes('/dashboard.html?gmail=connected'));

    // Inspect database persistence
    const connSnap = await db.ref('gmail_connections/userA').get();
    const conn = connSnap.val();
    assert.ok(conn);
    assert.equal(conn.email, 'alice.workspace@gmail.com');
    assert.equal(conn.status, 'active');

    // Verify plaintext refresh token is NEVER in database
    assert.equal(conn.refreshToken, undefined);
    assert.equal(JSON.stringify(conn).includes(rawRefreshToken), false);

    // Verify encrypted token can be decrypted with server key
    assert.ok(conn.encryptedRefreshToken);
    const decrypted = decryptCredentials(encKey, 'userA', conn.encryptedRefreshToken);
    assert.equal(decrypted.refreshToken, rawRefreshToken);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('GET /api/gmail/status and POST /api/gmail/disconnect manage connection lifecycle and enforce tenant isolation', async () => {
  const db = memoryDb();
  const app = createApp({ db, auth: fakeAuth, sendingConfig: { encryptionKey: encKey } });

  // User A connects Gmail
  const encrypted = encryptCredentials(encKey, 'userA', { refreshToken: 'rt-userA' });
  await db.ref('gmail_connections/userA').set({
    email: 'alice@gmail.com',
    status: 'active',
    encryptedRefreshToken: encrypted,
    connectedAt: Date.now()
  });

  // User A checks status -> connected
  const statusResA = await request(app)
    .get('/api/gmail/status')
    .set('Cookie', 'mb_session=session_userA');
  assert.equal(statusResA.status, 200);
  assert.equal(statusResA.body.connected, true);
  assert.equal(statusResA.body.email, 'alice@gmail.com');
  assert.equal(statusResA.body.encryptedRefreshToken, undefined);

  // User B checks status -> NOT connected (tenant isolated)
  const statusResB = await request(app)
    .get('/api/gmail/status')
    .set('Cookie', 'mb_session=session_userB');
  assert.equal(statusResB.status, 200);
  assert.equal(statusResB.body.connected, false);

  // User A disconnects Gmail
  const discRes = await request(app)
    .post('/api/gmail/disconnect')
    .set('Cookie', 'mb_session=session_userA; mb_csrf=' + 'a'.repeat(64))
    .set('X-CSRF-Token', 'a'.repeat(64));
  assert.equal(discRes.status, 200);
  assert.equal(discRes.body.success, true);

  // Status is now disconnected
  const statusAfter = await request(app)
    .get('/api/gmail/status')
    .set('Cookie', 'mb_session=session_userA');
  assert.equal(statusAfter.body.connected, false);
});

test('POST /api/gmail/send-test dispatches email via Gmail API and records sending activity', async () => {
  const db = memoryDb();
  const app = createApp({ db, auth: fakeAuth, sendingConfig: { encryptionKey: encKey } });

  const encrypted = encryptCredentials(encKey, 'userA', { refreshToken: 'rt-userA-test' });
  await db.ref('gmail_connections/userA').set({
    email: 'alice@gmail.com',
    status: 'active',
    encryptedRefreshToken: encrypted,
    connectedAt: Date.now()
  });

  let rawSentPayload = null;

  globalThis.fetch = async (url, opts) => {
    const urlStr = url.toString();
    if (urlStr.includes('oauth2.googleapis.com/token')) {
      return {
        ok: true,
        json: async () => ({ access_token: 'mock-gmail-send-access-token' })
      };
    }
    if (urlStr.includes('gmail.googleapis.com/gmail/v1/users/me/messages/send')) {
      rawSentPayload = JSON.parse(opts.body);
      return {
        ok: true,
        json: async () => ({
          id: 'gmail-msg-id-12345',
          threadId: 'gmail-thread-67890'
        })
      };
    }
    throw new Error('unexpected fetch: ' + urlStr);
  };

  try {
    const res = await request(app)
      .post('/api/gmail/send-test')
      .set('Cookie', 'mb_session=session_userA; mb_csrf=' + 'a'.repeat(64))
      .set('X-CSRF-Token', 'a'.repeat(64))
      .send({
        to: 'target@example.com',
        subject: 'Live Test Subject',
        text: 'Live test email body content'
      });

    assert.equal(res.status, 200);
    assert.equal(res.body.success, true);
    assert.equal(res.body.messageId, 'gmail-msg-id-12345');
    assert.ok(res.body.from.includes('alice@gmail.com'));

    // Check sent RFC 2822 payload was encoded
    assert.ok(rawSentPayload);
    assert.ok(rawSentPayload.raw);
    const decodedMime = Buffer.from(rawSentPayload.raw, 'base64url').toString('utf8');
    assert.ok(decodedMime.includes('To: target@example.com'));
    assert.ok(decodedMime.includes('Subject: Live Test Subject'));

    // Verify logged in wallet send requests
    const wallet = (await db.ref('wallets/userA').get()).val();
    const reqs = Object.values(wallet.sendRequests || {});
    assert.equal(reqs.length, 1);
    assert.equal(reqs[0].provider, 'gmail_api');
    assert.equal(reqs[0].providerMessageId, 'gmail-msg-id-12345');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('runJob automatically routes through connected Gmail API and transitions job to accepted', async () => {
  const db = memoryDb();
  const uid = 'userA';
  const jobId = crypto.createHash('sha256').update('test-job-1').digest('hex');

  const encrypted = encryptCredentials(encKey, uid, { refreshToken: 'rt-userA-job' });
  await db.ref(`gmail_connections/${uid}`).set({
    email: 'alice@gmail.com',
    status: 'active',
    encryptedRefreshToken: encrypted
  });

  await db.ref(`wallets/${uid}`).set({
    balance: 0,
    reserved: 1,
    purchased: 1,
    consumed: 0,
    sendRequests: {
      [jobId]: {
        id: jobId,
        status: 'queued',
        message: {
          to: 'customer@example.com',
          subject: 'Order Confirmation',
          text: 'Thank you for your order'
        }
      }
    }
  });

  globalThis.fetch = async (url) => {
    const s = url.toString();
    if (s.includes('oauth2.googleapis.com/token')) {
      return {
        ok: true,
        json: async () => ({ access_token: 'mock-job-access-token' })
      };
    }
    if (s.includes('gmail.googleapis.com/gmail/v1/users/me/messages/send')) {
      return {
        ok: true,
        json: async () => ({ id: 'gmail-job-msg-777', threadId: 'th-888' })
      };
    }
    throw new Error('unexpected URL: ' + s);
  };

  try {
    const { runJob } = require('../src/sending');
    await runJob({ db, key: encKey, uid, id: jobId });

    const job = (await db.ref(`wallets/${uid}/sendRequests/${jobId}`).get()).val();
    assert.equal(job.status, 'accepted');
    assert.equal(job.provider, 'gmail_api');
    assert.equal(job.senderEmail, 'alice@gmail.com');
    assert.equal(job.providerMessageId, 'gmail-job-msg-777');

    const wallet = (await db.ref(`wallets/${uid}`).get()).val();
    assert.equal(wallet.reserved, 0);
    assert.equal(wallet.consumed, 1);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('Exact Google Cloud Console registered redirect URIs /oauth/oauth/* routes work identically', async () => {
  const db = memoryDb();
  const app = createApp({ db, auth: fakeAuth, sendingConfig: { encryptionKey: encKey } });

  // 1. Test /oauth/oauth/google/start
  const startRes = await request(app).get('/oauth/oauth/google/start');
  assert.equal(startRes.status, 302);
  const loc = new URL(startRes.headers.location);
  assert.equal(loc.searchParams.get('scope'), 'openid email profile');
  const state = loc.searchParams.get('state');
  assert.ok(state);

  // 2. Test /oauth/oauth/google/callback
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    const s = url.toString();
    if (s.includes('oauth2.googleapis.com/token')) {
      return { ok: true, json: async () => ({ access_token: 'nested-access-token' }) };
    }
    if (s.includes('googleapis.com/oauth2/v2/userinfo')) {
      return {
        ok: true,
        json: async () => ({ id: '987654321', verified_email: true, email: 'registered.callback@gmail.com', name: 'Registered User' })
      };
    }
    throw new Error('unexpected: ' + s);
  };

  try {
    const cbRes = await request(app).get(`/oauth/oauth/google/callback?code=mock-code&state=${state}`);
    assert.equal(cbRes.status, 302);
    assert.ok(cbRes.headers.location.includes('/dashboard.html?auth=google_success'));
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('Credentials and secrets are strictly backend-only and never exposed in responses', async () => {
  const db = memoryDb();
  const app = createApp({ db, auth: fakeAuth, sendingConfig: { encryptionKey: encKey } });

  // 1. Check /api/config
  const configRes = await request(app).get('/api/config');
  assert.equal(configRes.status, 200);
  const configStr = JSON.stringify(configRes.body);
  assert.ok(!configStr.includes('client_secret'));
  assert.ok(!configStr.includes('GOOGLE_CLIENT_SECRET'));

  // 2. Check /api/gmail/status
  const statusRes = await request(app)
    .get('/api/gmail/status')
    .set('Cookie', 'mb_session=session_userA');
  assert.equal(statusRes.status, 200);
  const statusStr = JSON.stringify(statusRes.body);
  assert.ok(!statusStr.includes('client_secret'));
  assert.ok(!statusStr.includes('GOOGLE_CLIENT_SECRET'));
  assert.ok(!statusStr.includes('encryptedRefreshToken'));
  assert.ok(!statusStr.includes('refreshToken'));
});

test('Admin 1-Click Gmail Connect: Non-admin is rejected from initiating connect', async () => {
  const db = memoryDb();
  const app = createApp({ db, auth: fakeAuth, sendingConfig: { encryptionKey: encKey } });

  // Unauthenticated request redirects
  const res1 = await request(app).get('/oauth/admin/gmail/connect');
  assert.equal(res1.status, 302);
  assert.ok(res1.headers.location.includes('/account.html?error='));

  // Non-admin user redirects
  const res2 = await request(app)
    .get('/oauth/admin/gmail/connect')
    .set('Cookie', 'mb_session=session_userA');
  assert.equal(res2.status, 302);
  assert.ok(res2.headers.location.includes('/account.html?error='));

  // JSON request returns 401
  const res3 = await request(app)
    .get('/api/admin/oauth/gmail/connect')
    .set('Accept', 'application/json');
  assert.equal(res3.status, 401);
});

test('Admin 1-Click Gmail Connect: Admin initiates OAuth, sets state, and redirects with account picker and scopes', async () => {
  const db = memoryDb();
  const app = createApp({ db, auth: fakeAuth, sendingConfig: { encryptionKey: encKey } });

  const res = await request(app)
    .get('/oauth/admin/gmail/connect')
    .set('Cookie', 'mb_session=session_admin');

  assert.equal(res.status, 302);
  const location = new URL(res.headers.location);
  assert.equal(location.host, 'accounts.google.com');
  assert.equal(location.searchParams.get('client_id'), 'test-google-client-id');
  assert.equal(location.searchParams.get('access_type'), 'offline');
  assert.equal(location.searchParams.get('prompt'), 'consent select_account');
  const scope = location.searchParams.get('scope');
  assert.ok(scope.includes('https://mail.google.com/'));
  assert.ok(scope.includes('https://www.googleapis.com/auth/gmail.send'));

  const state = location.searchParams.get('state');
  assert.ok(state);
  const stateRecord = (await db.ref(`oauth_states/${state}`).get()).val();
  assert.equal(stateRecord.type, 'admin_gmail_connect');
  assert.equal(stateRecord.adminUid, 'adminUid');
  assert.equal(stateRecord.adminEmail, 'guliavansh64@gmail.com');
});

test('Admin 1-Click Gmail Connect: Callback exchanges code, adds active sender to sender_accounts pool, and logs audit', async () => {
  const db = memoryDb();
  const app = createApp({ db, auth: fakeAuth, sendingConfig: { encryptionKey: encKey } });

  const state = 'test_admin_state_123';
  await db.ref(`oauth_states/${state}`).set({
    type: 'admin_gmail_connect',
    adminUid: 'adminUid',
    adminEmail: 'guliavansh64@gmail.com',
    redirectUri: 'http://localhost:3000/oauth/oauth/gmail/callback',
    createdAt: Date.now(),
    expiresAt: Date.now() + 600000
  });

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    const s = url.toString();
    if (s.includes('oauth2.googleapis.com/token')) {
      return {
        ok: true,
        json: async () => ({
          access_token: 'mock-admin-access-token',
          refresh_token: '1//mock-admin-refresh-token-xyz'
        })
      };
    }
    if (s.includes('googleapis.com/oauth2/v2/userinfo')) {
      return {
        ok: true,
        json: async () => ({
          id: 'google-admin-sender-1',
          email: 'dispatch.admin@gmail.com',
          name: 'Dispatch Admin Sender'
        })
      };
    }
    throw new Error('unexpected: ' + s);
  };

  try {
    const cbRes = await request(app).get(`/oauth/gmail/callback?code=mock_code&state=${state}`);
    assert.equal(cbRes.status, 302);
    assert.ok(cbRes.headers.location.includes('/admin/senders.html?sender_connected=success'));
    assert.ok(cbRes.headers.location.includes('dispatch.admin%40gmail.com'));

    // Check sender_accounts in db
    const sendersSnap = await db.ref('sender_accounts').get();
    const senders = Object.values(sendersSnap.val() || {});
    assert.equal(senders.length, 1);
    const sender = senders[0];
    assert.equal(sender.email, 'dispatch.admin@gmail.com');
    assert.equal(sender.name, 'Dispatch Admin Sender');
    assert.equal(sender.provider, 'gmail_oauth');
    assert.equal(sender.authType, 'oauth2');
    assert.equal(sender.status, 'active');
    assert.ok(Number.isFinite(sender.verifiedAt) && sender.verifiedAt > 0);
    assert.equal(sender.dailyLimit, 500);

    // Verify encrypted credentials can be decrypted
    const { decryptCredentials } = require('../src/sending');
    const secret = decryptCredentials(encKey, sender.id, sender.credentials);
    assert.equal(secret.type, 'oauth2');
    assert.equal(secret.clientId, 'test-google-client-id');
    assert.equal(secret.clientSecret, 'test-google-client-secret');
    assert.equal(secret.refreshToken, '1//mock-admin-refresh-token-xyz');
    assert.equal(secret.host, 'smtp.gmail.com');
    assert.equal(secret.port, 465);

    // Verify state was consumed
    const consumedState = (await db.ref(`oauth_states/${state}`).get()).val();
    assert.ok(!consumedState);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('Admin 1-Click Gmail Connect: Multiple Gmail accounts can be connected for multi-sender rotation pool', async () => {
  const db = memoryDb();
  const app = createApp({ db, auth: fakeAuth, sendingConfig: { encryptionKey: encKey } });

  const originalFetch = globalThis.fetch;
  try {
    // Connect Sender 1
    const state1 = 'state_sender_1';
    await db.ref(`oauth_states/${state1}`).set({
      type: 'admin_gmail_connect',
      adminUid: 'adminUid',
      adminEmail: 'guliavansh64@gmail.com',
      redirectUri: 'http://localhost:3000/oauth/oauth/gmail/callback',
      createdAt: Date.now(),
      expiresAt: Date.now() + 600000
    });

    globalThis.fetch = async (url) => {
      const s = url.toString();
      if (s.includes('oauth2.googleapis.com/token')) {
        return { ok: true, json: async () => ({ access_token: 'token1', refresh_token: 'rt1' }) };
      }
      if (s.includes('googleapis.com/oauth2/v2/userinfo')) {
        return { ok: true, json: async () => ({ id: 'g1', email: 'sender1@gmail.com', name: 'Pool Sender One' }) };
      }
      throw new Error('unexpected: ' + s);
    };

    const res1 = await request(app).get(`/oauth/gmail/callback?code=code1&state=${state1}`);
    assert.equal(res1.status, 302);

    // Connect Sender 2
    const state2 = 'state_sender_2';
    await db.ref(`oauth_states/${state2}`).set({
      type: 'admin_gmail_connect',
      adminUid: 'adminUid',
      adminEmail: 'guliavansh64@gmail.com',
      redirectUri: 'http://localhost:3000/oauth/oauth/gmail/callback',
      createdAt: Date.now(),
      expiresAt: Date.now() + 600000
    });

    globalThis.fetch = async (url) => {
      const s = url.toString();
      if (s.includes('oauth2.googleapis.com/token')) {
        return { ok: true, json: async () => ({ access_token: 'token2', refresh_token: 'rt2' }) };
      }
      if (s.includes('googleapis.com/oauth2/v2/userinfo')) {
        return { ok: true, json: async () => ({ id: 'g2', email: 'sender2@gmail.com', name: 'Pool Sender Two' }) };
      }
      throw new Error('unexpected: ' + s);
    };

    const res2 = await request(app).get(`/oauth/gmail/callback?code=code2&state=${state2}`);
    assert.equal(res2.status, 302);

    // Check that BOTH senders exist in sender_accounts
    const sendersSnap = await db.ref('sender_accounts').get();
    const senders = Object.values(sendersSnap.val() || {});
    assert.equal(senders.length, 2);
    const emails = senders.map(s => s.email).sort();
    assert.deepEqual(emails, ['sender1@gmail.com', 'sender2@gmail.com']);
    assert.ok(senders.every(s => s.status === 'active' && s.authType === 'oauth2'));
  } finally {
    globalThis.fetch = originalFetch;
  }
});


