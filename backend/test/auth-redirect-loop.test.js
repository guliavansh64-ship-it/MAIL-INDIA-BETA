'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const crypto = require('node:crypto');
const { createApp } = require('../src/app');
const { createLocalDatabase, createLocalAuth } = require('../src/local-dev');

function parseCookies(res) {
  const setCookies = res.headers['set-cookie'] || [];
  return setCookies.map(c => c.split(';')[0]).join('; ');
}

test('Comprehensive Auth Flow Verification (9 Scenarios)', async (t) => {
  const db = createLocalDatabase();
  const auth = createLocalAuth();
  const encKey = crypto.randomBytes(32).toString('base64');
  const app = createApp({ db, auth, sendingConfig: { encryptionKey: encKey } });

  let googleUserA = { id: 'usr-11111', email: 'userA.google@gmail.com', name: 'User Alpha' };
  let googleUserB = { id: 'usr-22222', email: 'userB.google@gmail.com', name: 'User Beta' };
  let currentGoogleMock = googleUserA;

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    const s = url.toString();
    if (s.includes('oauth2.googleapis.com/token')) {
      return {
        ok: true,
        json: async () => ({
          access_token: 'mock-google-token-' + currentGoogleMock.id,
          refresh_token: 'mock-google-refresh-' + currentGoogleMock.id
        })
      };
    }
    if (s.includes('googleapis.com/oauth2/v2/userinfo')) {
      return {
        ok: true,
        json: async () => currentGoogleMock
      };
    }
    throw new Error('Unexpected fetch in test: ' + s);
  };

  try {
    // -------------------------------------------------------------
    // Scenario 1: First-time Google login
    // -------------------------------------------------------------
    await t.test('Scenario 1: First-time Google login provisions user and sets Lax cookies', async () => {
      currentGoogleMock = googleUserA;
      const startRes = await request(app).get('/oauth/google/start');
      assert.equal(startRes.status, 302);
      const startUrl = new URL(startRes.headers.location);
      const state = startUrl.searchParams.get('state');
      assert.ok(state);

      const callbackRes = await request(app).get(`/oauth/google/callback?code=code-1&state=${state}`);
      assert.equal(callbackRes.status, 302);
      assert.ok(callbackRes.headers.location.includes('/dashboard.html?auth=google_success&welcome=1'));

      const cookieHeader = parseCookies(callbackRes);
      assert.ok(cookieHeader.includes('mb_session='));
      assert.ok(cookieHeader.includes('mb_csrf='));

      // Check cookie options (SameSite=Lax)
      const rawCookies = callbackRes.headers['set-cookie'];
      assert.ok(rawCookies.some(c => c.includes('SameSite=Lax')));

      // Check DB user creation & 10 credits
      const user = (await db.ref('users/google_usr-11111').get()).val();
      assert.ok(user);
      assert.equal(user.email, 'usera.google@gmail.com');
      assert.equal(user.authProvider, 'google');

      const wallet = (await db.ref('wallets/google_usr-11111').get()).val();
      assert.equal(wallet.balance, 10);
    });

    // -------------------------------------------------------------
    // Scenario 2: Existing Google user login
    // -------------------------------------------------------------
    let userACookie = '';
    await t.test('Scenario 2: Existing Google user login updates lastLoginAt without duplicate', async () => {
      currentGoogleMock = googleUserA;
      const startRes = await request(app).get('/oauth/google/start');
      const state = new URL(startRes.headers.location).searchParams.get('state');

      const callbackRes = await request(app).get(`/oauth/google/callback?code=code-2&state=${state}`);
      assert.equal(callbackRes.status, 302);
      // Not a new user, so &welcome=1 is omitted
      assert.ok(callbackRes.headers.location.includes('/dashboard.html?auth=google_success'));
      assert.ok(!callbackRes.headers.location.includes('&welcome=1'));

      userACookie = parseCookies(callbackRes);
      const user = (await db.ref('users/google_usr-11111').get()).val();
      assert.ok(user.lastLoginAt > 0);
    });

    // -------------------------------------------------------------
    // Scenario 3: Page refresh after login
    // -------------------------------------------------------------
    await t.test('Scenario 3: Page refresh after login restores session via cookies', async () => {
      const statusRes = await request(app).get('/api/session/status').set('Cookie', userACookie);
      assert.equal(statusRes.status, 200);
      assert.equal(statusRes.body.success, true);
      assert.ok(statusRes.body.csrf);

      const meRes = await request(app).get('/api/me').set('Cookie', userACookie);
      assert.equal(meRes.status, 200);
      assert.equal(meRes.body.user.email, 'usera.google@gmail.com');
      assert.equal(meRes.body.wallet.balance, 10);
    });

    // -------------------------------------------------------------
    // Scenario 4: Dashboard navigation
    // -------------------------------------------------------------
    await t.test('Scenario 4: Dashboard navigation serves HTML and allows API access', async () => {
      const dashRes = await request(app).get('/dashboard.html');
      assert.equal(dashRes.status, 200);
      assert.ok(dashRes.text.includes('initDashboard()'));

      const meRes = await request(app).get('/api/me').set('Cookie', userACookie);
      assert.equal(meRes.status, 200);
      assert.ok(Array.isArray(meRes.body.recentEmails));
    });

    // -------------------------------------------------------------
    // Scenario 5: Browser restart and session restoration
    // -------------------------------------------------------------
    await t.test('Scenario 5: Session restores cleanly across separate requests', async () => {
      const statusRes = await request(app).get('/api/session/status').set('Cookie', userACookie);
      assert.equal(statusRes.status, 200);
      assert.equal(statusRes.body.success, true);
    });

    // -------------------------------------------------------------
    // Scenario 6: Logout and login again
    // -------------------------------------------------------------
    await t.test('Scenario 6: Logout revokes session, clears cookies, prevents access', async () => {
      const statusBefore = await request(app).get('/api/session/status').set('Cookie', userACookie);
      const csrf = statusBefore.body.csrf;

      const logoutRes = await request(app)
        .post('/api/session/logout')
        .set('Cookie', userACookie)
        .set('X-CSRF-Token', csrf);
      assert.equal(logoutRes.status, 200);

      // Verify cookies are expired in Set-Cookie header
      const clearedCookies = logoutRes.headers['set-cookie'] || [];
      assert.ok(clearedCookies.some(c => c.includes('mb_session=;') || c.includes('Expires=Thu, 01 Jan 1970')));

      // Subsequent access with old cookie fails
      const statusAfter = await request(app).get('/api/session/status').set('Cookie', userACookie);
      assert.equal(statusAfter.status, 401);
    });

    // -------------------------------------------------------------
    // Scenario 7: Expired session
    // -------------------------------------------------------------
    await t.test('Scenario 7: Expired or malformed session returns 401 fail-closed', async () => {
      const badCookie = 'mb_session=invalid-or-expired-token; mb_csrf=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
      const statusRes = await request(app).get('/api/session/status').set('Cookie', badCookie);
      assert.equal(statusRes.status, 401);
      assert.equal(statusRes.body.error, 'UNAUTHENTICATED');
    });

    // -------------------------------------------------------------
    // Scenario 8: Multiple users
    // -------------------------------------------------------------
    await t.test('Scenario 8: Multiple users get isolated sessions and wallets', async () => {
      currentGoogleMock = googleUserB;
      const startRes = await request(app).get('/oauth/google/start');
      const state = new URL(startRes.headers.location).searchParams.get('state');

      const callbackRes = await request(app).get(`/oauth/google/callback?code=code-b&state=${state}`);
      const userBCookie = parseCookies(callbackRes);

      const meB = await request(app).get('/api/me').set('Cookie', userBCookie);
      assert.equal(meB.status, 200);
      assert.equal(meB.body.user.email, 'userb.google@gmail.com');
      assert.equal(meB.body.user.uid, 'google_usr-22222');

      // User A and User B have separate accounts in DB
      const userA = (await db.ref('users/google_usr-11111').get()).val();
      const userB = (await db.ref('users/google_usr-22222').get()).val();
      assert.notEqual(userA.uid || 'google_usr-11111', userB.uid || 'google_usr-22222');
      assert.notEqual(userA.email, userB.email);
    });

    // -------------------------------------------------------------
    // Scenario 9: Gmail connection after login
    // -------------------------------------------------------------
    await t.test('Scenario 9: Gmail connection requires login and links to user', async () => {
      // Re-login User A
      currentGoogleMock = googleUserA;
      const startRes = await request(app).get('/oauth/google/start');
      const stateA = new URL(startRes.headers.location).searchParams.get('state');
      const callbackA = await request(app).get(`/oauth/google/callback?code=code-a2&state=${stateA}`);
      const cookieA = parseCookies(callbackA);

      // Connect Gmail requires active session
      const connectUnauth = await request(app).get('/oauth/gmail/connect');
      assert.equal(connectUnauth.status, 302);
      assert.ok(connectUnauth.headers.location.includes('/account.html'));

      const connectAuth = await request(app).get('/oauth/gmail/connect').set('Cookie', cookieA);
      assert.equal(connectAuth.status, 302);
      const gmailOAuthUrl = new URL(connectAuth.headers.location);
      assert.ok(gmailOAuthUrl.searchParams.get('scope').includes('gmail.send'));
    });

  } finally {
    globalThis.fetch = originalFetch;
  }
});
