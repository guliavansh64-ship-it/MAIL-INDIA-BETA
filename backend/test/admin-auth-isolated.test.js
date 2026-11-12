'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const { createApp } = require('../src/app');

function createMockDb(initialData = {}) {
  const root = structuredClone(initialData);
  function get(path) {
    return path.split('/').filter(Boolean).reduce((obj, key) => obj?.[key], root);
  }
  function put(path, val) {
    const keys = path.split('/').filter(Boolean);
    const last = keys.pop();
    let curr = root;
    for (const k of keys) curr = curr[k] ??= {};
    if (val === null) delete curr[last];
    else curr[last] = structuredClone(val);
  }
  return {
    root,
    ref(path = '') {
      return {
        async get() { return { val: () => structuredClone(get(path)) }; },
        async set(v) { put(path, v); },
        async update(obj) {
          for (const [k, v] of Object.entries(obj)) put([path, k].filter(Boolean).join('/'), v);
        },
        async transaction(fn) {
          const res = fn(structuredClone(get(path)));
          if (res === undefined) return { committed: false };
          put(path, res);
          return { committed: true, snapshot: { val: () => structuredClone(res) } };
        }
      };
    }
  };
}

test('Dedicated Admin Auth: Non-admin email is strictly rejected on /api/admin/auth/login', async () => {
  const db = createMockDb({ users: {} });
  const app = createApp({
    db,
    auth: {
      verifyIdToken: async () => ({ uid: 'user123', email: 'user@gmail.com' }),
      verifySessionCookie: async () => null,
      createSessionCookie: async () => 'sess_token'
    },
    publicConfig: { firebaseApiKey: 'mock-key' }
  });

  // Attempt login with regular user gmail
  const res = await request(app)
    .post('/api/admin/auth/login')
    .send({ email: 'user@gmail.com', password: 'AnyPassword123!' });

  assert.equal(res.status, 403);
  assert.equal(res.body.success, false);
  assert.equal(res.body.error, 'ADMIN_ACCESS_DENIED');
  assert.ok(res.body.message.includes('Only the authorized platform administrator (guliavansh64@gmail.com)'));
});

test('Dedicated Admin Auth: Other @gmail.com accounts cannot log in even with valid ID tokens', async () => {
  const db = createMockDb({ users: {} });
  const app = createApp({
    db,
    auth: {
      verifyIdToken: async () => ({ uid: 'user_other', email: 'vanshappmaker@gmail.com' }),
      verifySessionCookie: async () => null,
      createSessionCookie: async () => 'sess_token'
    },
    publicConfig: { firebaseApiKey: 'mock-key' }
  });

  const res = await request(app)
    .post('/api/admin/auth/login')
    .send({ email: 'vanshappmaker@gmail.com', idToken: 'valid_user_token' });

  assert.equal(res.status, 403);
  assert.equal(res.body.error, 'ADMIN_ACCESS_DENIED');
});

test('Dedicated Admin Auth: guliavansh64@gmail.com succeeds with valid ID token and issues admin session', async () => {
  const db = createMockDb({ users: { N74WbDpqXShi9VqhAWik9mXOKLo1: { email: 'guliavansh64@gmail.com', status: 'active' } } });
  const app = createApp({
    db,
    auth: {
      verifyIdToken: async token => {
        if (token === 'admin_valid_token') {
          return { uid: 'N74WbDpqXShi9VqhAWik9mXOKLo1', email: 'guliavansh64@gmail.com', email_verified: true };
        }
        throw new Error('Invalid token');
      },
      createSessionCookie: async () => 'admin_session_cookie_mock',
      verifySessionCookie: async token => {
        if (token === 'admin_session_cookie_mock') {
          return { uid: 'N74WbDpqXShi9VqhAWik9mXOKLo1', email: 'guliavansh64@gmail.com', admin: true };
        }
        return null;
      }
    },
    publicConfig: { firebaseApiKey: 'mock-key' }
  });

  const res = await request(app)
    .post('/api/admin/auth/login')
    .send({ email: 'guliavansh64@gmail.com', idToken: 'admin_valid_token' });

  assert.equal(res.status, 200);
  assert.equal(res.body.success, true);
  assert.equal(res.body.user.email, 'guliavansh64@gmail.com');
  assert.equal(res.body.user.admin, true);
  assert.ok(res.body.csrf);

  // Verify cookies were set
  const cookies = res.headers['set-cookie'];
  assert.ok(cookies);
  assert.ok(cookies.some(c => c.includes('mb_session=')));
});

test('Dedicated Admin Auth: GET /api/admin/auth/session rejects unauthenticated and user accounts', async () => {
  const db = createMockDb({});
  const app = createApp({
    db,
    auth: {
      verifySessionCookie: async token => {
        if (token === 'user_session') return { uid: 'regular_user', email: 'regular@gmail.com' };
        if (token === 'admin_session') return { uid: 'admin_user', email: 'guliavansh64@gmail.com' };
        return null;
      }
    }
  });

  // 1. No token -> 401
  const unauth = await request(app).get('/api/admin/auth/session');
  assert.equal(unauth.status, 401);
  assert.equal(unauth.body.isAdmin, false);

  // 2. Regular user token -> 403 Access Denied
  const userRes = await request(app)
    .get('/api/admin/auth/session')
    .set('Cookie', 'mb_session=user_session');
  assert.equal(userRes.status, 403);
  assert.equal(userRes.body.isAdmin, false);
  assert.equal(userRes.body.error, 'ADMIN_ACCESS_DENIED');

  // 3. Platform Admin token -> 200 Authorized
  const adminRes = await request(app)
    .get('/api/admin/auth/session')
    .set('Cookie', 'mb_session=admin_session');
  assert.equal(adminRes.status, 200);
  assert.equal(adminRes.body.isAdmin, true);
  assert.equal(adminRes.body.user.email, 'guliavansh64@gmail.com');
});

test('Dedicated Admin Auth: POST /api/admin/auth/logout clears session cookies', async () => {
  const db = createMockDb({});
  const app = createApp({ db, auth: {} });

  const res = await request(app).post('/api/admin/auth/logout');
  assert.equal(res.status, 200);
  assert.equal(res.body.success, true);
  assert.equal(res.body.redirect, '/admin/login.html');
  const cookies = res.headers['set-cookie'];
  assert.ok(cookies);
  assert.ok(cookies.some(c => c.includes('mb_session=;')));
});
