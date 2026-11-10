'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const crypto = require('node:crypto');
const { createApp, hashKey } = require('../src/app');

function createTestMemory() {
  const root = {
    users: {
      admin: { email: 'admin@example.com', status: 'active' },
      user_a: { email: 'a@example.com', status: 'active' },
      user_b: { email: 'b@example.com', status: 'active' },
      suspended_admin: { email: 'susp_admin@example.com', status: 'suspended' }
    },
    wallets: {
      user_a: { balance: 25, reserved: 0, purchased: 25, consumed: 0 },
      user_b: { balance: 99, reserved: 0, purchased: 99, consumed: 0 }
    },
    email_logs: {
      user_a: {
        log_a: { id: 'log_a', recipient: 'alice@example.com', subject: 'Secret A', status: 'accepted', createdAt: Date.now() }
      },
      user_b: {
        log_b: { id: 'log_b', recipient: 'bob@example.com', subject: 'Secret B', status: 'accepted', createdAt: Date.now() }
      }
    },
    support_tickets: {
      user_b: {
        ticket_b: { subject: 'Confidential B', message: 'Do not leak', status: 'open', createdAt: Date.now() }
      }
    },
    user_api_keys: {
      user_b: {
        key_b: { name: 'Bob Key', prefix: 'mb_live_bob', status: 'active', createdAt: Date.now() }
      }
    },
    key_index: {}
  };

  function get(p) { return p.split('/').filter(Boolean).reduce((o, k) => o?.[k], root); }
  function put(p, v) {
    const a = p.split('/').filter(Boolean), k = a.pop();
    let o = root;
    for (const x of a) o = o[x] ??= {};
    if (v === null) delete o[k];
    else o[k] = structuredClone(v);
  }

  return {
    root,
    ref(p = '') {
      return {
        async get() { return { val: () => structuredClone(get(p)) }; },
        async set(v) { put(p, structuredClone(v)); },
        async update(v) { for (const [k, x] of Object.entries(v)) put([p, k].filter(Boolean).join('/'), structuredClone(x)); },
        async transaction(fn) {
          const v = fn(structuredClone(get(p)));
          if (v === undefined) return { committed: false };
          put(p, v);
          return { committed: true, snapshot: { val: () => structuredClone(v) } };
        }
      };
    }
  };
}

const auth = {
  async verifyIdToken(t) {
    if (t === 'token_a') return { uid: 'user_a', email: 'a@example.com', email_verified: true };
    if (t === 'token_b') return { uid: 'user_b', email: 'b@example.com', email_verified: true };
    if (t === 'token_admin') return { uid: 'admin', email: 'admin@example.com', email_verified: true, admin: true };
    if (t === 'token_susp_admin') return { uid: 'suspended_admin', email: 'susp_admin@example.com', email_verified: true, admin: true };
    throw Error('unauthenticated');
  }
};

test('IDOR protection: user cannot read another tenant email logs or tickets', async () => {
  const db = createTestMemory();
  const app = createApp({ db, auth });

  // User A fetches their email logs
  const logsRes = await request(app).get('/api/emails').set('Authorization', 'Bearer token_a');
  assert.equal(logsRes.status, 200);
  assert.equal(logsRes.body.emails.length, 1);
  assert.equal(logsRes.body.emails[0].id, 'log_a');
  // Does not leak User B's log
  assert.ok(!JSON.stringify(logsRes.body).includes('Secret B'));

  // User A tries to view support tickets
  const ticketsRes = await request(app).get('/api/support').set('Authorization', 'Bearer token_a');
  assert.equal(ticketsRes.status, 200);
  assert.equal(ticketsRes.body.tickets.length, 0);
});

test('API keys are hashed and plaintext key is never persisted', async () => {
  const db = createTestMemory();
  const app = createApp({ db, auth });

  const res = await request(app)
    .post('/api/keys')
    .set('Authorization', 'Bearer token_a')
    .send({ name: 'Secret Service Key' });

  assert.equal(res.status, 201);
  const rawKey = res.body.key;
  assert.ok(rawKey.startsWith('mb_live_'));

  // Verify the plaintext raw key is NOT saved in the database
  const serialized = JSON.stringify(db.root);
  assert.equal(serialized.includes(rawKey), false);

  // But its sha256 hash IS in key_index
  const expectedHash = hashKey(rawKey);
  assert.ok(db.root.key_index[expectedHash]);
  assert.equal(db.root.key_index[expectedHash].uid, 'user_a');
});

test('CSRF protection blocks cookie requests missing valid CSRF token', async () => {
  const db = createTestMemory();
  const sessionAuth = {
    ...auth,
    async verifySessionCookie(cookie) {
      if (cookie === 'valid_cookie') return { uid: 'user_a', email: 'a@example.com' };
      throw Error('invalid');
    }
  };
  const app = createApp({ db, auth: sessionAuth });

  // Post without CSRF token fails 403
  const resNoCsrf = await request(app)
    .post('/api/profile')
    .set('Cookie', ['__Host-mb_session=valid_cookie', '__Host-mb_csrf=' + 'a'.repeat(64)])
    .send({ name: 'Hacked Name' });
  assert.equal(resNoCsrf.status, 403);
  assert.equal(resNoCsrf.body.error, 'CSRF_FAILED');

  // Post with matching CSRF token succeeds
  const csrf = 'b'.repeat(64);
  const resValid = await request(app)
    .post('/api/profile')
    .set('Cookie', [`__Host-mb_session=valid_cookie`, `__Host-mb_csrf=${csrf}`])
    .set('X-CSRF-Token', csrf)
    .send({ name: 'Legitimate Name' });
  assert.equal(resValid.status, 200);
  assert.equal(db.root.users.user_a.name, 'Legitimate Name');
});

test('admin authorization blocks suspended admin accounts and non-admins', async () => {
  const db = createTestMemory();
  const app = createApp({ db, auth });

  // Regular user blocked from admin summary
  const resUser = await request(app).get('/api/admin/summary').set('Authorization', 'Bearer token_a');
  assert.equal(resUser.status, 403);

  // Suspended admin claim blocked from admin summary
  const resSusp = await request(app).get('/api/admin/summary').set('Authorization', 'Bearer token_susp_admin');
  assert.equal(resSusp.status, 403);

  // Active admin succeeds
  const resAdmin = await request(app).get('/api/admin/summary').set('Authorization', 'Bearer token_admin');
  assert.equal(resAdmin.status, 200);
});
