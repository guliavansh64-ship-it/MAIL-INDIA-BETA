'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const { createApp } = require('../src/app');
const { createRateLimiter } = require('../src/limiter');

function createTestMemory() {
  const root = {
    users: {
      admin: { email: 'admin@example.com', status: 'active' },
      u1: { email: 'u1@example.com', status: 'active', apiRateLimit: 5 }
    },
    wallets: {
      u1: { balance: 10, reserved: 0, purchased: 10, consumed: 0 }
    },
    platform_settings: {
      creditRate: 5
    }
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
    if (t === 'admin') return { uid: 'admin', email: 'admin@example.com', email_verified: true, admin: true };
    if (t === 'u1') return { uid: 'u1', email: 'u1@example.com', email_verified: true };
    throw Error('unauthenticated');
  }
};

test('distributed rate limiter enforces per-user custom limits and throttles excessive requests', async () => {
  const limiter = createRateLimiter(null, { userLimit: 3, keyLimit: 10 });
  const uid = 'test_user_throttle';
  const keyId = 'key_1';

  // First 3 requests pass
  assert.equal(await limiter(uid, keyId, 3), true);
  assert.equal(await limiter(uid, keyId, 3), true);
  assert.equal(await limiter(uid, keyId, 3), true);

  // 4th request throttled
  assert.equal(await limiter(uid, keyId, 3), false);
});

test('scoped rate limiting restricts IP login bursts', async () => {
  const limiter = createRateLimiter(null, { ipLoginLimit: 2 });
  const ip = '192.168.1.100';

  assert.equal(await limiter.checkScoped('ipLogin', ip, 2), true);
  assert.equal(await limiter.checkScoped('ipLogin', ip, 2), true);
  assert.equal(await limiter.checkScoped('ipLogin', ip, 2), false);
});

test('payment order creation obeys payment limit per user', async () => {
  const db = createTestMemory();
  const limiter = createRateLimiter(null, { paymentLimit: 2 });
  const provider = {
    async createOrder(o) { return { id: 'order_testlimit', amount: o.amount, currency: 'INR' }; }
  };
  const app = createApp({
    db,
    auth,
    paymentConfig: { enabled: true, keyId: 'rzp_test_rate', keySecret: 'secret', webhookSecret: 'sec' },
    paymentProvider: provider,
    distributedLimiter: limiter
  });

  const r1 = await request(app).post('/api/payments/orders').set('Authorization', 'Bearer u1').send({ amountPaise: 1000 });
  assert.equal(r1.status, 201);
  const r2 = await request(app).post('/api/payments/orders').set('Authorization', 'Bearer u1').send({ amountPaise: 1000 });
  assert.equal(r2.status, 201);
  const r3 = await request(app).post('/api/payments/orders').set('Authorization', 'Bearer u1').send({ amountPaise: 1000 });
  assert.equal(r3.status, 429);
  assert.equal(r3.body.error, 'RATE_LIMIT_EXCEEDED');
});
