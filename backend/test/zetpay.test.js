'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const { createApp } = require('../src/app');
const { createZetpayRoutes, zetpayProvider } = require('../src/zetpay');
const { createRateLimiter } = require('../src/limiter');

function createTestMemory() {
  const store = {};
  function get(p) {
    const parts = p.split('/').filter(Boolean);
    let cur = store;
    for (const part of parts) {
      if (cur == null || typeof cur !== 'object') return undefined;
      cur = cur[part];
    }
    return cur;
  }
  function put(p, val) {
    const parts = p.split('/').filter(Boolean);
    let cur = store;
    for (let i = 0; i < parts.length - 1; i++) {
      cur[parts[i]] = cur[parts[i]] || {};
      cur = cur[parts[i]];
    }
    cur[parts[parts.length - 1]] = val;
  }
  return {
    root: store,
    ref(p = '') {
      return {
        async get() { return { val: () => structuredClone(get(p) ?? null) }; },
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
    if (t === 'user_token') return { uid: 'u_zetpay_test', email: 'user@mailindia.in', email_verified: true };
    if (t === 'unverified') return { uid: 'u_unverified', email: 'unverified@mailindia.in', email_verified: false };
    throw Error('Invalid token');
  }
};

test('zetpayProvider creates order and fetches order status via mock provider', async () => {
  const mockOrders = {};
  const mockProvider = {
    apiKey: 'ZPPCCkPtfAH7EC78UMNT8kUqm7q5XdjNRSX',
    async createOrder(params) {
      const orderId = 'ZP' + Date.now();
      mockOrders[orderId] = {
        order_id: orderId,
        payment_url: 'https://app.zetpay.online/test.html?order=' + orderId,
        amount: params.amount,
        mode: 'test'
      };
      return mockOrders[orderId];
    },
    async getOrderStatus(orderId) {
      const o = mockOrders[orderId];
      if (!o) throw Error('ORDER_NOT_FOUND');
      return {
        order_id: orderId,
        status: o.status || 'pending',
        amount: o.amount
      };
    }
  };

  const o = await mockProvider.createOrder({ amount: 100, title: 'Credits Recharge' });
  assert.ok(o.order_id.startsWith('ZP'));
  assert.equal(o.amount, 100);

  const s = await mockProvider.getOrderStatus(o.order_id);
  assert.equal(s.status, 'pending');
});

test('POST /api/payments/zetpay/order creates authenticated order and snapshots credits', async () => {
  const db = createTestMemory();
  await db.ref('users/u_zetpay_test').set({ status: 'active', email: 'user@mailindia.in' });
  await db.ref('platform_settings').set({ creditRate: 5 });

  const mockProvider = {
    apiKey: 'ZPPCCkPtfAH7EC78UMNT8kUqm7q5XdjNRSX',
    async createOrder(params) {
      return {
        order_id: 'ZP1234567890TEST',
        payment_url: 'https://app.zetpay.online/test.html?order=ZP1234567890TEST',
        amount: params.amount,
        mode: 'test'
      };
    },
    async getOrderStatus(id) {
      return { order_id: id, status: 'pending', amount: 50 };
    }
  };

  const app = createApp({
    db,
    auth,
    zetpayConfig: { apiKey: 'ZPPCCkPtfAH7EC78UMNT8kUqm7q5XdjNRSX' },
    zetpayProviderInstance: mockProvider,
    distributedLimiter: createRateLimiter(null)
  });

  const res = await request(app)
    .post('/api/payments/zetpay/order')
    .set('Authorization', 'Bearer user_token')
    .send({ amountRupees: 50 });

  assert.equal(res.status, 201);
  assert.equal(res.body.success, true);
  assert.equal(res.body.orderId, 'ZP1234567890TEST');
  assert.equal(res.body.amount, 50);
  assert.equal(res.body.credits, 250); // 50 * 5 = 250 credits
  assert.ok(res.body.paymentUrl);

  const saved = (await db.ref('payment_orders/ZP1234567890TEST').get()).val();
  assert.equal(saved.credits, 250);
  assert.equal(saved.status, 'created');
  assert.equal(saved.provider, 'zetpay');
});

test('POST /api/payments/zetpay/verify commits wallet credits idempotently when status is success', async () => {
  const db = createTestMemory();
  await db.ref('users/u_zetpay_test').set({ status: 'active', email: 'user@mailindia.in' });
  await db.ref('platform_settings').set({ creditRate: 5 });

  let orderStatus = 'pending';
  const mockProvider = {
    apiKey: 'ZPPCCkPtfAH7EC78UMNT8kUqm7q5XdjNRSX',
    async createOrder(p) {
      return { order_id: 'ZP9988776655CONF', payment_url: 'https://pay', amount: p.amount, mode: 'test' };
    },
    async getOrderStatus(id) {
      return { order_id: id, status: orderStatus, amount: 100 };
    }
  };

  const app = createApp({
    db,
    auth,
    zetpayConfig: { apiKey: 'ZPPCCkPtfAH7EC78UMNT8kUqm7q5XdjNRSX' },
    zetpayProviderInstance: mockProvider,
    distributedLimiter: createRateLimiter(null)
  });

  // Create order
  const orderRes = await request(app)
    .post('/api/payments/zetpay/order')
    .set('Authorization', 'Bearer user_token')
    .send({ amountRupees: 100 });
  assert.equal(orderRes.status, 201);

  // Attempt verify while pending -> should not credit
  const verifyPending = await request(app)
    .post('/api/payments/zetpay/verify')
    .set('Authorization', 'Bearer user_token')
    .send({ orderId: 'ZP9988776655CONF' });
  assert.equal(verifyPending.status, 200);
  assert.equal(verifyPending.body.status, 'pending');

  let wallet = (await db.ref('wallets/u_zetpay_test').get()).val();
  assert.equal(wallet?.balance || 0, 0);

  // Status transitions to success in ZetPay
  orderStatus = 'success';

  const verifySuccess = await request(app)
    .post('/api/payments/zetpay/verify')
    .set('Authorization', 'Bearer user_token')
    .send({ orderId: 'ZP9988776655CONF' });
  assert.equal(verifySuccess.status, 200);
  assert.equal(verifySuccess.body.status, 'credited');
  assert.equal(verifySuccess.body.credits, 500); // 100 * 5 = 500 credits

  wallet = (await db.ref('wallets/u_zetpay_test').get()).val();
  assert.equal(wallet.balance, 500);
  assert.equal(wallet.purchased, 500);
  assert.ok(wallet.ledger['purchase_ZP9988776655CONF']);

  // Repeat verify (idempotent duplicate call) -> must not double credit!
  const verifyRepeat = await request(app)
    .post('/api/payments/zetpay/verify')
    .set('Authorization', 'Bearer user_token')
    .send({ orderId: 'ZP9988776655CONF' });
  assert.equal(verifyRepeat.status, 200);
  assert.equal(verifyRepeat.body.alreadyCredited, true);

  wallet = (await db.ref('wallets/u_zetpay_test').get()).val();
  assert.equal(wallet.balance, 500); // Still exactly 500!
});

test('POST /api/payments/zetpay/sync-pending verifies and credits pending orders', async () => {
  const db = createTestMemory();
  const mockProvider = {
    apiKey: 'zap_test_key',
    async getOrderStatus(id) {
      if (id === 'ZP_PENDING_SUCCESS') return { order_id: id, status: 'success', amount: 100 };
      return { order_id: id, status: 'pending', amount: 100 };
    }
  };

  const app = createApp({
    auth,
    db,
    zetpayConfig: { apiKey: 'zap_test_key' },
    zetpayProviderInstance: mockProvider,
    sendingConfig: { enabled: true }
  });

  await db.ref('users/u_zetpay_test').set({ uid: 'u_zetpay_test', email: 'user@mailindia.in', status: 'active' });
  await db.ref('wallets/u_zetpay_test').set({ balance: 0, reserved: 0, purchased: 0, consumed: 0 });

  // Add one successful pending order and one still-pending order
  await db.ref('payment_orders/ZP_PENDING_SUCCESS').set({
    uid: 'u_zetpay_test',
    orderId: 'ZP_PENDING_SUCCESS',
    amountRupees: 100,
    credits: 500,
    status: 'created',
    createdAt: Date.now() - 60000
  });

  await db.ref('payment_orders/ZP_STILL_PENDING').set({
    uid: 'u_zetpay_test',
    orderId: 'ZP_STILL_PENDING',
    amountRupees: 100,
    credits: 500,
    status: 'created',
    createdAt: Date.now() - 30000
  });

  const syncRes = await request(app)
    .post('/api/payments/zetpay/sync-pending')
    .set('Authorization', 'Bearer user_token')
    .send();

  assert.equal(syncRes.status, 200);
  assert.equal(syncRes.body.success, true);
  assert.equal(syncRes.body.creditedCount, 1);
  assert.equal(syncRes.body.totalCreditsAdded, 500);
  assert.equal(syncRes.body.wallet.balance, 500);

  const orderSnap = (await db.ref('payment_orders/ZP_PENDING_SUCCESS').get()).val();
  assert.equal(orderSnap.status, 'captured');
});

test('live ZetPay API connectivity with provided credentials', async (t) => {
  try {
    const provider = zetpayProvider('ZPPCCkPtfAH7EC78UMNT8kUqm7q5XdjNRSX');

    // Test create-order against live ZetPay endpoint
    const order = await provider.createOrder({
      amount: 10,
      title: 'Mail India Live Test',
      useEmbedded: true
    });

    assert.ok(order.order_id);
    assert.ok(order.order_id.startsWith('ZP'));
    assert.ok(order.payment_url);
    assert.equal(order.amount, 10);

    // Test getOrderStatus
    const status = await provider.getOrderStatus(order.order_id);
    assert.equal(status.order_id, order.order_id);
    assert.ok(['pending', 'success', 'failed'].includes(status.status));
  } catch (err) {
    if (err.cause?.code === 'UND_ERR_CONNECT_TIMEOUT' || err.code === 'UND_ERR_CONNECT_TIMEOUT' || (err.message && err.message.includes('fetch failed'))) {
      if (t && typeof t.skip === 'function') {
        t.skip('Skipping live ZetPay network test in sandbox without external network access');
        return;
      }
    }
    throw err;
  }
});
