'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const crypto = require('node:crypto');
const { createApp } = require('../src/app');

function createTestMemory() {
  const root = {
    users: {
      admin: { email: 'admin@example.com', status: 'active', name: 'Admin User' },
      u1: { email: 'u1@example.com', status: 'active', name: 'User One' }
    },
    wallets: {
      u1: {
        balance: 50,
        reserved: 0,
        purchased: 50,
        consumed: 0,
        paymentOrders: { order_123: 'pay_123' },
        ledger: {
          purchase_order_123: { type: 'purchase', credits: 50, amountPaise: 1000, reference: 'pay_123', createdAt: Date.now() - 10000 }
        }
      }
    },
    payment_orders: {
      order_123: {
        uid: 'u1',
        amountPaise: 1000,
        credits: 50,
        creditRate: 5,
        status: 'captured',
        paymentId: 'pay_123',
        createdAt: Date.now() - 10000,
        capturedAt: Date.now() - 9000,
        refundedPaise: 0
      }
    },
    payment_refunds: {}
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
    if (t === 'admin_token') return { uid: 'admin', email: 'admin@example.com', email_verified: true, admin: true };
    if (t === 'user_token') return { uid: 'u1', email: 'u1@example.com', email_verified: true };
    throw Error('Invalid token');
  }
};

const paymentConfig = {
  enabled: true,
  keyId: 'rzp_test_refundkey',
  keySecret: 'testsecret',
  webhookSecret: 'websecret'
};

test('admin can initiate full refund and recover wallet credits', async () => {
  const db = createTestMemory();
  const provider = {
    async createRefund(paymentId, data) {
      return { id: 'rfnd_full_1', payment_id: paymentId, amount: data.amount, status: 'processed' };
    }
  };
  const app = createApp({ db, auth, paymentConfig, paymentProvider: provider });

  const res = await request(app)
    .post('/api/admin/payments/order_123/refund')
    .set('Authorization', 'Bearer admin_token')
    .send({ reason: 'Customer requested refund' });

  assert.equal(res.status, 201);
  assert.equal(res.body.success, true);
  assert.equal(res.body.refund.status, 'completed');
  assert.equal(res.body.refund.amountPaise, 1000);
  assert.equal(res.body.refund.creditsToRecover, 50);

  // Check wallet balance is deducted by 50
  assert.equal(db.root.wallets.u1.balance, 0);
  assert.equal(db.root.wallets.u1.purchased, 0);
  assert.ok(db.root.wallets.u1.ledger.refund_rfnd_full_1);
  assert.equal(db.root.payment_orders.order_123.refundedPaise, 1000);
});

test('admin can initiate partial refund and recover proportional credits', async () => {
  const db = createTestMemory();
  const provider = {
    async createRefund(paymentId, data) {
      return { id: 'rfnd_part_1', payment_id: paymentId, amount: data.amount, status: 'processed' };
    }
  };
  const app = createApp({ db, auth, paymentConfig, paymentProvider: provider });

  const res = await request(app)
    .post('/api/admin/payments/order_123/refund')
    .set('Authorization', 'Bearer admin_token')
    .send({ amountPaise: 400, reason: 'Partial goodwill refund' });

  assert.equal(res.status, 201);
  assert.equal(res.body.refund.amountPaise, 400);
  assert.equal(res.body.refund.creditsToRecover, 20); // 40% of 50 credits

  assert.equal(db.root.wallets.u1.balance, 30);
  assert.equal(db.root.payment_orders.order_123.refundedPaise, 400);
});

test('credit recovery requires manual review if credits were already consumed', async () => {
  const db = createTestMemory();
  // Simulate user has already consumed 40 credits, so only 10 remain
  db.root.wallets.u1.balance = 10;
  db.root.wallets.u1.consumed = 40;

  const provider = {
    async createRefund(paymentId, data) {
      return { id: 'rfnd_consumed_1', payment_id: paymentId, amount: data.amount, status: 'processed' };
    }
  };
  const app = createApp({ db, auth, paymentConfig, paymentProvider: provider });

  const res = await request(app)
    .post('/api/admin/payments/order_123/refund')
    .set('Authorization', 'Bearer admin_token')
    .send({ amountPaise: 1000, reason: 'Full refund after consumption' });

  assert.equal(res.status, 201);
  assert.equal(res.body.refund.recoveryStatus, 'manual_review_required');

  // Rule: Never blindly deduct credits into negative! Balance remains non-negative
  assert.equal(db.root.wallets.u1.balance, 10);
  assert.ok(db.root.wallets.u1.ledger.refund_pending_review_rfnd_consumed_1);
});

test('failed refund record is stored and eligible for safe retry', async () => {
  const db = createTestMemory();
  let attempts = 0;
  const provider = {
    async createRefund(paymentId, data) {
      attempts++;
      if (attempts === 1) throw new Error('GATEWAY_TIMEOUT');
      return { id: 'rfnd_retry_success', payment_id: paymentId, amount: data.amount, status: 'processed' };
    }
  };
  const app = createApp({ db, auth, paymentConfig, paymentProvider: provider });

  // 1. Initial attempt fails
  const failedRes = await request(app)
    .post('/api/admin/payments/order_123/refund')
    .set('Authorization', 'Bearer admin_token')
    .send({ amountPaise: 500 });

  assert.equal(failedRes.status, 400);
  const failedRefunds = Object.values(db.root.payment_refunds);
  assert.equal(failedRefunds.length, 1);
  assert.equal(failedRefunds[0].status, 'failed');

  // 2. Retry succeeds
  const retryRes = await request(app)
    .post('/api/admin/refunds/' + failedRefunds[0].id + '/retry')
    .set('Authorization', 'Bearer admin_token')
    .send({});

  assert.equal(retryRes.status, 200);
  assert.equal(retryRes.body.refund.status, 'completed');
  assert.equal(db.root.wallets.u1.balance, 25);
});
