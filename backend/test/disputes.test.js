'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const crypto = require('node:crypto');
const { createApp } = require('../src/app');

function createTestMemory() {
  const root = {
    users: {
      admin: { email: 'admin@example.com', status: 'active' },
      u1: { email: 'u1@example.com', status: 'active' }
    },
    wallets: {
      u1: {
        balance: 50,
        reserved: 0,
        purchased: 50,
        consumed: 0,
        paymentOrders: { order_dsp_1: 'pay_dsp_1' },
        ledger: {
          purchase_order_dsp_1: { type: 'purchase', credits: 50, amountPaise: 1000, reference: 'pay_dsp_1', createdAt: Date.now() - 5000 }
        }
      }
    },
    payment_orders: {
      order_dsp_1: {
        uid: 'u1',
        amountPaise: 1000,
        credits: 50,
        creditRate: 5,
        status: 'captured',
        paymentId: 'pay_dsp_1',
        createdAt: Date.now() - 5000,
        capturedAt: Date.now() - 4000
      }
    },
    payment_disputes: {},
    processed_webhook_events: {}
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
    throw Error('invalid');
  }
};

const cfg = {
  enabled: true,
  keyId: 'rzp_test_dispute',
  keySecret: 'secret',
  webhookSecret: 'disputewebsecret'
};

const sign = (key, body) => crypto.createHmac('sha256', key).update(body).digest('hex');

test('dispute webhook holds credits when user balance is sufficient', async () => {
  const db = createTestMemory();
  const app = createApp({ db, auth, paymentConfig: cfg });

  const eventPayload = JSON.stringify({
    event: 'payment.dispute.created',
    payload: {
      dispute: {
        entity: {
          id: 'disp_1001',
          payment_id: 'pay_dsp_1',
          amount: 1000,
          status: 'open',
          reason_code: 'fraudulent'
        }
      }
    }
  });

  const res = await request(app)
    .post('/api/payments/webhook')
    .set('Content-Type', 'application/json')
    .set('X-Razorpay-Event-Id', 'evt_disp_1')
    .set('X-Razorpay-Signature', sign(cfg.webhookSecret, eventPayload))
    .send(eventPayload);

  assert.equal(res.status, 200);
  assert.equal(res.body.received, true);

  const disp = db.root.payment_disputes.disp_1001;
  assert.ok(disp);
  assert.equal(disp.status, 'open');
  assert.equal(disp.recoveryStatus, 'recovered');
  assert.equal(db.root.wallets.u1.balance, 0); // 50 credits held
  assert.ok(db.root.wallets.u1.ledger.dispute_hold_disp_1001);
});

test('dispute won restores held credits back to user wallet', async () => {
  const db = createTestMemory();
  const app = createApp({ db, auth, paymentConfig: cfg });

  // 1. Initial dispute created & held
  const createPayload = JSON.stringify({
    event: 'payment.dispute.created',
    payload: {
      dispute: {
        entity: { id: 'disp_2002', payment_id: 'pay_dsp_1', amount: 1000, status: 'open' }
      }
    }
  });
  await request(app)
    .post('/api/payments/webhook')
    .set('Content-Type', 'application/json')
    .set('X-Razorpay-Event-Id', 'evt_disp_create')
    .set('X-Razorpay-Signature', sign(cfg.webhookSecret, createPayload))
    .send(createPayload);

  assert.equal(db.root.wallets.u1.balance, 0);

  // 2. Dispute won webhook
  const wonPayload = JSON.stringify({
    event: 'payment.dispute.won',
    payload: {
      dispute: {
        entity: { id: 'disp_2002', payment_id: 'pay_dsp_1', amount: 1000, status: 'won' }
      }
    }
  });
  const resWon = await request(app)
    .post('/api/payments/webhook')
    .set('Content-Type', 'application/json')
    .set('X-Razorpay-Event-Id', 'evt_disp_won')
    .set('X-Razorpay-Signature', sign(cfg.webhookSecret, wonPayload))
    .send(wonPayload);

  assert.equal(resWon.status, 200);
  assert.equal(db.root.payment_disputes.disp_2002.status, 'won');
  // Balance restored to 50
  assert.equal(db.root.wallets.u1.balance, 50);
  assert.ok(db.root.wallets.u1.ledger.dispute_restored_disp_2002);
});

test('admin can submit evidence and resolve unsafe dispute recovery', async () => {
  const db = createTestMemory();
  // Simulate user consumed all credits
  db.root.wallets.u1.balance = 0;
  db.root.wallets.u1.consumed = 50;

  const app = createApp({ db, auth, paymentConfig: cfg });

  const createPayload = JSON.stringify({
    event: 'payment.dispute.created',
    payload: {
      dispute: {
        entity: { id: 'disp_3003', payment_id: 'pay_dsp_1', amount: 1000, status: 'open' }
      }
    }
  });
  await request(app)
    .post('/api/payments/webhook')
    .set('Content-Type', 'application/json')
    .set('X-Razorpay-Event-Id', 'evt_disp_consumed')
    .set('X-Razorpay-Signature', sign(cfg.webhookSecret, createPayload))
    .send(createPayload);

  const disp = db.root.payment_disputes.disp_3003;
  assert.equal(disp.recoveryStatus, 'manual_review_required');
  assert.equal(db.root.wallets.u1.balance, 0); // Not blindly deducted

  // Submit Evidence
  const evRes = await request(app)
    .post('/api/admin/disputes/disp_3003/evidence')
    .set('Authorization', 'Bearer admin')
    .send({ evidence: 'Consent logs and delivery confirmation document ID 999.' });
  assert.equal(evRes.status, 200);
  assert.equal(db.root.payment_disputes.disp_3003.status, 'under_review');

  // Resolve with explicit negative adjustment
  const resResolve = await request(app)
    .post('/api/admin/disputes/disp_3003/recover')
    .set('Authorization', 'Bearer admin')
    .send({ action: 'create_negative_adjustment', reason: 'Dispute closed lost by merchant agreement' });
  assert.equal(resResolve.status, 200);
  assert.equal(db.root.payment_disputes.disp_3003.recoveryStatus, 'explicit_adjustment_applied');
  assert.equal(db.root.wallets.u1.balance, -50);
  assert.ok(db.root.wallets.u1.ledger.dispute_explicit_adjustment_disp_3003);
});
