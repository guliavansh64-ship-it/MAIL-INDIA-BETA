'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const { createApp } = require('../src/app');
const { performReconciliation } = require('../src/reconciliation');
const { verifyLedgerIntegrity } = require('../scripts/verify-ledger-integrity');

function createTestMemory() {
  const root = {
    users: {
      admin: { email: 'admin@example.com', status: 'active' },
      u1: { email: 'u1@example.com', status: 'active' },
      u2: { email: 'u2@example.com', status: 'active' }
    },
    wallets: {
      u1: {
        balance: 50,
        reserved: 0,
        purchased: 50,
        consumed: 0,
        paymentOrders: { order_matched: 'pay_matched' },
        ledger: {
          purchase_order_matched: { type: 'purchase', credits: 50, amountPaise: 1000, reference: 'pay_matched', createdAt: 1000 }
        }
      },
      u2: {
        balance: 0,
        reserved: 0,
        purchased: 0,
        consumed: 0,
        paymentOrders: {},
        ledger: {}
      }
    },
    payment_orders: {
      order_matched: {
        uid: 'u1',
        amountPaise: 1000,
        credits: 50,
        status: 'captured',
        paymentId: 'pay_matched',
        createdAt: 1000,
        capturedAt: 1000
      },
      order_missing_credit: {
        uid: 'u2',
        amountPaise: 2000,
        credits: 100,
        status: 'captured',
        paymentId: 'pay_missing',
        createdAt: 2000,
        capturedAt: 2000
      }
    },
    payment_refunds: {
      rfnd_missing_ledger: {
        id: 'rfnd_missing_ledger',
        orderId: 'order_matched',
        paymentId: 'pay_matched',
        uid: 'u1',
        amountPaise: 200,
        creditsToRecover: 10,
        status: 'completed',
        createdAt: 3000
      }
    },
    payment_disputes: {},
    admin_logs: {}
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
    throw Error('unauthenticated');
  }
};

test('financial reconciliation correctly identifies matched, missing credits and missing refunds', async () => {
  const db = createTestMemory();
  const report = await performReconciliation(db);

  assert.equal(report.matched.length, 1);
  assert.equal(report.matched[0].orderId, 'order_matched');

  assert.equal(report.missingWalletCredits.length, 1);
  assert.equal(report.missingWalletCredits[0].orderId, 'order_missing_credit');

  assert.equal(report.missingRefundEntries.length, 1);
  assert.equal(report.missingRefundEntries[0].refundId, 'rfnd_missing_ledger');
});

test('admin can resolve missing wallet credit discrepancy through audit resolution', async () => {
  const db = createTestMemory();
  const app = createApp({ db, auth });

  const res = await request(app)
    .post('/api/admin/reconciliation/financial/resolve')
    .set('Authorization', 'Bearer admin')
    .send({
      type: 'missing_credit',
      orderId: 'order_missing_credit',
      uid: 'u2',
      reason: 'Captured payment verified against Razorpay bank statement',
      operationId: 'op_recon_credit_1001'
    });

  assert.equal(res.status, 200);
  assert.equal(db.root.wallets.u2.balance, 100);
  assert.equal(db.root.wallets.u2.purchased, 100);
  assert.ok(db.root.wallets.u2.ledger.reconciliation_op_recon_credit_1001);
});

test('ledger integrity verifier detects inconsistencies and verifies valid states', async () => {
  const db = createTestMemory();
  // u1 has missing refund in wallet ledger, but balance is 50 matching ledger purchases
  const check = await verifyLedgerIntegrity(db);
  assert.equal(check.valid, true);

  // Intentionally inject invalid balance
  db.root.wallets.u1.balance = 999;
  const invalidCheck = await verifyLedgerIntegrity(db);
  assert.equal(invalidCheck.valid, false);
  assert.equal(invalidCheck.issues[0].error, 'BALANCE_LEDGER_MISMATCH');
});
