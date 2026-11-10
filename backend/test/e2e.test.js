'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const crypto = require('node:crypto');
const { createApp, hashKey } = require('../src/app');
const { runJob, encryptCredentials } = require('../src/sending');
const { createRateLimiter } = require('../src/limiter');

function createE2EMemory() {
  const root = {
    users: {
      admin_uid: { email: 'admin@mailbridge.local', status: 'active', name: 'Platform Admin' }
    },
    wallets: {},
    payment_orders: {},
    payment_refunds: {},
    payment_disputes: {},
    sender_accounts: {},
    sender_assignments: {},
    email_logs: {},
    user_api_keys: {},
    key_index: {},
    platform_settings: {
      creditRate: 5
    },
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

test('complete 18-step end-to-end integration workflow', async () => {
  const db = createE2EMemory();
  const encryptionKey = crypto.randomBytes(32).toString('base64');
  const nowSec = Math.floor(Date.now() / 1000);

  let verifiedUserToken = {
    uid: 'test_user_e2e',
    email: 'customer@example.com',
    email_verified: true,
    auth_time: nowSec
  };

  const auth = {
    async verifyIdToken(t) {
      if (t === 'admin_token') return { uid: 'admin_uid', email: 'admin@mailbridge.local', email_verified: true, admin: true };
      if (t === 'user_token') return verifiedUserToken;
      throw Error('Invalid token');
    },
    async createSessionCookie(token) { return 'session_cookie_' + token; },
    async verifySessionCookie(cookie) {
      if (cookie.includes('user_token')) return verifiedUserToken;
      throw Error('Invalid session');
    }
  };

  let mockPaymentStore = {};
  const paymentProvider = {
    async createOrder(o) {
      const id = 'order_e2e1';
      mockPaymentStore[id] = { id, amount: o.amount, currency: 'INR', status: 'created' };
      return mockPaymentStore[id];
    },
    async getPayment(pId) {
      return {
        id: pId,
        order_id: 'order_e2e1',
        amount: 1000,
        currency: 'INR',
        status: 'captured',
        amount_refunded: 0
      };
    },
    async createRefund(pId, data) {
      return {
        id: 'rfnd_e2e_1',
        payment_id: pId,
        amount: data.amount,
        status: 'processed'
      };
    }
  };

  const paymentConfig = {
    enabled: true,
    keyId: 'rzp_test_e2ekey',
    keySecret: 'secret_key_123',
    webhookSecret: 'webhook_secret_123'
  };

  // Mock queue that immediately processes job
  const queuedJobs = [];
  const sendQueue = {
    async add(name, data) {
      queuedJobs.push(data);
    }
  };

  const limiter = createRateLimiter(null);

  const app = createApp({
    db,
    auth,
    paymentConfig,
    paymentProvider,
    sendingConfig: { enabled: true, encryptionKey },
    sendQueue,
    distributedLimiter: limiter
  });

  const sign = (key, body) => crypto.createHmac('sha256', key).update(body).digest('hex');

  // STEP 1: Register a user (bootstrap)
  const bootstrapRes = await request(app)
    .post('/api/session/bootstrap')
    .set('Authorization', 'Bearer user_token')
    .send({});
  assert.equal(bootstrapRes.status, 200);
  assert.equal(bootstrapRes.body.user.email, 'customer@example.com');

  // STEP 2: Verify email
  assert.equal(bootstrapRes.body.user.emailVerified, true);

  // STEP 3: Login & session cookie
  const loginRes = await request(app)
    .post('/api/session/login')
    .set('Authorization', 'Bearer user_token');
  assert.equal(loginRes.status, 200);
  assert.ok(loginRes.body.csrf);
  const sessionCookie = loginRes.headers['set-cookie'][0].split(';')[0];
  const csrfCookie = loginRes.headers['set-cookie'][1].split(';')[0];

  // STEP 4: Purchase ₹10 in Razorpay sandbox
  const orderRes = await request(app)
    .post('/api/payments/orders')
    .set('Authorization', 'Bearer user_token')
    .send({ amountPaise: 1000 });
  assert.equal(orderRes.status, 201);
  assert.equal(orderRes.body.credits, 50);
  const orderId = orderRes.body.orderId;

  // STEP 5: Verify payment checkout callback
  const verifySig = sign(paymentConfig.keySecret, `${orderId}|pay_e2e1`);
  const verifyRes = await request(app)
    .post('/api/payments/verify')
    .set('Authorization', 'Bearer user_token')
    .send({
      razorpay_order_id: orderId,
      razorpay_payment_id: 'pay_e2e1',
      razorpay_signature: verifySig
    });
  assert.equal(verifyRes.status, 200);
  assert.equal(verifyRes.body.status, 'awaiting_webhook');

  // STEP 6: Deliver webhook & add exactly 50 credits
  const captureWebhook = JSON.stringify({
    event: 'payment.captured',
    payload: {
      payment: {
        entity: { id: 'pay_e2e1', order_id: orderId }
      }
    }
  });
  const captureRes = await request(app)
    .post('/api/payments/webhook')
    .set('Content-Type', 'application/json')
    .set('X-Razorpay-Event-Id', 'evt_e2e_capture')
    .set('X-Razorpay-Signature', sign(paymentConfig.webhookSecret, captureWebhook))
    .send(captureWebhook);
  assert.equal(captureRes.status, 200);
  assert.equal(db.root.wallets.test_user_e2e.balance, 50);
  assert.equal(db.root.wallets.test_user_e2e.purchased, 50);

  // STEP 7: Generate an API key
  const keyRes = await request(app)
    .post('/api/keys')
    .set('Authorization', 'Bearer user_token')
    .send({ name: 'E2E Testing Key' });
  assert.equal(keyRes.status, 201);
  const apiKey = keyRes.body.key;
  assert.ok(apiKey.startsWith('mb_live_'));

  // Setup sender in pool and pin to user
  const senderId = 'sender_e2e_id';
  const credentials = encryptCredentials(encryptionKey, senderId, { type: 'app_password', password: 'testpassword' });
  db.root.sender_accounts[senderId] = {
    email: 'sender@mailbridge.local',
    credentials,
    dailyLimit: 100,
    status: 'active'
  };
  db.root.sender_assignments.test_user_e2e = { senderId };

  // STEP 8: Send a legitimate test email
  const idempotencyKey = 'idemp_key_e2e_1';
  const sendRes = await request(app)
    .post('/v1/emails/send')
    .set('Authorization', `Bearer ${apiKey}`)
    .set('Idempotency-Key', idempotencyKey)
    .send({
      to: 'recipient@partner.com',
      subject: 'E2E Test Subject',
      text: 'Hello from MailBridge API!',
      consent: true
    });
  assert.equal(sendRes.status, 202);
  assert.equal(sendRes.body.status, 'queued');
  const messageId = sendRes.body.message_id;

  // STEP 9: Verify Gmail provider acceptance via SMTP worker
  let mockSmtpSent = false;
  const mockSend = async (sender, msg) => {
    mockSmtpSent = true;
    return { accepted: [msg.to], messageId: '<provider.12345@gmail.com>' };
  };

  await runJob({
    db,
    key: encryptionKey,
    uid: 'test_user_e2e',
    id: messageId,
    send: mockSend
  });
  assert.equal(mockSmtpSent, true);

  // STEP 10: Deduct exactly one credit
  const walletAfterSend = db.root.wallets.test_user_e2e;
  assert.equal(walletAfterSend.consumed, 1);
  assert.equal(walletAfterSend.reserved, 0);

  // STEP 11: Confirm 49 credits remain
  assert.equal(walletAfterSend.balance, 49);

  // STEP 12: Confirm email appears in user logs
  const userLogsRes = await request(app)
    .get('/v1/emails')
    .set('Authorization', `Bearer ${apiKey}`);
  assert.equal(userLogsRes.status, 200);
  assert.equal(userLogsRes.body.emails.length, 1);
  assert.equal(userLogsRes.body.emails[0].status, 'accepted');
  assert.equal(userLogsRes.body.emails[0].recipient, 'recipient@partner.com');

  // STEP 13: Confirm email appears in admin monitoring
  const adminMonRes = await request(app)
    .get('/api/admin/monitoring/emails')
    .set('Authorization', 'Bearer admin_token');
  assert.equal(adminMonRes.status, 200);
  assert.ok(adminMonRes.body.emails.some(e => e.id === messageId && e.status === 'accepted'));

  // STEP 14: Process a test refund
  const refundRes = await request(app)
    .post(`/api/admin/payments/${orderId}/refund`)
    .set('Authorization', 'Bearer admin_token')
    .send({ amountPaise: 400, reason: 'Test partial refund' }); // 40% of order = 20 credits
  assert.equal(refundRes.status, 201);
  assert.equal(refundRes.body.refund.status, 'completed');
  assert.equal(refundRes.body.refund.creditsToRecover, 20);

  // STEP 15: Verify refund and ledger records
  assert.equal(db.root.wallets.test_user_e2e.balance, 29); // 49 - 20 = 29
  assert.ok(db.root.wallets.test_user_e2e.ledger.refund_rfnd_e2e_1);

  // STEP 16: Verify admin reconciliation
  const reconRes = await request(app)
    .get('/api/admin/reconciliation/financial')
    .set('Authorization', 'Bearer admin_token');
  assert.equal(reconRes.status, 200);
  assert.equal(reconRes.body.report.summary.errorsCount, 0);

  // STEP 17: Test unknown email outcome handling
  const uncertainIdempKey = 'idemp_uncertain_e2e';
  const sendUncertainRes = await request(app)
    .post('/v1/emails/send')
    .set('Authorization', `Bearer ${apiKey}`)
    .set('Idempotency-Key', uncertainIdempKey)
    .send({
      to: 'unreachable@partner.com',
      subject: 'Uncertain Test',
      text: 'Body',
      consent: true
    });
  assert.equal(sendUncertainRes.status, 202);
  const uncertainMsgId = sendUncertainRes.body.message_id;

  // Mock SMTP error during transmission
  const failingSend = async () => {
    throw new Error('ETIMEDOUT: Connection dropped during DATA transmission');
  };
  await runJob({
    db,
    key: encryptionKey,
    uid: 'test_user_e2e',
    id: uncertainMsgId,
    send: failingSend
  });

  const jobRecord = db.root.wallets.test_user_e2e.sendRequests[uncertainMsgId];
  // Rule: Mark uncertain results as UNKNOWN. Do not automatically resend.
  assert.equal(jobRecord.status, 'unknown');
  assert.equal(db.root.wallets.test_user_e2e.reserved, 1); // Credit remains reserved

  // STEP 18: Verify no duplicate email or duplicate credit charge on retry with same idempotency key
  const retrySendRes = await request(app)
    .post('/v1/emails/send')
    .set('Authorization', `Bearer ${apiKey}`)
    .set('Idempotency-Key', uncertainIdempKey)
    .send({
      to: 'unreachable@partner.com',
      subject: 'Uncertain Test',
      text: 'Body',
      consent: true
    });
  assert.equal(retrySendRes.body.message_id, uncertainMsgId);
  // Credits not charged twice
  assert.equal(db.root.wallets.test_user_e2e.reserved, 1);
  assert.equal(db.root.wallets.test_user_e2e.balance, 28); // 29 - 1 reserved = 28
});
