'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const crypto = require('node:crypto');
const { createApp } = require('../src/app');
const { decryptCredentials, transport } = require('../src/sending');

function memoryDb() {
  const root = {
    users: {
      admin: { email: 'admin@mailindia.in', status: 'active', admin: true },
      user1: { email: 'user@example.com', status: 'active', email_verified: true }
    },
    wallets: {
      user1: { balance: 100, reserved: 0, purchased: 100, consumed: 0, sendRequests: {} }
    },
    sender_accounts: {},
    sender_assignments: {},
    suppression_list: {},
    admin_logs: {},
    system_runtime: {}
  };

  function get(p) {
    return p.split('/').filter(Boolean).reduce((v, k) => v?.[k], root);
  }
  function put(p, v) {
    const a = p.split('/').filter(Boolean), k = a.pop();
    let x = root;
    for (const n of a) x = x[n] ??= {};
    if (v === null) delete x[k];
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
    ref(p = '') {
      return {
        async get() { return snap(get(p)); },
        async set(v) { put(p, v); },
        async remove() { put(p, null); },
        child(cp) { return this; },
        async update(obj) { for (const [k, v] of Object.entries(obj)) put([p, k].filter(Boolean).join('/'), v); },
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

const auth = {
  async verifyIdToken(token) {
    if (token === 'admin') return { uid: 'admin', email: 'admin@mailindia.in', email_verified: true, admin: true };
    if (token === 'user') return { uid: 'user1', email: 'user@example.com', email_verified: true };
    throw new Error('invalid');
  }
};

test('all 10 email provider connectors configure and decrypt correctly', async () => {
  const db = memoryDb();
  const app = createApp({ db, auth });

  const connectors = [
    {
      preset: 'gmail',
      body: {
        email: 'dispatch1@gmail.com',
        name: 'Gmail Dispatch',
        authType: 'app_password',
        provider: 'gmail',
        password: 'abcd efgh ijkl mnop',
        dailyLimit: 500
      },
      expectedHost: 'smtp.gmail.com',
      expectedPort: 465,
      expectedSecure: true,
      expectedUser: 'dispatch1@gmail.com',
      expectedCleanPass: 'abcdefghijklmnop'
    },
    {
      preset: 'gmail_oauth',
      body: {
        email: 'oauth@gmail.com',
        name: 'OAuth Sender',
        authType: 'oauth2',
        provider: 'gmail_oauth',
        clientId: 'test-client-id.apps.googleusercontent.com',
        clientSecret: 'mock_client_secret_xyz',
        refreshToken: '1//refresh-token-xyz',
        dailyLimit: 2000
      },
      expectedHost: 'smtp.gmail.com',
      expectedPort: 465,
      expectedSecure: true,
      expectedUser: 'oauth@gmail.com'
    },
    {
      preset: 'outlook',
      body: {
        email: 'billing@mycompany.com',
        name: 'Outlook Billing',
        authType: 'custom_smtp',
        provider: 'outlook',
        password: 'outlook-password-123',
        dailyLimit: 5000
      },
      expectedHost: 'smtp.office365.com',
      expectedPort: 587,
      expectedSecure: false,
      expectedUser: 'billing@mycompany.com'
    },
    {
      preset: 'sendgrid',
      body: {
        email: 'alerts@mycompany.com',
        name: 'SendGrid Alerts',
        authType: 'custom_smtp',
        provider: 'sendgrid',
        password: 'SG.fakeApiKey1234567890',
        dailyLimit: 10000
      },
      expectedHost: 'smtp.sendgrid.net',
      expectedPort: 587,
      expectedSecure: false,
      expectedUser: 'apikey' // Must strictly be apikey
    },
    {
      preset: 'ses',
      body: {
        email: 'notifications@mycompany.com',
        name: 'Amazon SES Cluster',
        authType: 'custom_smtp',
        provider: 'ses',
        username: 'AKIAIOSFODNN7EXAMPLE',
        password: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        dailyLimit: 50000
      },
      expectedHost: 'email-smtp.ap-south-1.amazonaws.com',
      expectedPort: 465,
      expectedSecure: true,
      expectedUser: 'AKIAIOSFODNN7EXAMPLE'
    },
    {
      preset: 'brevo',
      body: {
        email: 'news@mycompany.com',
        name: 'Brevo Marketing Relay',
        authType: 'custom_smtp',
        provider: 'brevo',
        password: 'xsmtpsib-mybrevomasterkey',
        dailyLimit: 10000
      },
      expectedHost: 'smtp-relay.brevo.com',
      expectedPort: 587,
      expectedSecure: false,
      expectedUser: 'news@mycompany.com'
    },
    {
      preset: 'resend',
      body: {
        email: 'team@mycompany.com',
        name: 'Resend Transactional',
        authType: 'custom_smtp',
        provider: 'resend',
        password: 're_1234567890abcdef',
        dailyLimit: 10000
      },
      expectedHost: 'smtp.resend.com',
      expectedPort: 465,
      expectedSecure: true,
      expectedUser: 'resend' // Must strictly be resend
    },
    {
      preset: 'mailgun',
      body: {
        email: 'postmaster@mg.mycompany.com',
        name: 'Mailgun Relay',
        authType: 'custom_smtp',
        provider: 'mailgun',
        password: 'mailgun-secret-password-xyz',
        dailyLimit: 10000
      },
      expectedHost: 'smtp.mailgun.org',
      expectedPort: 587,
      expectedSecure: false,
      expectedUser: 'postmaster@mg.mycompany.com'
    },
    {
      preset: 'postmark',
      body: {
        email: 'invoices@mycompany.com',
        name: 'Postmark Invoicing',
        authType: 'custom_smtp',
        provider: 'postmark',
        password: 'postmark-server-api-token-999',
        dailyLimit: 10000
      },
      expectedHost: 'smtp.postmarkapp.com',
      expectedPort: 587,
      expectedSecure: false,
      expectedUser: 'postmark-server-api-token-999' // Postmark token as username
    },
    {
      preset: 'custom_smtp',
      body: {
        email: 'relay@enterprise.in',
        name: 'Private Linux Postfix Relay',
        authType: 'custom_smtp',
        provider: 'custom_smtp',
        host: 'mail.enterprise.in',
        port: 2525,
        secure: false,
        username: 'postfix_user',
        password: 'postfix_secure_pass_123',
        dailyLimit: 25000
      },
      expectedHost: 'mail.enterprise.in',
      expectedPort: 2525,
      expectedSecure: false,
      expectedUser: 'postfix_user'
    }
  ];

  for (const c of connectors) {
    const res = await request(app)
      .post('/api/admin/senders')
      .set('Authorization', 'Bearer admin')
      .send(c.body);

    assert.equal(res.status, 201, `Failed to register connector ${c.preset}: ${JSON.stringify(res.body)}`);
    assert.ok(res.body.id);

    // Verify stored configuration in Firebase RTDB
    const stored = db.root.sender_accounts[res.body.id];
    assert.ok(stored, `Sender account ${res.body.id} was not saved in DB`);
    assert.equal(stored.email, c.body.email.toLowerCase());
    assert.equal(stored.host, c.expectedHost);
    assert.equal(stored.port, c.expectedPort);
    assert.equal(stored.username, c.expectedUser);
    assert.equal(stored.status, 'active');

    // Verify credential decryption
    const decrypted = decryptCredentials(encKey, res.body.id, stored.credentials);
    assert.equal(decrypted.host, c.expectedHost);
    assert.equal(decrypted.port, c.expectedPort);
    assert.equal(decrypted.secure, c.expectedSecure);

    if (c.body.authType === 'oauth2') {
      assert.equal(decrypted.clientId, c.body.clientId);
      assert.equal(decrypted.clientSecret, c.body.clientSecret);
      assert.equal(decrypted.refreshToken, c.body.refreshToken);
    } else {
      const expectedPass = c.expectedCleanPass || c.body.password;
      assert.equal(decrypted.password, expectedPass);
    }

    // Verify nodemailer transporter creates cleanly without throwing
    const t = transport(stored.email, decrypted);
    assert.ok(t);
    assert.ok(typeof t.sendMail === 'function');
  }

  // Verify list endpoint returns all 10 connectors with masked credentials
  const listRes = await request(app)
    .get('/api/admin/senders')
    .set('Authorization', 'Bearer admin');
  assert.equal(listRes.status, 200);
  assert.equal(listRes.body.senders.length, 10);

  for (const s of listRes.body.senders) {
    assert.equal(s.credentials, undefined, 'Plaintext/encrypted credentials must never leak in sender list');
    assert.ok(s.id);
    assert.ok(s.email);
    assert.ok(s.host);
    assert.ok(s.port);
    assert.ok(s.provider);
  }
});

test('multi-connector round-robin sequentially load balances across active sender accounts', async () => {
  const db = memoryDb();
  const queueJobs = [];
  const fakeQueue = {
    async add(name, data, opts) {
      queueJobs.push({ name, data, opts });
      return { id: opts.jobId };
    }
  };

  const app = createApp({
    db,
    auth,
    sendQueue: fakeQueue,
    sendingConfig: { enabled: true },
    distributedLimiter: async () => true
  });

  // Admin registers 4 active sender accounts: Gmail 1, Gmail 2, Brevo, SendGrid
  const accounts = [
    { email: 'account1@gmail.com', name: 'Sender Alpha', provider: 'gmail', authType: 'app_password', password: 'passone' },
    { email: 'account2@gmail.com', name: 'Sender Beta', provider: 'gmail', authType: 'app_password', password: 'passtwo' },
    { email: 'account3@brevo.com', name: 'Sender Gamma (Brevo)', provider: 'brevo', authType: 'custom_smtp', password: 'passthree' },
    { email: 'account4@sendgrid.com', name: 'Sender Delta (SendGrid)', provider: 'sendgrid', authType: 'custom_smtp', password: 'passfour' }
  ];

  const senderIds = [];
  for (const a of accounts) {
    const res = await request(app)
      .post('/api/admin/senders')
      .set('Authorization', 'Bearer admin')
      .send(a);
    assert.equal(res.status, 201);
    senderIds.push(res.body.id);
  }

  // Sorted sender IDs for deterministic round-robin matching
  const sortedIds = [...senderIds].sort();

  // User sends 8 consecutive test emails
  const assignedSenders = [];
  for (let i = 0; i < 8; i++) {
    const res = await request(app)
      .post('/api/test-email')
      .set('Authorization', 'Bearer user')
      .send({
        to: `recipient${i}@example.com`,
        subject: `Round-robin dispatch #${i}`,
        text: `Message content for round-robin send ${i}`,
        consent: true,
        idempotency_key: `rr-key-${i}-${Date.now()}`
      });

    assert.equal(res.status, 202);
    assert.ok(res.body.message_id);

    // Retrieve the reserved job from user wallet
    const job = db.root.wallets.user1.sendRequests[res.body.message_id];
    assert.ok(job);
    assignedSenders.push(job.senderId);
  }

  // Verify that the 8 sends sequentially rotated through the 4 sender accounts
  assert.equal(assignedSenders.length, 8);
  for (let i = 0; i < 8; i++) {
    const expectedSender = sortedIds[i % sortedIds.length];
    assert.equal(assignedSenders[i], expectedSender, `Send #${i} did not route to expected round-robin sender account`);
  }
});

