'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const express = require('express');
const request = require('supertest');
const { adminRoutes } = require('../src/admin');
const { decryptCredentials, encryptCredentials, normalize, reserve, runJob } = require('../src/sending');
const { memoryDb } = require('./helpers/mail-memory');

const key = crypto.randomBytes(32).toString('base64');
function fixture(verify = async () => true) {
  const db = memoryDb({ users: { admin: { email: 'admin@example.com', status: 'active', admin: true }, tenant: { email: 'tenant@example.com', status: 'active' } }, sender_accounts: {} });
  const app = express();
  app.use(express.json());
  app.use('/admin', adminRoutes({ db, key, authenticate(req, res, next) { req.user = { uid: 'admin', email: 'admin@example.com', admin: true, email_verified: true }; next(); }, smtpFactory: () => ({ verify }) }));
  return { app, db };
}
const gmail = { email: 'owner@gmail.com', provider: 'gmail', authType: 'app_password', password: 'abcd efgh ijkl mnop', dailyLimit: 500 };

test('sender save validates Gmail password, encrypts it, and requires a handshake before activation', async () => {
  let verifications = 0;
  const f = fixture(async () => { verifications++; });
  const invalid = await request(f.app).post('/admin/senders').send({ ...gmail, password: 'not-an-app-password' });
  assert.equal(invalid.status, 400);
  assert.equal(invalid.body.error, 'GMAIL_APP_PASSWORD_INVALID');
  const saved = await request(f.app).post('/admin/senders').send(gmail);
  assert.equal(saved.status, 201);
  assert.equal(saved.body.status, 'paused');
  const id = saved.body.id;
  assert.equal(f.db.root.sender_accounts[id].verifiedAt, null);
  assert.equal(decryptCredentials(key, id, f.db.root.sender_accounts[id].credentials).password, 'abcdefghijklmnop');
  assert.equal(verifications, 0);
  const active = await request(f.app).post(`/admin/senders/${id}/status`).send({ status: 'active' });
  assert.equal(active.status, 409);
  assert.equal(active.body.error, 'SENDER_NOT_VERIFIED');
  const verified = await request(f.app).post(`/admin/senders/${id}/verify`).send({});
  assert.equal(verified.status, 200);
  assert.equal(verifications, 1);
  assert.equal(verified.body.status, 'active');
  assert.ok(verified.body.verifiedAt > 0);
  assert.equal(f.db.root.sender_accounts[id].status, 'active');
});

test('SMTP authentication failure stays paused and never returns raw provider credentials', async () => {
  const f = fixture(async () => { throw Object.assign(new Error('private-password-value'), { code: 'EAUTH', responseCode: 535 }); });
  const saved = await request(f.app).post('/admin/senders').send(gmail);
  const verified = await request(f.app).post(`/admin/senders/${saved.body.id}/verify`).send({});
  assert.equal(verified.status, 502);
  assert.equal(verified.body.error, 'SMTP_AUTH_FAILED');
  assert.equal(JSON.stringify(verified.body).includes('private-password-value'), false);
  assert.equal(f.db.root.sender_accounts[saved.body.id].status, 'paused');
});

test('replacing credentials resets verification without resetting daily usage', async () => {
  const f = fixture();
  const saved = await request(f.app).post('/admin/senders').send(gmail);
  const s = f.db.root.sender_accounts[saved.body.id];
  s.status = 'active'; s.verifiedAt = Date.now(); s.usage = { '2026-11-11': 12 };
  const updated = await request(f.app).post('/admin/senders').send({ ...gmail, password: 'ponmlkjihgfedcba' });
  assert.equal(updated.body.id, saved.body.id);
  assert.equal(updated.body.status, 'paused');
  assert.equal(f.db.root.sender_accounts[saved.body.id].verifiedAt, null);
  assert.deepEqual(f.db.root.sender_accounts[saved.body.id].usage, { '2026-11-11': 12 });
});

test('editing a sender during SMTP verification cannot verify the new credentials', async () => {
  let f;
  f = fixture(async () => {
    const id = Object.keys(f.db.root.sender_accounts)[0];
    f.db.root.sender_accounts[id].credentials = encryptCredentials(key, id, { type: 'app_password', password: 'ponmlkjihgfedcba' });
  });
  const saved = await request(f.app).post('/admin/senders').send(gmail);
  const verified = await request(f.app).post(`/admin/senders/${saved.body.id}/verify`).send({});
  assert.equal(verified.status, 409);
  assert.equal(verified.body.error, 'SENDER_CHANGED');
  assert.equal(f.db.root.sender_accounts[saved.body.id].verifiedAt, null);
});

test('admin tenant assignments are explicitly pinned', async () => {
  const f = fixture();
  const saved = await request(f.app).post('/admin/senders').send(gmail);
  const assigned = await request(f.app).post('/admin/assignments').send({ uid: 'tenant', senderId: saved.body.id });
  assert.equal(assigned.status, 200);
  assert.equal(f.db.root.sender_assignments.tenant.manual, true);
  assert.equal(f.db.root.sender_assignments.tenant.senderId, saved.body.id);
});

function workerDb() {
  return memoryDb({ users: { tenant: { status: 'active' } }, wallets: { tenant: { balance: 2, reserved: 0, consumed: 0 } }, sender_assignments: { tenant: { manual: true, senderId: 'gmail1' } }, sender_accounts: {
    gmail1: { email: 'owner@gmail.com', status: 'active', dailyLimit: 10, credentials: encryptCredentials(key, 'gmail1', { type: 'app_password', password: 'abcdefghijklmnop' }) },
    other: { email: 'other@gmail.com', status: 'active', dailyLimit: 10, credentials: encryptCredentials(key, 'other', { type: 'app_password', password: 'ponmlkjihgfedcba' }) }
  } });
}

test('a pinned sender takes precedence over user Gmail OAuth without changing From', async () => {
  const db = workerDb();
  const ref = db.ref.bind(db);
  db.ref = path => { assert.equal(path.startsWith('gmail_connections/'), false, 'Explicit sender must not query or dispatch through another Gmail account'); return ref(path); };
  const message = normalize({ to: 'recipient@example.com', subject: 'Hello', text: 'Message', consent: true });
  const job = await reserve(db, 'tenant', 'pinned-send', message, 'gmail1');
  const sent = [];
  await runJob({ db, key, uid: 'tenant', id: job.id, send: async (sender, payload) => { sent.push({ sender, payload }); return { accepted: [message.to] }; } });
  assert.equal(sent.length, 1);
  assert.equal(sent[0].sender.email, 'owner@gmail.com');
  assert.ok(sent[0].payload.from.includes('owner@gmail.com'));
  assert.equal(db.root.wallets.tenant.sendRequests[job.id].status, 'accepted');
});

test('a paused pinned sender fails instead of substituting another active From account', async () => {
  const db = workerDb();
  const message = normalize({ to: 'recipient@example.com', subject: 'Hello', text: 'Message', consent: true });
  const job = await reserve(db, 'tenant', 'pinned-paused', message, 'gmail1');
  db.root.sender_accounts.gmail1.status = 'paused';
  let sent = 0;
  await runJob({ db, key, uid: 'tenant', id: job.id, send: async () => { sent++; } });
  assert.equal(sent, 0);
  assert.equal(db.root.wallets.tenant.sendRequests[job.id].status, 'failed');
  assert.equal(db.root.wallets.tenant.balance, 2);
});

async function withSystemSender(senderId, run) {
  const previous = process.env.SYSTEM_SENDER_ID;
  process.env.SYSTEM_SENDER_ID = senderId;
  try { await run(); }
  finally {
    if (previous === undefined) delete process.env.SYSTEM_SENDER_ID;
    else process.env.SYSTEM_SENDER_ID = previous;
  }
}

test('global system sender takes precedence over user OAuth when no tenant pin exists', async () => {
  await withSystemSender('gmail1', async () => {
    const db = workerDb();
    delete db.root.sender_assignments.tenant;
    const ref = db.ref.bind(db);
    db.ref = path => { assert.equal(path.startsWith('gmail_connections/'), false); return ref(path); };
    const message = normalize({ to: 'recipient@example.com', subject: 'System sender', text: 'Message', consent: true });
    const job = await reserve(db, 'tenant', 'global-pin', message, 'gmail1');
    const from = [];
    await runJob({ db, key, uid: 'tenant', id: job.id, send: async (sender, payload) => { from.push(payload.from); return { accepted: [message.to] }; } });
    assert.equal(from.length, 1);
    assert.ok(from[0].includes('owner@gmail.com'));
    assert.equal(db.root.wallets.tenant.sendRequests[job.id].status, 'accepted');
  });
});

test('an unavailable global sender does not fall back to an active pool sender', async () => {
  await withSystemSender('gmail1', async () => {
    const db = workerDb();
    delete db.root.sender_assignments.tenant;
    const message = normalize({ to: 'recipient@example.com', subject: 'System sender', text: 'Message', consent: true });
    const job = await reserve(db, 'tenant', 'global-paused', message, 'gmail1');
    db.root.sender_accounts.gmail1.status = 'paused';
    let calls = 0;
    await runJob({ db, key, uid: 'tenant', id: job.id, send: async () => { calls++; } });
    assert.equal(calls, 0);
    assert.equal(db.root.wallets.tenant.sendRequests[job.id].error, 'SENDER_UNAVAILABLE');
    assert.equal(db.root.wallets.tenant.balance, 2);
  });
});

test('a queued job with a different global sender fails instead of changing its From', async () => {
  await withSystemSender('other', async () => {
    const db = workerDb();
    delete db.root.sender_assignments.tenant;
    const message = normalize({ to: 'recipient@example.com', subject: 'Changed system sender', text: 'Message', consent: true });
    const job = await reserve(db, 'tenant', 'global-changed', message, 'gmail1');
    let calls = 0;
    await runJob({ db, key, uid: 'tenant', id: job.id, send: async () => { calls++; } });
    assert.equal(calls, 0);
    assert.equal(db.root.wallets.tenant.sendRequests[job.id].error, 'SENDER_UNAVAILABLE');
  });
});

test('an explicit tenant assignment overrides the global system sender', async () => {
  await withSystemSender('other', async () => {
    const db = workerDb();
    const message = normalize({ to: 'recipient@example.com', subject: 'Tenant sender', text: 'Message', consent: true });
    const job = await reserve(db, 'tenant', 'tenant-before-global', message, 'gmail1');
    const sent = [];
    await runJob({ db, key, uid: 'tenant', id: job.id, send: async sender => { sent.push(sender.email); return { accepted: [message.to] }; } });
    assert.deepEqual(sent, ['owner@gmail.com']);
    assert.equal(db.root.wallets.tenant.sendRequests[job.id].status, 'accepted');
  });
});

test('a user who signed in with Google dispatches via their own connected Gmail instead of admin sender', async () => {
  const prevCid = process.env.GOOGLE_CLIENT_ID;
  const prevSec = process.env.GOOGLE_CLIENT_SECRET;
  process.env.GOOGLE_CLIENT_ID = 'test_mock_client_id';
  process.env.GOOGLE_CLIENT_SECRET = 'test_mock_client_secret';
  try {
    await withSystemSender('admin_sys_sender', async () => {
      const db = workerDb();
      const gUid = 'google_998877';
      db.root.users = db.root.users || {};
      db.root.wallets = db.root.wallets || {};
      db.root.gmail_connections = db.root.gmail_connections || {};
      db.root.users[gUid] = { uid: gUid, email: 'googleuser@gmail.com', status: 'active', authProvider: 'google', name: 'Google User' };
      db.root.wallets[gUid] = { balance: 5, reserved: 0, consumed: 0, sendRequests: {} };
      db.root.gmail_connections[gUid] = {
        email: 'googleuser@gmail.com',
        status: 'active',
        encryptedRefreshToken: encryptCredentials(key, gUid, { refreshToken: 'mock_refresh_token' })
      };

    const originalFetch = globalThis.fetch;
    try {
      globalThis.fetch = async (url) => {
        const s = url.toString();
        if (s.includes('oauth2.googleapis.com/token')) {
          return { ok: true, json: async () => ({ access_token: 'mock_access_token', expires_in: 3600 }) };
        }
        if (s.includes('gmail.googleapis.com')) {
          return { ok: true, json: async () => ({ id: 'gmail_msg_12345', threadId: 'th_1' }) };
        }
        throw new Error('unexpected fetch: ' + s);
      };

      const message = normalize({ to: 'recipient@example.com', subject: 'Google user email', text: 'Hello from my Gmail', consent: true });
      const job = await reserve(db, gUid, 'g-send-1', message, 'user_gmail_' + gUid);

      let smtpSenderCalled = false;
      await runJob({
        db,
        key,
        uid: gUid,
        id: job.id,
        send: async () => { smtpSenderCalled = true; }
      });

      // SMTP sender should NOT have been called because it sent via user's Gmail API!
      assert.equal(smtpSenderCalled, false);
      const updatedJob = db.root.wallets[gUid].sendRequests[job.id];
      assert.equal(updatedJob.status, 'accepted');
      assert.equal(updatedJob.provider, 'gmail_api');
      assert.equal(updatedJob.senderEmail, 'googleuser@gmail.com');
      assert.equal(updatedJob.providerMessageId, 'gmail_msg_12345');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
} finally {
  if (prevCid === undefined) delete process.env.GOOGLE_CLIENT_ID;
  else process.env.GOOGLE_CLIENT_ID = prevCid;
  if (prevSec === undefined) delete process.env.GOOGLE_CLIENT_SECRET;
  else process.env.GOOGLE_CLIENT_SECRET = prevSec;
}
});

