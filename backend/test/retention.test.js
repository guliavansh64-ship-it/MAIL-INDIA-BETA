'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const { createApp } = require('../src/app');
const { runRetentionCleanup, purgeUserData } = require('../src/retention');

function createTestMemory() {
  const now = Date.now();
  const day = 86400000;
  const root = {
    users: {
      admin: { email: 'admin@example.com', status: 'active' },
      u1: { email: 'u1@example.com', status: 'active', name: 'John Doe' }
    },
    wallets: {
      u1: {
        balance: 50,
        reserved: 0,
        purchased: 50,
        consumed: 0,
        paymentOrders: { ord_1: 'pay_1' },
        sendRequests: {
          job_old: {
            id: 'job_old',
            status: 'accepted',
            createdAt: now - (40 * day), // 40 days old (> 30 days content policy)
            message: { to: 'customer@example.com', text: 'Secret message body', html: '<p>Secret</p>' }
          },
          job_fresh: {
            id: 'job_fresh',
            status: 'accepted',
            createdAt: now - (5 * day),
            message: { to: 'fresh@example.com', text: 'Fresh body', html: '<p>Fresh</p>' }
          }
        },
        ledger: {
          purchase_ord_1: { type: 'purchase', credits: 50, amountPaise: 1000, reference: 'pay_1', createdAt: now - (40 * day) }
        }
      }
    },
    user_api_keys: {
      u1: {
        key_1: { name: 'Prod Key', prefix: 'mb_live_123', status: 'active' }
      }
    },
    key_index: {
      hash_1: { uid: 'u1', keyId: 'key_1', status: 'active' }
    },
    email_logs: {
      u1: {
        log_expired: { id: 'log_expired', recipient: 'old@example.com', createdAt: now - (100 * day) }, // 100 days (> 90 days log policy)
        log_recent: { id: 'log_recent', recipient: 'recent@example.com', createdAt: now - (10 * day) }
      }
    },
    support_tickets: {
      u1: {
        ticket_closed_old: { subject: 'Old help', status: 'closed', closedAt: now - (200 * day) },
        ticket_open: { subject: 'Active ticket', status: 'open', createdAt: now - (5 * day) }
      }
    },
    data_deletion_logs: {},
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
    if (t === 'u1') return { uid: 'u1', email: 'u1@example.com', email_verified: true };
    throw Error('unauthenticated');
  }
};

test('data retention cleanup purges expired logs, closed tickets, and redacts old message bodies', async () => {
  const db = createTestMemory();
  const res = await runRetentionCleanup(db, 'admin');

  assert.equal(res.logsPurged, 1);
  assert.equal(res.messageContentPurged, 1);
  assert.equal(res.ticketsPurged, 1);

  // Expired log purged; recent log remains
  assert.equal(db.root.email_logs.u1.log_expired, undefined);
  assert.ok(db.root.email_logs.u1.log_recent);

  // Old email body redacted; fresh remains intact
  assert.equal(db.root.wallets.u1.sendRequests.job_old.message.text, '[PURGED_RETENTION_POLICY]');
  assert.equal(db.root.wallets.u1.sendRequests.job_fresh.message.text, 'Fresh body');

  // Old closed ticket purged; active remains
  assert.equal(db.root.support_tickets.u1.ticket_closed_old, undefined);
  assert.ok(db.root.support_tickets.u1.ticket_open);
});

test('GDPR user data deletion anonymizes personal information while preserving financial ledgers', async () => {
  const db = createTestMemory();
  const res = await purgeUserData(db, 'u1', 'gdpr_request');

  assert.equal(res.financialRecordsPreserved, true);

  // Profile anonymized
  assert.equal(db.root.users.u1.name, 'Anonymized User');
  assert.ok(db.root.users.u1.email.endsWith('@privacy.local'));
  assert.equal(db.root.users.u1.status, 'deleted');

  // API keys revoked & cleared
  assert.equal(db.root.user_api_keys.u1.key_1.status, 'revoked');
  assert.equal(Object.keys(db.root.key_index).length, 0);

  // Email logs purged
  assert.equal(db.root.email_logs.u1, undefined);

  // Send request recipient anonymized and message text purged
  assert.equal(db.root.wallets.u1.sendRequests.job_fresh.message.to, 'anonymized@privacy.local');
  assert.equal(db.root.wallets.u1.sendRequests.job_fresh.message.text, '[DELETED_UNDER_GDPR]');

  // Financial ledgers & balance strictly preserved
  assert.equal(db.root.wallets.u1.balance, 50);
  assert.ok(db.root.wallets.u1.ledger.purchase_ord_1);
  assert.equal(db.root.wallets.u1.paymentOrders.ord_1, 'pay_1');

  // Audit entry recorded
  assert.equal(Object.keys(db.root.data_deletion_logs).length, 1);
});
