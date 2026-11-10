'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const crypto = require('node:crypto');
const { createApp } = require('../src/app');
const { recordBounce, recordComplaint, isSuppressed } = require('../src/bounces');

function createTestMemory() {
  const root = {
    users: {
      admin: { email: 'admin@example.com', status: 'active' },
      u1: { email: 'u1@example.com', status: 'active' }
    },
    wallets: {
      u1: { balance: 10, reserved: 0, purchased: 10, consumed: 0 }
    },
    suppression_list: {},
    bounce_records: {},
    complaint_records: {}
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

test('hard bounce immediately adds recipient to permanent suppression list', async () => {
  const db = createTestMemory();
  const recipient = 'hardbounce@example.com';
  const res = await recordBounce(db, {
    recipient,
    type: 'hard',
    reason: '550 5.1.1 User unknown'
  });

  assert.equal(res.suppressed, true);
  const suppressed = await isSuppressed(db, recipient);
  assert.equal(suppressed, true);

  const hash = crypto.createHash('sha256').update(recipient).digest('hex');
  assert.equal(db.root.suppression_list[hash].type, 'hard_bounce');
});

test('repeated soft bounces trigger automatic suppression on threshold', async () => {
  const db = createTestMemory();
  const recipient = 'softbounce@example.com';

  // 1st soft bounce: not suppressed yet
  const b1 = await recordBounce(db, { recipient, type: 'soft', reason: '451 Mailbox full' });
  assert.equal(b1.suppressed, false);
  assert.equal(await isSuppressed(db, recipient), false);

  // 2nd soft bounce
  await recordBounce(db, { recipient, type: 'soft', reason: '451 Mailbox full' });
  assert.equal(await isSuppressed(db, recipient), false);

  // 3rd soft bounce within 7 days: triggers suppression!
  await recordBounce(db, { recipient, type: 'soft', reason: '451 Mailbox full' });
  assert.equal(await isSuppressed(db, recipient), true);

  const hash = crypto.createHash('sha256').update(recipient).digest('hex');
  assert.equal(db.root.suppression_list[hash].type, 'repeated_soft_bounce');
});

test('spam complaint immediately permanently suppresses recipient', async () => {
  const db = createTestMemory();
  const recipient = 'complainer@example.com';
  const res = await recordComplaint(db, { recipient, reason: 'Feedback loop abuse report' });

  assert.equal(res.suppressed, true);
  assert.equal(await isSuppressed(db, recipient), true);
  const hash = crypto.createHash('sha256').update(recipient).digest('hex');
  assert.equal(db.root.suppression_list[hash].type, 'complaint');
});

test('admin can ingest bounce reports via administrative API', async () => {
  const db = createTestMemory();
  const app = createApp({ db, auth });

  const res = await request(app)
    .post('/api/admin/bounces/ingest')
    .set('Authorization', 'Bearer admin')
    .send({
      recipient: 'ndr_report@example.com',
      type: 'hard',
      reason: 'Host not found'
    });

  assert.equal(res.status, 201);
  assert.equal(await isSuppressed(db, 'ndr_report@example.com'), true);
});
