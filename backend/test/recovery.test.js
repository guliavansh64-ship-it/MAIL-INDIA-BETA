'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const { createApp } = require('../src/app');
const { scanQueueState, autoRecoverStuckJobs, moveToDLQ } = require('../src/recovery');

function createTestMemory() {
  const now = Date.now();
  const root = {
    users: {
      admin: { email: 'admin@example.com', status: 'active' },
      u1: { email: 'u1@example.com', status: 'active' }
    },
    wallets: {
      u1: {
        balance: 10,
        reserved: 2,
        purchased: 12,
        consumed: 0,
        sendRequests: {
          job_stuck_proc: {
            id: 'job_stuck_proc',
            status: 'processing',
            createdAt: now - 400000,
            updatedAt: now - 400000,
            message: { to: 'recip1@example.com', subject: 'Stuck Send' }
          },
          job_stuck_queued: {
            id: 'job_stuck_queued',
            status: 'queued',
            createdAt: now - 400000,
            message: { to: 'recip2@example.com', subject: 'Queued' }
          }
        }
      }
    },
    queue_dlq: {},
    email_logs: {}
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

test('stuck job detection identifies expired processing and queued jobs', async () => {
  const db = createTestMemory();
  const state = await scanQueueState(db);

  assert.equal(state.stuckProcessing.length, 1);
  assert.equal(state.stuckProcessing[0].id, 'job_stuck_proc');
  assert.equal(state.stuckQueued.length, 1);
  assert.equal(state.stuckQueued[0].id, 'job_stuck_queued');
});

test('auto recovery safely marks stuck processing job as UNKNOWN to prevent duplicate email', async () => {
  const db = createTestMemory();
  const res = await autoRecoverStuckJobs(db);

  assert.equal(res.recoveredCount, 1);
  assert.equal(db.root.wallets.u1.sendRequests.job_stuck_proc.status, 'unknown');
  assert.equal(db.root.wallets.u1.sendRequests.job_stuck_proc.error, 'PROCESSING_TIMEOUT_LOCK_EXPIRED');
});

test('jobs can be moved to dead letter queue and inspected', async () => {
  const db = createTestMemory();
  const dlq = await moveToDLQ(db, {
    uid: 'u1',
    id: 'job_stuck_queued',
    error: 'MALFORMED_RECIPIENT_DOMAIN'
  });

  assert.equal(dlq.id, 'job_stuck_queued');
  assert.ok(db.root.queue_dlq.job_stuck_queued);
  assert.equal(db.root.wallets.u1.sendRequests.job_stuck_queued.status, 'dead_letter');
});

test('admin can release pre-send failed job and restore reserved credit', async () => {
  const db = createTestMemory();
  const app = createApp({ db, auth });

  const res = await request(app)
    .post('/api/admin/queue/recover')
    .set('Authorization', 'Bearer admin')
    .send({
      uid: 'u1',
      id: 'job_stuck_queued',
      action: 'release_presend'
    });

  assert.equal(res.status, 200);
  assert.equal(db.root.wallets.u1.balance, 11); // credit restored from 10 to 11
  assert.equal(db.root.wallets.u1.reserved, 1);  // reserved decreased from 2 to 1
  assert.equal(db.root.wallets.u1.sendRequests.job_stuck_queued.status, 'failed');
});
