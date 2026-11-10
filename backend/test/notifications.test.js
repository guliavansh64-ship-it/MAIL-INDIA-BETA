'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const { createApp } = require('../src/app');

function fakeDb() {
  let root = {};
  const read = p => p ? p.split('/').reduce((o, k) => o?.[k], root) : root;
  const write = (p, v) => {
    let a = p.split('/'), k = a.pop(), o = root;
    for (let x of a) o = o[x] ??= {};
    if (v === null) delete o[k];
    else o[k] = v;
  };
  const snap = (v, key) => ({
    key,
    val: () => v,
    forEach: fn => Object.entries(v || {}).forEach(([k, x]) => fn(snap(x, k)))
  });
  return {
    ref(p = '') {
      let filter = null, limit = null;
      return {
        async get() {
          let v = read(p);
          if (filter) v = Object.fromEntries(Object.entries(v || {}).filter(([, x]) => x[filter.k] === filter.v));
          if (limit) v = Object.fromEntries(Object.entries(v || {}).slice(-limit));
          return snap(v);
        },
        async set(v) { write(p, v); },
        async update(obj) { for (const [k, v] of Object.entries(obj)) write(p ? p + '/' + k : k, v); },
        async remove() { write(p, null); },
        async transaction(fn) {
          let v = fn(read(p));
          write(p, v);
          return { committed: true, snapshot: snap(v) };
        },
        orderByChild(k) { filter = { k }; return this; },
        equalTo(v) { filter.v = v; return this; },
        limitToLast(n) { limit = n; return this; }
      };
    },
    data: () => root
  };
}

const users = {
  alice: { uid: 'alice', email: 'alice@example.com', email_verified: true },
  bob: { uid: 'bob', email: 'bob@example.com', email_verified: true }
};

const auth = {
  async verifyIdToken(t) {
    if (!users[t]) throw Error('bad token');
    return users[t];
  }
};

const db = fakeDb();
const app = createApp({ auth, db });
const bearer = t => ({ Authorization: 'Bearer ' + t });

test('notifications onboarding seeds starter notifications on first access', async () => {
  await request(app).post('/api/session/bootstrap').set(bearer('alice'));
  const res = await request(app).get('/api/notifications').set(bearer('alice'));
  assert.equal(res.status, 200);
  assert.equal(res.body.success, true);
  assert.ok(Array.isArray(res.body.notifications));
  assert.ok(res.body.notifications.length >= 3);
  assert.ok(res.body.unreadCount >= 3);
  const categories = res.body.notifications.map(n => n.category);
  assert.ok(categories.includes('system'));
  assert.ok(categories.includes('billing'));
  assert.ok(categories.includes('security'));
});

test('mark single notification as read updates read flag and decreases unread count', async () => {
  const getRes = await request(app).get('/api/notifications').set(bearer('alice'));
  const firstId = getRes.body.notifications[0].id;
  const initialUnread = getRes.body.unreadCount;

  const readRes = await request(app).post(`/api/notifications/${firstId}/read`).set(bearer('alice'));
  assert.equal(readRes.status, 200);
  assert.equal(readRes.body.success, true);

  const getAfter = await request(app).get('/api/notifications').set(bearer('alice'));
  assert.equal(getAfter.body.unreadCount, initialUnread - 1);
  const target = getAfter.body.notifications.find(n => n.id === firstId);
  assert.equal(target.read, true);
  assert.ok(target.readAt);
});

test('mark all notifications as read marks entire list as read', async () => {
  const readAllRes = await request(app).post('/api/notifications/read-all').set(bearer('alice'));
  assert.equal(readAllRes.status, 200);
  assert.equal(readAllRes.body.success, true);

  const getAfter = await request(app).get('/api/notifications').set(bearer('alice'));
  assert.equal(getAfter.body.unreadCount, 0);
  assert.ok(getAfter.body.notifications.every(n => n.read === true));
});

test('delete single notification removes it from database', async () => {
  const getRes = await request(app).get('/api/notifications').set(bearer('alice'));
  const targetId = getRes.body.notifications[0].id;
  const initialTotal = getRes.body.notifications.length;

  const delRes = await request(app).delete(`/api/notifications/${targetId}`).set(bearer('alice'));
  assert.equal(delRes.status, 200);
  assert.equal(delRes.body.success, true);

  const getAfter = await request(app).get('/api/notifications').set(bearer('alice'));
  assert.equal(getAfter.body.notifications.length, initialTotal - 1);
  assert.equal(getAfter.body.notifications.some(n => n.id === targetId), false);
});

test('tenant isolation: users cannot see or mutate other users notifications', async () => {
  await request(app).post('/api/session/bootstrap').set(bearer('bob'));
  const bobRes = await request(app).get('/api/notifications').set(bearer('bob'));
  assert.equal(bobRes.status, 200);
  const bobId = bobRes.body.notifications[0].id;

  // Alice tries to mark Bob's notification as read
  const hackRes = await request(app).post(`/api/notifications/${bobId}/read`).set(bearer('alice'));
  assert.equal(hackRes.status, 404);

  // Alice tries to delete Bob's notification
  const hackDel = await request(app).delete(`/api/notifications/${bobId}`).set(bearer('alice'));
  assert.equal(hackDel.status, 200); // deletes alice's non-existent path without touching bob
  const bobCheck = await request(app).get('/api/notifications').set(bearer('bob'));
  assert.ok(bobCheck.body.notifications.some(n => n.id === bobId));
});

test('clear all notifications deletes entire notification history', async () => {
  const clearRes = await request(app).delete('/api/notifications').set(bearer('bob'));
  assert.equal(clearRes.status, 200);
  assert.equal(clearRes.body.success, true);
  // Database node for bob is removed
  assert.equal(db.data().notifications?.bob, undefined);
});
