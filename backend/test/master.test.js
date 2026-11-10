'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const { createApp } = require('../src/app');

function fakeDb() {
  let root = {};
  const read = p => (p ? p.split('/').reduce((o, k) => o?.[k], root) : root);
  const write = (p, v) => {
    let a = p.split('/'),
      k = a.pop(),
      o = root;
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
      let filter = null,
        limit = null;
      return {
        async get() {
          let v = read(p);
          if (filter) v = Object.fromEntries(Object.entries(v || {}).filter(([, x]) => x[filter.k] === filter.v));
          if (limit) v = Object.fromEntries(Object.entries(v || {}).slice(-limit));
          return snap(v);
        },
        async set(v) {
          write(p, v);
        },
        async update(obj) {
          for (const [k, v] of Object.entries(obj)) write(k, v);
        },
        async remove() {
          write(p, null);
        },
        async transaction(fn) {
          let v = fn(read(p));
          write(p, v);
          return { committed: true, snapshot: snap(v) };
        },
        orderByChild(k) {
          filter = { k };
          return this;
        },
        equalTo(v) {
          filter.v = v;
          return this;
        },
        limitToLast(n) {
          limit = n;
          return this;
        }
      };
    },
    data: () => root
  };
}

const users = {
  alice: { uid: 'alice', email: 'alice@example.com', email_verified: true }
};
const auth = {
  async verifyIdToken(t) {
    if (!users[t]) throw Error('bad token');
    return users[t];
  }
};
const db = fakeDb();
const app = createApp({ auth, db, publicConfig: { firebaseConfig: { projectId: 'to-375ee' } } });
const bearer = t => ({ Authorization: 'Bearer ' + t });

test('contacts management API CRUD and duplicate detection', async () => {
  await request(app).post('/api/session/bootstrap').set(bearer('alice'));

  // 1. Initially empty
  let r = await request(app).get('/api/contacts').set(bearer('alice'));
  assert.equal(r.status, 200);
  assert.equal(r.body.contacts.length, 0);

  // 2. Add contact
  r = await request(app)
    .post('/api/contacts')
    .set(bearer('alice'))
    .send({ email: 'rahul@example.com', name: 'Rahul', company: 'Tech India', consent: true });
  assert.equal(r.status, 201);
  assert.equal(r.body.contact.email, 'rahul@example.com');
  const contactId = r.body.contact.id;

  // 3. Duplicate check fails with 409
  r = await request(app)
    .post('/api/contacts')
    .set(bearer('alice'))
    .send({ email: 'rahul@example.com', name: 'Duplicate' });
  assert.equal(r.status, 409);
  assert.equal(r.body.error, 'DUPLICATE_CONTACT');

  // 4. Delete contact
  r = await request(app).delete('/api/contacts/' + contactId).set(bearer('alice'));
  assert.equal(r.status, 200);

  // 5. Contact Groups
  r = await request(app)
    .post('/api/contacts/groups')
    .set(bearer('alice'))
    .send({ name: 'Subscribers', description: 'Active newsletter recipients' });
  assert.equal(r.status, 201);
  assert.equal(r.body.group.name, 'Subscribers');
});

test('templates management API CRUD', async () => {
  // 1. Initially empty
  let r = await request(app).get('/api/templates').set(bearer('alice'));
  assert.equal(r.status, 200);
  assert.equal(r.body.templates.length, 0);

  // 2. Create template
  r = await request(app)
    .post('/api/templates')
    .set(bearer('alice'))
    .send({
      name: 'Welcome Template',
      subject: 'Welcome to MAIL INDIA {{name}}',
      category: 'Onboarding',
      text: 'Hello {{name}}',
      html: '<h1>Hello {{name}}</h1>'
    });
  assert.equal(r.status, 201);
  assert.equal(r.body.template.name, 'Welcome Template');
  const tplId = r.body.template.id;

  // 3. Verify retrieved in list
  r = await request(app).get('/api/templates').set(bearer('alice'));
  assert.equal(r.body.templates.length, 1);
  assert.equal(r.body.templates[0].id, tplId);

  // 4. Delete template
  r = await request(app).delete('/api/templates/' + tplId).set(bearer('alice'));
  assert.equal(r.status, 200);
});

test('all 66 master routes return HTTP 200 OK', async () => {
  const routes = [
    '/',
    '/index.html',
    '/dashboard.html',
    '/overview.html',
    '/quick-actions.html',
    '/recent-activity.html',
    '/emails/all.html',
    '/send-email.html',
    '/send-test.html',
    '/send-bulk.html',
    '/email-history.html',
    '/email-templates.html',
    '/contacts.html',
    '/contacts/suppression.html',
    '/wallet.html',
    '/billing/buy.html',
    '/recharge-history.html',
    '/billing/transactions.html',
    '/billing/invoices.html',
    '/billing/pricing.html',
    '/api-docs.html',
    '/api-management.html',
    '/api-playground.html',
    '/api/webhooks.html',
    '/api/rate-limits.html',
    '/api/logs.html',
    '/usage-analytics.html',
    '/analytics/delivery.html',
    '/analytics/bounces.html',
    '/analytics/consumption.html',
    '/profile.html',
    '/account.html',
    '/security/sessions.html',
    '/security/export.html',
    '/help/index.html',
    '/support.html',
    '/help/status.html',
    '/admin',
    '/admin/',
    '/admin/index.html',
    '/admin/analytics.html',
    '/admin/activity.html',
    '/admin/health.html',
    '/admin/users.html',
    '/admin/user-details.html',
    '/admin/credits.html',
    '/admin/email-logs.html',
    '/admin/abuse.html',
    '/admin/senders.html',
    '/admin/smtp-providers.html',
    '/admin/keys.html',
    '/admin/api-limits.html',
    '/admin/revenue.html',
    '/admin/payments.html',
    '/admin/refunds.html',
    '/admin/disputes.html',
    '/admin/reconciliation.html',
    '/admin/queue.html',
    '/admin/queue-dlq.html',
    '/admin/security.html',
    '/admin/sessions.html',
    '/admin/support.html',
    '/admin/announcements.html',
    '/admin/db-overview.html',
    '/admin/backups.html',
    '/admin/settings.html'
  ];

  for (const route of routes) {
    const res = await request(app).get(route);
    assert.equal(res.status, 200, `Route ${route} must return 200`);
    assert.ok(res.text.includes('MAIL INDIA'), `Route ${route} must contain MAIL INDIA branding`);
  }
});
