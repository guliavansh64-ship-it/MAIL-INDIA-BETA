'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { createFirebaseAdminRuntime } = require('../src/firebase-admin-runtime');
const { createFirebaseAuth } = require('../src/firebase-sync');
const { createLocalDatabase } = require('../src/local-dev');

function fixture() {
  const calls = { initialized: [], reads: [], writes: [], transactions: [], auth: [], certificates: [], adc: 0, deleted: 0 };
  const storage = createLocalDatabase({ platform_settings: { creditRate: 5 }, wallets: { member: { balance: 10 } } });
  let probeResult = async () => ({ val: () => ({ creditRate: 5 }) });
  let tokenResult = async () => ({ access_token: 'local-test-access-token', expires_in: 3600 });
  const nativeDb = {
    ref(p = '') {
      const ref = storage.ref(p);
      return {
        ...ref,
        get: async () => { calls.reads.push(p); return p === 'platform_settings' ? probeResult() : ref.get(); },
        set: async value => { calls.writes.push(p); return ref.set(value); },
        transaction: async (...args) => { calls.transactions.push({ p, args }); return ref.transaction(...args); },
        child: child => nativeDb.ref([p, child].filter(Boolean).join('/'))
      };
    }
  };
  const nativeAuth = {
    async verifyIdToken(...args) {
      calls.auth.push({ method: 'verifyIdToken', args });
      return { uid: 'member', email: 'member@example.com', email_verified: false, auth_time: Math.floor(Date.now() / 1000) };
    },
    async generateEmailVerificationLink(...args) {
      calls.auth.push({ method: 'generateEmailVerificationLink', args });
      return 'https://test-project.firebaseapp.com/__/auth/action?mode=verifyEmail&oobCode=local-test-code';
    }
  };
  const credential = { getAccessToken: () => tokenResult() };
  const sdk = {
    cert(value) { calls.certificates.push(value); return credential; },
    applicationDefault() { calls.adc++; return credential; },
    initializeApp(options, name) { calls.initialized.push({ options, name }); return { name }; },
    getDatabase: () => nativeDb,
    getAuth: () => nativeAuth,
    async deleteApp() { calls.deleted++; }
  };
  const make = options => createFirebaseAdminRuntime({
    projectId: 'test-project', databaseURL: 'https://test-project-default-rtdb.firebaseio.com',
    sdk, probeTimeoutMs: 100, probeIntervalMs: 0, ...options
  });
  return { calls, storage, nativeDb, nativeAuth, make, setProbe: value => { probeResult = value; }, setToken: value => { tokenResult = value; } };
}

test('missing Firebase configuration fails closed without initializing a database', async () => {
  const f = fixture();
  const runtime = f.make({ projectId: '' });
  assert.equal(await runtime.ready(), false);
  assert.equal(runtime.getStatus().database.reason, 'MISSING_FIREBASE_CONFIG');
  assert.equal(f.calls.initialized.length, 0);
  await assert.rejects(runtime.db.ref('users/member').set({ admin: true }), { code: 'DATABASE_UNAVAILABLE', status: 503 });
  await assert.rejects(runtime.adminAuth.verifyIdToken('token', true), { code: 'AUTH_UNAVAILABLE' });
  assert.equal(f.calls.writes.length, 0);
  await runtime.close();
});

test('missing credential files remain unavailable and never expose credential error contents', async () => {
  const f = fixture();
  const runtime = f.make({ credentialPath: 'missing-service-account.json', readCredentialFile() { throw new Error('private-sensitive-file-details'); } });
  assert.equal(await runtime.ready(), false);
  const status = runtime.getStatus();
  assert.equal(status.database.reason, 'ADMIN_CREDENTIALS_UNAVAILABLE');
  assert.equal(status.authentication.state, 'unavailable');
  assert.equal(JSON.stringify(status).includes('private-sensitive'), false);
  assert.equal(f.calls.initialized.length, 0);
  await runtime.close();
});

test('unavailable ADC cannot fall back to unauthenticated or local persistence', async () => {
  const f = fixture();
  f.setToken(async () => { throw new Error('No application default credentials'); });
  const runtime = f.make();
  assert.equal(await runtime.ready(), false);
  assert.equal(f.calls.adc, 1);
  assert.equal(f.calls.initialized.length, 0);
  assert.equal(runtime.getStatus().database.configured, false);
  await assert.rejects(runtime.db.ref('users').get(), { code: 'DATABASE_UNAVAILABLE' });
  assert.deepEqual(f.calls.reads, []);
  await runtime.close();
});

test('service account setup probes RTDB without writes and delegates native references and transactions', async () => {
  const f = fixture();
  const serviceAccount = { type: 'service_account', project_id: 'test-project', client_email: 'local@test-project.iam.gserviceaccount.com', private_key: 'local-test-private-key' };
  const runtime = f.make({ credentialPath: 'local-test-service-account.json', readCredentialFile: () => JSON.stringify(serviceAccount) });
  assert.equal(await runtime.ready(), true);
  assert.equal(f.calls.adc, 0);
  assert.deepEqual(f.calls.certificates, [serviceAccount]);
  assert.equal(f.calls.initialized[0].options.projectId, 'test-project');
  assert.deepEqual(f.calls.reads, ['platform_settings']);
  assert.deepEqual(f.calls.writes, []);
  const updater = wallet => ({ ...wallet, balance: wallet.balance - 1 });
  const result = await runtime.db.ref('wallets/member').transaction(updater, undefined, false);
  assert.equal(result.committed, true);
  assert.equal(f.calls.transactions[0].args[0], updater);
  assert.equal(f.calls.transactions[0].args[2], false);
  assert.equal(f.storage.root.wallets.member.balance, 9);
  await runtime.db.ref('users/member').child('name').set('Verified user');
  assert.equal((await runtime.db.ref('users/member').get()).val().name, 'Verified user');
  const status = runtime.getStatus();
  assert.equal(status.database.state, 'connected');
  assert.ok(status.database.checkedAt > 0);
  status.database.state = 'tampered';
  assert.equal(runtime.getStatus().database.state, 'connected');
  await runtime.close();
  assert.equal(f.calls.deleted, 1);
});

test('RTDB permission failure is reported honestly and a later probe can recover', async () => {
  const f = fixture();
  f.setProbe(async () => { throw Object.assign(new Error('Permission denied'), { code: 'PERMISSION_DENIED' }); });
  const runtime = f.make();
  assert.equal(await runtime.ready(), false);
  assert.equal(runtime.getStatus().database.reason, 'DATABASE_ACCESS_DENIED');
  assert.equal(runtime.getStatus().authentication.state, 'ready');
  await assert.rejects(runtime.db.ref('wallets/member').set({ balance: 100 }), { code: 'DATABASE_UNAVAILABLE' });
  const link = await runtime.adminAuth.generateEmailVerificationLink('member@example.com');
  assert.match(link, /mode=verifyEmail/);
  assert.equal(f.calls.writes.length, 0);
  f.setProbe(async () => ({ val: () => ({ creditRate: 5 }) }));
  assert.equal(await runtime.checkConnection(), true);
  assert.equal(runtime.getStatus().database.state, 'connected');
  assert.equal((await runtime.db.ref('wallets/member').get()).val().balance, 10);
  await runtime.close();
});

test('credential and database probes are bounded and never claim connectivity on timeout', async () => {
  const credentials = fixture();
  credentials.setToken(() => new Promise(() => {}));
  const missing = credentials.make({ probeTimeoutMs: 15 });
  assert.equal(await missing.ready(), false);
  assert.equal(missing.getStatus().database.reason, 'ADMIN_CREDENTIALS_TIMEOUT');
  await missing.close();
  const database = fixture();
  database.setProbe(() => new Promise(() => {}));
  const delayed = database.make({ probeTimeoutMs: 15 });
  assert.equal(await delayed.ready(), false);
  assert.equal(delayed.getStatus().database.reason, 'DATABASE_TIMEOUT');
  await assert.rejects(delayed.db.ref('users').get(), { code: 'DATABASE_UNAVAILABLE' });
  await delayed.close();
});

test('official Admin identity/link methods retain the existing verified OAuth session contract', async () => {
  const f = fixture();
  const runtime = f.make();
  await runtime.ready();
  let profileReads = 0;
  const blockedDb = { ref() { return { get() { profileReads++; return new Promise(() => {}); } }; } };
  const auth = createFirebaseAuth({ projectId: 'test-project', db: blockedDb, adminAuth: runtime.adminAuth, sessionSecret: crypto.randomBytes(32).toString('hex') });
  const user = await auth.verifyIdToken('official-id-token', true, { includeProfile: false });
  assert.equal(user.email_verified, false);
  assert.equal(user.uid, 'member');
  assert.equal(profileReads, 0);
  assert.deepEqual(f.calls.auth[0], { method: 'verifyIdToken', args: ['official-id-token', true] });
  const settings = { url: 'http://localhost:3000/account.html' };
  assert.match(await auth.generateEmailVerificationLink(user.email, settings), /oobCode=local-test-code/);
  assert.deepEqual(f.calls.auth[1], { method: 'generateEmailVerificationLink', args: [user.email, settings] });
  await assert.rejects(auth.createSessionCookie({ uid: 'pending', email_verified: false }), /verified email/);
  const oauthAuth = createFirebaseAuth({ projectId: 'test-project', adminAuth: runtime.adminAuth, sessionSecret: crypto.randomBytes(32).toString('hex') });
  const session = await oauthAuth.createSessionCookie({ uid: 'google_member', email: 'member@example.com', email_verified: true });
  assert.equal((await oauthAuth.verifySessionCookie(session, true)).uid, 'google_member');
  const unconfigured = createFirebaseAuth({ projectId: 'test-project', adminAuth: runtime.adminAuth });
  await assert.rejects(unconfigured.createSessionCookie({ uid: 'member', email_verified: true }), { code: 'AUTH_UNAVAILABLE' });
  await runtime.close();
});
