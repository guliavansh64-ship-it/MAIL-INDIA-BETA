'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { encryptCredentials } = require('../src/sending');
const { createSystemMailer, SystemMailError } = require('../src/system-mail');
const { memoryDb } = require('./helpers/mail-memory');

const key = crypto.randomBytes(32).toString('base64');
const actionLink = 'https://project.firebaseapp.com/__/auth/action?mode=verifyEmail&oobCode=private-action-code';
function sender(id = 'gmail1', email = 'owner@gmail.com') {
  return { email, name: 'MAIL INDIA', host: 'smtp.gmail.com', authType: 'app_password', status: 'active', verifiedAt: Date.now(), dailyLimit: 10,
    credentials: encryptCredentials(key, id, { type: 'app_password', host: 'smtp.gmail.com', password: 'abcdefghijklmnop', port: 465, secure: true }) };
}
function fixture(options = {}) {
  const db = options.db || memoryDb({ sender_accounts: { gmail1: sender() } });
  const sent = [];
  const generated = [];
  const auth = options.auth || { async generateEmailVerificationLink(email, settings) { generated.push({ email, settings }); return actionLink; } };
  const smtpFactory = options.smtpFactory || ((email, secret) => ({
    async sendMail(message) { sent.push({ email, secret, message }); return { accepted: [message.to], rejected: [] }; }
  }));
  const mailer = createSystemMailer({ db, auth, encryptionKey: key, senderId: '', ...options, smtpFactory });
  return { db, sent, generated, mailer };
}
const verification = { email: 'new@example.com', actionCodeSettings: { url: 'https://mail.example.com/account.html' } };

test('verification sends the genuine Firebase action link exactly once from the configured Gmail account', async () => {
  const f = fixture();
  const result = await f.mailer.sendVerificationEmail(verification);
  assert.deepEqual(f.generated, [{ email: verification.email, settings: verification.actionCodeSettings }]);
  assert.equal(f.sent.length, 1);
  assert.equal(f.sent[0].email, 'owner@gmail.com');
  assert.deepEqual(f.sent[0].message.from, { name: 'MAIL INDIA', address: 'owner@gmail.com' });
  assert.ok(f.sent[0].message.text.includes(actionLink));
  assert.ok(f.sent[0].message.html.includes('private-action-code'));
  assert.equal(result.success, true);
  assert.equal(result.provider, 'gmail_smtp');
  assert.equal(JSON.stringify(result).includes('private-action-code'), false);
  assert.equal(JSON.stringify(result).includes('abcdefghijklmnop'), false);
});

test('system sender selection refuses ambiguity and honors an explicit sender ID', async () => {
  const db = memoryDb({ sender_accounts: { gmail1: sender(), gmail2: sender('gmail2', 'second@gmail.com') } });
  const ambiguous = fixture({ db });
  await assert.rejects(ambiguous.mailer.sendVerificationEmail(verification), { code: 'SYSTEM_SENDER_AMBIGUOUS' });
  assert.equal(ambiguous.generated.length, 0);
  assert.equal(ambiguous.sent.length, 0);
  const chosen = fixture({ db, senderId: 'gmail2' });
  await chosen.mailer.sendVerificationEmail(verification);
  assert.equal(chosen.sent[0].message.from.address, 'second@gmail.com');
});

test('legacy active senders without verifiedAt cannot send system email', async () => {
  const s = sender();
  delete s.verifiedAt;
  const f = fixture({ db: memoryDb({ sender_accounts: { gmail1: s } }), senderId: 'gmail1' });
  await assert.rejects(f.mailer.sendVerificationEmail(verification), { code: 'SYSTEM_SENDER_UNVERIFIED' });
  assert.equal(f.generated.length, 0);
  assert.equal(f.sent.length, 0);
});

test('system mail uses the injected encryption key and exposes safe decryption errors', async () => {
  const f = fixture({ encryptionKey: crypto.randomBytes(32).toString('base64') });
  await assert.rejects(f.mailer.sendVerificationEmail(verification), { code: 'SENDER_DECRYPTION_FAILED' });
  assert.equal(f.sent.length, 0);
  assert.equal(f.generated.length, 0);
});

test('system mail preserves a matching explicit From and rejects a different account without sending', async () => {
  const f = fixture();
  await assert.rejects(f.mailer.sendEmail({ to: 'new@example.com', from: 'other@gmail.com', subject: 'Notice', text: 'Message' }), { code: 'SYSTEM_SENDER_FROM_MISMATCH' });
  assert.equal(f.sent.length, 0);
  const from = '"Account Security" <owner@gmail.com>';
  await f.mailer.sendEmail({ to: 'new@example.com', from, subject: 'Notice', text: 'Message' });
  assert.equal(f.sent[0].message.from, from);
});

test('system mail requires confirmation for the intended recipient and never retries', async () => {
  for (const [result, code] of [
    [{ accepted: [], rejected: ['new@example.com'] }, 'SMTP_RECIPIENT_REJECTED'],
    [{ accepted: ['different@example.com'], rejected: [] }, 'SMTP_OUTCOME_UNCERTAIN'],
    [{}, 'SMTP_OUTCOME_UNCERTAIN']
  ]) {
    let calls = 0;
    const f = fixture({ smtpFactory: () => ({ async sendMail() { calls++; return result; } }) });
    await assert.rejects(f.mailer.sendVerificationEmail(verification), { code });
    assert.equal(calls, 1);
  }
});

test('SMTP auth and uncertain errors are distinguished without leaking provider text', async () => {
  for (const [providerError, code, uncertain] of [
    [Object.assign(new Error('password: do-not-expose'), { code: 'EAUTH', responseCode: 535 }), 'SMTP_AUTH_FAILED', false],
    [Object.assign(new Error(actionLink), { code: 'ETIMEDOUT' }), 'SMTP_OUTCOME_UNCERTAIN', true]
  ]) {
    let calls = 0;
    const f = fixture({ smtpFactory: () => ({ async sendMail() { calls++; throw providerError; } }) });
    await assert.rejects(f.mailer.sendVerificationEmail(verification), error => {
      assert.ok(error instanceof SystemMailError);
      assert.equal(error.code, code);
      assert.equal(error.uncertain, uncertain);
      assert.equal(error.message.includes('do-not-expose'), false);
      assert.equal(error.message.includes('private-action-code'), false);
      return true;
    });
    assert.equal(calls, 1);
  }
});

test('unavailable database, missing Admin capability and quota prevent SMTP submission', async () => {
  const broken = fixture({ db: { ref() { return { async get() { throw new Error('private details'); } }; } } });
  await assert.rejects(broken.mailer.sendVerificationEmail(verification), { code: 'DATABASE_UNAVAILABLE' });
  const noAdmin = fixture({ auth: {} });
  await assert.rejects(noAdmin.mailer.sendVerificationEmail(verification), { code: 'FIREBASE_ADMIN_REQUIRED' });
  const full = sender();
  full.usage = { [new Date().toISOString().slice(0, 10)]: full.dailyLimit };
  const quota = fixture({ db: memoryDb({ sender_accounts: { gmail1: full } }) });
  await assert.rejects(quota.mailer.sendVerificationEmail(verification), { code: 'SYSTEM_SENDER_QUOTA_EXCEEDED' });
  assert.equal(broken.sent.length + noAdmin.sent.length + quota.sent.length, 0);
});

test('a changed or paused sender cannot send after the verification link was generated', async () => {
  const db = memoryDb({ sender_accounts: { gmail1: sender() } });
  const f = fixture({ db, auth: { async generateEmailVerificationLink() { db.root.sender_accounts.gmail1.status = 'paused'; return actionLink; } } });
  await assert.rejects(f.mailer.sendVerificationEmail(verification), { code: 'SYSTEM_SENDER_UNAVAILABLE' });
  assert.equal(f.sent.length, 0);
});
