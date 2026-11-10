'use strict';
const express = require('express');
const crypto = require('node:crypto');
const { projectLog } = require('./logs');
const { encryptCredentials, transport, validEmail, safeId } = require('./sending');
const {
  REFUND_STATES,
  getRefundableAmount,
  initiateRefund,
  retryFailedRefund
} = require('./refunds');
const {
  DISPUTE_STATUSES,
  RECOVERY_STATUSES,
  resolveDisputeRecovery,
  recordDisputeEvidence
} = require('./disputes');
const {
  performReconciliation,
  resolveReconciliationMismatch
} = require('./reconciliation');
const {
  scanQueueState,
  autoRecoverStuckJobs,
  moveToDLQ,
  manualRecoverJob
} = require('./recovery');
const {
  recordBounce,
  recordComplaint,
  handleDeliveryEvent
} = require('./bounces');
const {
  getRetentionPolicies,
  setRetentionPolicies,
  runRetentionCleanup,
  purgeUserData
} = require('./retention');

function adminRoutes({ db, authenticate, key, paymentConfig = {}, provider, sendQueue = null, distributedLimiter = null }) {
  const r = express.Router();
  const encKey = (key && typeof key === 'string' && Buffer.from(key, 'base64').length === 32)
    ? key
    : ((process.env.SENDER_ENCRYPTION_KEY && Buffer.from(process.env.SENDER_ENCRYPTION_KEY, 'base64').length === 32)
      ? process.env.SENDER_ENCRYPTION_KEY
      : crypto.createHash('sha256').update(process.env.SESSION_SECRET || 'mailbridge-master-session-salt-375ee').digest('base64'));

  // Admin Authentication and Authorization Middleware
  r.use(authenticate, async (req, res, next) => {
    const adminEmails = (process.env.ADMIN_EMAILS || 'guliavansh64@gmail.com').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
    const userEmail = (req.user.email || '').toLowerCase();
    const isGmail = userEmail.endsWith('@gmail.com');

    // Strict rule: all Gmail cannot be admin except strictly guliavansh64@gmail.com
    if (isGmail && userEmail !== 'guliavansh64@gmail.com') {
      req.user.admin = false;
      try {
        await db.ref('users/' + req.user.uid + '/admin').set(false);
      } catch {}
      return res.status(403).json({ success: false, error: 'ADMIN_REQUIRED', message: 'Administrator privileges are required to access this resource.' });
    }

    const isExplicitAdmin = userEmail === 'guliavansh64@gmail.com' || (!isGmail && (adminEmails.includes(userEmail) || Boolean(req.user.admin)));

    let profile = null;
    try {
      profile = (await db.ref('users/' + req.user.uid).get()).val();
    } catch {}

    if (isExplicitAdmin || (!isGmail && profile && profile.admin)) {
      req.user.admin = true;
      req.user.email_verified = true;
      if (profile && !profile.admin && userEmail === 'guliavansh64@gmail.com') {
        await db.ref('users/' + req.user.uid + '/admin').set(true).catch(() => {});
      }
    } else {
      req.user.admin = false;
    }

    if (req.user.admin !== true || req.user.email_verified !== true) {
      return res.status(403).json({ success: false, error: 'ADMIN_REQUIRED' });
    }
    try {
      if (profile && profile.status !== 'active') {
        return res.status(403).json({ success: false, error: 'ADMIN_REQUIRED' });
      }
      // Rate limit check for admin actions
      if (distributedLimiter && typeof distributedLimiter.checkScoped === 'function') {
        const ok = await distributedLimiter.checkScoped('admin', req.user.uid);
        if (!ok) {
          return res.status(429).json({ success: false, error: 'RATE_LIMIT_EXCEEDED', message: 'Admin operation rate limit exceeded.' });
        }
      }
      next();
    } catch {
      return res.status(503).json({ success: false, error: 'ADMIN_AUTH_UNAVAILABLE' });
    }
  });

  async function audit(uid, action, target, details = null) {
    const logId = crypto.randomUUID();
    const entry = {
      adminId: uid,
      action,
      target: String(target || ''),
      createdAt: Date.now()
    };
    if (details !== null && details !== undefined) entry.details = details;
    await db.ref('admin_logs/' + logId).set(entry);
    return logId;
  }

  // ==========================================
  // 1. ADMIN DASHBOARD & SUMMARY
  // ==========================================
  r.get('/summary', async (req, res) => {
    try {
      const [uSnap, sSnap, wSnap, pSnap, rSnap, qSnap] = await Promise.all([
        db.ref('users').get(),
        db.ref('sender_accounts').get(),
        db.ref('wallets').get(),
        db.ref('payment_orders').get(),
        db.ref('payment_refunds').get(),
        scanQueueState(db)
      ]);

      const users = Object.values(uSnap.val() || {});
      const senders = Object.values(sSnap.val() || {});
      const wallets = Object.values(wSnap.val() || {});
      const payments = Object.values(pSnap.val() || {});
      const refunds = Object.values(rSnap.val() || {});

      let totalAccepted = 0;
      let totalFailed = 0;
      for (const w of wallets) {
        for (const j of Object.values(w.sendRequests || {})) {
          if (j.status === 'accepted') totalAccepted++;
          else if (j.status === 'failed') totalFailed++;
        }
      }

      const totalCapturedPaise = payments.filter(x => x.status === 'captured').reduce((a, x) => a + (x.amountPaise || 0), 0);
      const totalRefundedPaise = refunds.filter(x => x.status === 'completed').reduce((a, x) => a + (x.amountPaise || 0), 0);

      res.json({
        success: true,
        users: users.length,
        activeUsers: users.filter(x => x.status === 'active').length,
        senders: senders.length,
        activeSenders: senders.filter(x => x.status === 'active').length,
        creditsConsumed: wallets.reduce((a, x) => a + (x.consumed || 0), 0),
        creditsPurchased: wallets.reduce((a, x) => a + (x.purchased || 0), 0),
        capturedPaise: totalCapturedPaise,
        refundedPaise: totalRefundedPaise,
        totalAccepted,
        totalFailed,
        queueHealth: {
          stuckProcessing: qSnap.summary.stuckProcessingCount,
          stuckQueued: qSnap.summary.stuckQueuedCount,
          unknownCount: qSnap.summary.unknownCount,
          dlqCount: qSnap.summary.dlqCount
        }
      });
    } catch {
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR' });
    }
  });

  // ==========================================
  // 2. USER MANAGEMENT
  // ==========================================
  r.get('/users', async (req, res) => {
    try {
      const [snap, wSnap] = await Promise.all([
        db.ref('users').get(),
        db.ref('wallets').get()
      ]);
      const wallets = wSnap.val() || {};
      const items = [];
      for (const [key, u] of Object.entries(snap.val() || {})) {
        const w = wallets[key] || {};
        items.push({
          uid: key,
          name: u.name || '',
          email: u.email || '',
          status: u.status || 'active',
          admin: Boolean(
            u.email && u.email.toLowerCase() === 'guliavansh64@gmail.com'
              ? true
              : (u.email && u.email.toLowerCase().endsWith('@gmail.com') ? false : (u.admin || u.role === 'admin'))
          ),
          balance: w.balance || 0,
          consumed: w.consumed || 0,
          createdAt: u.createdAt || null,
          apiRateLimit: u.apiRateLimit || 120
        });
      }
      const q = String(req.query.search || '').trim().toLowerCase().slice(0, 100);
      const filtered = q ? items.filter(u => (u.uid + ' ' + u.email + ' ' + u.name).toLowerCase().includes(q)) : items;
      res.json({ success: true, users: filtered.slice(0, 100), truncated: filtered.length > 100 });
    } catch {
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR' });
    }
  });

  r.post('/users/:uid/status', async (req, res) => {
    const uid = req.params.uid;
    const { status, reason } = req.body || {};
    if (!safeId(uid) || !['active', 'suspended'].includes(status) || typeof reason !== 'string' || reason.trim().length < 5 || reason.length > 300) {
      return res.status(400).json({ error: 'INVALID_REQUEST', message: 'A status and reason of 5–300 characters are required.' });
    }
    if (uid === req.user.uid) {
      return res.status(400).json({ error: 'INVALID_REQUEST', message: 'You cannot change your own status.' });
    }
    try {
      if (!(await db.ref('users/' + uid).get()).val()) return res.status(404).json({ error: 'NOT_FOUND' });
      await db.ref('users/' + uid + '/status').set(status);
      await audit(req.user.uid, 'user.' + status, uid, { reason: reason.trim() });
      res.json({ success: true, status });
    } catch {
      return res.status(500).json({ error: 'USER_UPDATE_FAILED' });
    }
  });

  r.post(['/users/:uid/rate-limit', '/users/:uid/limit'], async (req, res) => {
    const uid = req.params.uid;
    const limit = req.body?.limit || req.body?.rateLimit;
    if (!safeId(uid) || !Number.isSafeInteger(limit) || limit < 1 || limit > 10000) {
      return res.status(400).json({ error: 'INVALID_REQUEST' });
    }
    try {
      if (!(await db.ref('users/' + uid).get()).val()) return res.status(404).json({ error: 'NOT_FOUND' });
      await db.ref('users/' + uid + '/apiRateLimit').set(limit);
      await audit(req.user.uid, 'user.rate_limit', uid, { limit });
      res.json({ success: true, limit });
    } catch {
      return res.status(500).json({ error: 'RATE_LIMIT_UPDATE_FAILED' });
    }
  });

  r.post(['/users/:uid/role', '/users/:uid/admin'], async (req, res) => {
    const uid = req.params.uid;
    const admin = Boolean(req.body?.admin);
    if (!safeId(uid)) return res.status(400).json({ error: 'INVALID_REQUEST' });
    try {
      if (!(await db.ref('users/' + uid).get()).val()) return res.status(404).json({ error: 'NOT_FOUND' });
      await db.ref('users/' + uid + '/admin').set(admin);
      await audit(req.user.uid, 'user.role_update', uid, { admin });
      res.json({ success: true, admin });
    } catch {
      return res.status(500).json({ error: 'ROLE_UPDATE_FAILED' });
    }
  });

  r.post('/users', async (req, res) => {
    const { email, name, credits, admin, apiRateLimit } = req.body || {};
    if (!validEmail(email)) {
      return res.status(400).json({ error: 'INVALID_REQUEST', message: 'A valid email address is required.' });
    }
    const cleanEmail = email.trim().toLowerCase();
    const initialCredits = Number.isSafeInteger(Number(credits)) && Number(credits) >= 0 ? Number(credits) : 100;
    const rateLimit = Number.isSafeInteger(Number(apiRateLimit)) && Number(apiRateLimit) >= 1 && Number(apiRateLimit) <= 10000 ? Number(apiRateLimit) : 120;
    const isAdmin = Boolean(admin);

    try {
      const snap = await db.ref('users').get();
      const existing = snap.val() || {};
      for (const [key, u] of Object.entries(existing)) {
        if (u.email && u.email.toLowerCase() === cleanEmail) {
          return res.status(409).json({ error: 'USER_EXISTS', message: 'A user account with this email address already exists.' });
        }
      }

      const uid = 'usr_' + crypto.randomUUID().replace(/-/g, '').slice(0, 16);
      const now = Date.now();

      await db.ref('users/' + uid).set({
        email: cleanEmail,
        name: typeof name === 'string' ? name.trim() : '',
        status: 'active',
        admin: isAdmin,
        apiRateLimit: rateLimit,
        createdAt: now
      });

      const initOpId = 'admin_init_' + now;
      await db.ref('wallets/' + uid).set({
        balance: initialCredits,
        reserved: 0,
        purchased: initialCredits,
        consumed: 0,
        ledger: {
          [initOpId]: {
            type: 'ADMIN_GRANT',
            credits: initialCredits,
            reason: 'Account creation initial credit grant',
            createdAt: now
          }
        }
      });

      await audit(req.user.uid, 'user.created', uid, { email: cleanEmail, credits: initialCredits, admin: isAdmin });
      res.status(201).json({
        success: true,
        uid,
        user: {
          uid,
          email: cleanEmail,
          name: typeof name === 'string' ? name.trim() : '',
          status: 'active',
          admin: isAdmin,
          balance: initialCredits,
          apiRateLimit: rateLimit,
          createdAt: now
        }
      });
    } catch {
      return res.status(500).json({ error: 'USER_CREATION_FAILED' });
    }
  });

  r.post(['/users/:uid/purge-data', '/users/:uid/delete'], async (req, res) => {
    const uid = req.params.uid;
    if (!safeId(uid)) return res.status(400).json({ error: 'INVALID_REQUEST' });
    try {
      const result = await purgeUserData(db, uid, req.user.uid);
      res.json({ success: true, result });
    } catch (err) {
      return res.status(500).json({ error: 'DATA_PURGE_FAILED', message: err.message });
    }
  });

  // ==========================================
  // 3. GMAIL SENDER POOL
  // ==========================================
  r.get('/senders', async (req, res) => {
    try {
      const snap = await db.ref('sender_accounts').get();
      const items = [];
      for (const [key, v] of Object.entries(snap.val() || {})) {
        items.push({
          id: key,
          email: v.email,
          name: v.name || '',
          provider: v.provider || v.authType || 'app_password',
          authType: v.authType || 'app_password',
          host: v.host || 'smtp.gmail.com',
          port: v.port || 465,
          username: v.username || v.email,
          status: v.status,
          dailyLimit: v.dailyLimit,
          usage: v.usage || {},
          createdAt: v.createdAt
        });
      }
      res.json({ success: true, senders: items });
    } catch {
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR' });
    }
  });

  r.post('/senders', async (req, res) => {
    const {
      email, dailyLimit, authType, password, clientId, clientSecret,
      refreshToken, authorized, name, host, port, secure, username, provider
    } = req.body || {};

    const effectiveLimit = Number(dailyLimit) || 500;
    const isAuth = authorized !== false;
    const allowedAuthTypes = [
      'app_password', 'oauth2', 'custom_smtp',
      'gmail', 'outlook', 'office365', 'sendgrid', 'ses', 'amazon_ses',
      'brevo', 'sendinblue', 'resend', 'mailgun', 'postmark', 'smtp',
      'gmail_oauth'
    ];
    // Check provider preset first, fallback to authType
    const pKey = (provider || authType || 'app_password').toLowerCase().trim();
    const rawAuthType = (authType || 'app_password').toLowerCase().trim();

    if (!isAuth || !validEmail(email) || !Number.isSafeInteger(effectiveLimit) || effectiveLimit < 1 || effectiveLimit > 1000000 || (!allowedAuthTypes.includes(pKey) && !allowedAuthTypes.includes(rawAuthType))) {
      return res.status(400).json({ error: 'INVALID_REQUEST' });
    }

    const cleanPassword = typeof password === 'string'
      ? (pKey === 'app_password' || rawAuthType === 'app_password' ? password.replace(/\s+/g, '') : password.trim())
      : '';

    // Determine normalized provider settings
    let effectiveHost = (host || '').trim();
    let effectivePort = port ? Number(port) : 465;
    let effectiveSecure = secure !== undefined ? Boolean(secure) : (effectivePort === 465);
    let effectiveUser = (username || '').trim();
    let normalizedAuthType = 'custom_smtp';
    let providerName = provider || pKey;

    if (pKey === 'app_password' || pKey === 'gmail' || rawAuthType === 'app_password') {
      effectiveHost = effectiveHost || 'smtp.gmail.com';
      effectivePort = Number(port) || 465;
      effectiveSecure = secure !== undefined ? Boolean(secure) : (effectivePort === 465);
      effectiveUser = effectiveUser || email.toLowerCase();
      normalizedAuthType = 'app_password';
      providerName = 'gmail';
    } else if (pKey === 'oauth2' || pKey === 'gmail_oauth' || rawAuthType === 'oauth2') {
      effectiveHost = effectiveHost || 'smtp.gmail.com';
      effectivePort = Number(port) || 465;
      effectiveSecure = true;
      effectiveUser = effectiveUser || email.toLowerCase();
      normalizedAuthType = 'oauth2';
      providerName = 'gmail_oauth';
    } else if (pKey === 'sendgrid') {
      effectiveHost = 'smtp.sendgrid.net';
      effectivePort = Number(port) || 587;
      effectiveSecure = effectivePort === 465;
      effectiveUser = 'apikey'; // SendGrid SMTP username is always "apikey"
      normalizedAuthType = 'custom_smtp';
      providerName = 'sendgrid';
    } else if (pKey === 'outlook' || pKey === 'office365') {
      effectiveHost = 'smtp.office365.com';
      effectivePort = Number(port) || 587;
      effectiveSecure = false;
      effectiveUser = effectiveUser || email.toLowerCase();
      normalizedAuthType = 'custom_smtp';
      providerName = 'outlook';
    } else if (pKey === 'ses' || pKey === 'amazon_ses') {
      effectiveHost = effectiveHost || 'email-smtp.ap-south-1.amazonaws.com';
      effectivePort = Number(port) || 465;
      effectiveSecure = secure !== undefined ? Boolean(secure) : (effectivePort === 465);
      effectiveUser = effectiveUser || email.toLowerCase();
      normalizedAuthType = 'custom_smtp';
      providerName = 'amazon_ses';
    } else if (pKey === 'brevo' || pKey === 'sendinblue') {
      effectiveHost = 'smtp-relay.brevo.com';
      effectivePort = Number(port) || 587;
      effectiveSecure = false;
      effectiveUser = effectiveUser || email.toLowerCase();
      normalizedAuthType = 'custom_smtp';
      providerName = 'brevo';
    } else if (pKey === 'resend') {
      effectiveHost = 'smtp.resend.com';
      effectivePort = Number(port) || 465;
      effectiveSecure = effectivePort === 465;
      effectiveUser = 'resend'; // Resend SMTP username is always "resend"
      normalizedAuthType = 'custom_smtp';
      providerName = 'resend';
    } else if (pKey === 'mailgun') {
      effectiveHost = effectiveHost || 'smtp.mailgun.org';
      effectivePort = Number(port) || 587;
      effectiveSecure = false;
      effectiveUser = effectiveUser || email.toLowerCase();
      normalizedAuthType = 'custom_smtp';
      providerName = 'mailgun';
    } else if (pKey === 'postmark') {
      effectiveHost = 'smtp.postmarkapp.com';
      effectivePort = Number(port) || 587;
      effectiveSecure = false;
      effectiveUser = effectiveUser || cleanPassword; // Postmark uses server API token as username
      normalizedAuthType = 'custom_smtp';
      providerName = 'postmark';
    } else {
      effectiveHost = effectiveHost || 'smtp.gmail.com';
      effectivePort = Number(port) || 465;
      effectiveSecure = secure !== undefined ? Boolean(secure) : (effectivePort === 465);
      effectiveUser = effectiveUser || email.toLowerCase();
      normalizedAuthType = 'custom_smtp';
      providerName = 'custom_smtp';
    }

    const secret = normalizedAuthType === 'app_password'
      ? { type: 'app_password', password: cleanPassword, host: effectiveHost, port: effectivePort, secure: effectiveSecure }
      : normalizedAuthType === 'oauth2'
      ? { type: 'oauth2', clientId, clientSecret, refreshToken, host: effectiveHost, port: effectivePort, secure: effectiveSecure }
      : { type: 'custom_smtp', password: cleanPassword, host: effectiveHost, port: effectivePort, secure: effectiveSecure, username: effectiveUser };

    if (Object.values(secret).some(x => typeof x !== 'string' && typeof x !== 'number' && typeof x !== 'boolean')) {
      return res.status(400).json({ error: 'INVALID_REQUEST' });
    }
    if ((normalizedAuthType === 'app_password' || normalizedAuthType === 'custom_smtp') && !cleanPassword) {
      return res.status(400).json({ error: 'PASSWORD_REQUIRED', message: 'Password or API Key is required.' });
    }
    if (normalizedAuthType === 'oauth2' && (!clientId || !clientSecret || !refreshToken)) {
      return res.status(400).json({ error: 'OAUTH_REQUIRED', message: 'Client ID, Client Secret, and Refresh Token are required.' });
    }

    try {
      const existingSnap = await db.ref('sender_accounts').get();
      const existingAccounts = existingSnap.val() || {};
      const existingEntry = Object.entries(existingAccounts).find(([_, a]) => a && a.email === email.toLowerCase());
      const id = existingEntry ? existingEntry[0] : crypto.randomUUID();
      const credentials = encryptCredentials(encKey, id, secret);
      await db.ref('sender_accounts/' + id).set({
        email: email.toLowerCase(),
        name: name || '',
        provider: providerName,
        authType: normalizedAuthType,
        host: effectiveHost,
        port: effectivePort,
        username: effectiveUser || email.toLowerCase(),
        credentials,
        dailyLimit: effectiveLimit,
        status: 'active',
        createdAt: existingEntry ? (existingEntry[1].createdAt || Date.now()) : Date.now(),
        updatedAt: Date.now()
      });
      await audit(req.user.uid, existingEntry ? 'sender.updated' : 'sender.created', id);
      res.status(201).json({ success: true, id, status: 'active', provider: providerName, updated: Boolean(existingEntry) });
    } catch (err) {
      console.error('[ADMIN SENDER ERROR]', err);
      return res.status(500).json({ error: 'SENDER_CREATE_FAILED', message: err.message });
    }
  });

  r.delete('/senders/:id', async (req, res) => {
    if (!safeId(req.params.id)) return res.status(400).json({ error: 'INVALID_REQUEST' });
    try {
      const ref = db.ref('sender_accounts/' + req.params.id);
      const s = (await ref.get()).val();
      if (!s) return res.status(404).json({ error: 'NOT_FOUND' });
      await ref.remove();
      await audit(req.user.uid, 'sender.deleted', req.params.id);
      res.json({ success: true });
    } catch {
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR' });
    }
  });

  r.post('/senders/:id/verify', async (req, res) => {
    if (!safeId(req.params.id)) return res.status(400).json({ error: 'INVALID_REQUEST' });
    try {
      const s = (await db.ref('sender_accounts/' + req.params.id).get()).val();
      if (!s) return res.status(404).json({ error: 'NOT_FOUND' });
      const { decryptCredentials } = require('./sending');
      await transport(s.email, decryptCredentials(encKey, req.params.id, s.credentials)).verify();
      await audit(req.user.uid, 'sender.verified', req.params.id);
      res.json({ success: true });
    } catch (err) {
      return res.status(502).json({ error: 'SENDER_VERIFICATION_FAILED', message: err.message || 'Unable to verify sender connection.' });
    }
  });

  r.post('/senders/:id/status', async (req, res) => {
    if (!safeId(req.params.id) || !['active', 'paused'].includes(req.body?.status)) {
      return res.status(400).json({ error: 'INVALID_REQUEST' });
    }
    try {
      const ref = db.ref('sender_accounts/' + req.params.id);
      const s = (await ref.get()).val();
      if (!s) return res.status(404).json({ error: 'NOT_FOUND' });
      await ref.child('status').set(req.body.status);
      await audit(req.user.uid, 'sender.' + req.body.status, req.params.id);
      res.json({ success: true });
    } catch {
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR' });
    }
  });

  r.post('/assignments', async (req, res) => {
    const { uid, senderId } = req.body || {};
    if (!safeId(uid) || !safeId(senderId)) return res.status(400).json({ error: 'INVALID_REQUEST' });
    try {
      const [u, s] = await Promise.all([db.ref('users/' + uid).get(), db.ref('sender_accounts/' + senderId).get()]);
      if (!u.val() || !s.val()) return res.status(404).json({ error: 'NOT_FOUND' });
      await db.ref('sender_assignments/' + uid).set({ senderId, assignedAt: Date.now() });
      await audit(req.user.uid, 'sender.assigned', uid, { senderId });
      res.json({ success: true });
    } catch {
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR' });
    }
  });

  // ==========================================
  // 4. EMAIL MONITORING & RECONCILIATION
  // ==========================================
  r.get('/reconciliation', async (req, res) => {
    try {
      const snap = await db.ref('wallets').get();
      const items = [];
      for (const [key, wVal] of Object.entries(snap.val() || {})) {
        for (const j of Object.values(wVal.sendRequests || {})) {
          if (j.status === 'unknown' || j.status === 'processing') {
            items.push({
              uid: key,
              id: j.id,
              status: j.status,
              createdAt: j.createdAt,
              updatedAt: j.updatedAt || j.createdAt,
              error: j.error || null
            });
          }
        }
      }
      items.sort((a, b) => a.createdAt - b.createdAt);
      res.json({ success: true, items: items.slice(0, 100) });
    } catch {
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR' });
    }
  });

  r.post(['/reconciliation', '/reconcile/:id'], async (req, res) => {
    const uid = req.body?.uid;
    const id = req.params?.id || req.body?.id;
    const outcome = req.body?.outcome || req.body?.status;
    let evidence = req.body?.evidence;
    if (evidence === undefined && req.params?.id) {
      evidence = 'Administrative operator reconciliation verified';
    }
    if (!safeId(uid) || !/^[a-f0-9]{64}$/.test(id || '') || !['accepted', 'failed'].includes(outcome) || typeof evidence !== 'string' || evidence.trim().length < 15 || evidence.length > 500) {
      return res.status(400).json({ error: 'INVALID_REQUEST', message: 'Provide a valid outcome and provider evidence (15–500 characters).' });
    }
    try {
      const t = Date.now(), actor = req.user.uid;
      const result = await db.ref('wallets/' + uid).transaction(w => {
        const j = w?.sendRequests?.[id];
        if (!j || j.status !== 'unknown' || !Number.isSafeInteger(w.reserved) || w.reserved < 1) return;
        w.reserved--;
        w.ledger = w.ledger || {};
        if (outcome === 'accepted') {
          w.consumed = (w.consumed || 0) + 1;
        } else {
          w.balance = (w.balance || 0) + 1;
        }
        j.status = outcome;
        j.updatedAt = t;
        j.error = null;
        j.reconciled = true;
        w.ledger['reconcile_' + id] = {
          type: 'manual_reconciliation',
          outcome,
          reference: id,
          adminId: actor,
          evidence: evidence.trim(),
          createdAt: t
        };
        return w;
      }, undefined, false);

      if (!result.committed) {
        return res.status(409).json({ error: 'NOT_RECONCILABLE', message: 'Only unknown outcomes can be reconciled. Processing jobs may still be in flight.' });
      }
      const j = result.snapshot.val().sendRequests[id];
      try { await projectLog(db, uid, j); } catch { console.error('Reconciliation log projection failed'); }
      await audit(actor, 'email.reconciled', id, { outcome, evidence: evidence.trim() });
      res.json({ success: true, status: outcome });
    } catch {
      return res.status(500).json({ error: 'RECONCILIATION_FAILED' });
    }
  });

  r.get('/monitoring/emails', async (req, res) => {
    try {
      const snap = await db.ref('wallets').get();
      const items = [];
      for (const [key, wVal] of Object.entries(snap.val() || {})) {
        const uid = key;
        for (const j of Object.values(wVal?.sendRequests || {})) {
          items.push({
            uid,
            id: j.id,
            status: j.status,
            recipient: j.message?.to || '',
            subject: j.message?.subject || '',
            senderId: j.senderId || null,
            error: j.error || null,
            createdAt: j.createdAt,
            updatedAt: j.updatedAt || j.createdAt
          });
        }
      }
      items.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));

      const status = String(req.query.status || 'all');
      let filtered = status !== 'all' ? items.filter(x => x.status === status) : items;
      const q = String(req.query.search || '').trim().toLowerCase();
      if (q) filtered = filtered.filter(x => (x.recipient + ' ' + x.subject + ' ' + x.id + ' ' + x.uid).toLowerCase().includes(q));

      const page = Math.max(1, parseInt(req.query.page, 10) || 1);
      const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 20));

      res.json({
        success: true,
        emails: filtered.slice((page - 1) * limit, page * limit),
        total: filtered.length,
        page,
        limit
      });
    } catch {
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR' });
    }
  });

  // ==========================================
  // 5. EMAIL LOGS (FULL PLATFORM VIEW)
  // ==========================================
  r.get('/logs/emails', async (req, res) => {
    try {
      const snap = await db.ref('email_logs').get();
      const items = [];
      for (const [uid, userLogs] of Object.entries(snap.val() || {})) {
        for (const logItem of Object.values(userLogs || {})) {
          items.push({ uid, ...logItem });
        }
      }
      items.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));

      const q = String(req.query.search || '').trim().toLowerCase();
      let filtered = q ? items.filter(x => (x.recipient + ' ' + x.subject + ' ' + x.id + ' ' + x.uid).toLowerCase().includes(q)) : items;

      const page = Math.max(1, parseInt(req.query.page, 10) || 1);
      const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 20));

      res.json({
        success: true,
        logs: filtered.slice((page - 1) * limit, page * limit),
        total: filtered.length,
        page,
        limit
      });
    } catch {
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR' });
    }
  });

  // ==========================================
  // 6. API KEY MANAGEMENT (ALL USERS)
  // ==========================================
  r.get('/keys', async (req, res) => {
    try {
      const snap = await db.ref('user_api_keys').get();
      const keys = [];
      for (const [uid, userKeys] of Object.entries(snap.val() || {})) {
        for (const [kId, val] of Object.entries(userKeys || {})) {
          keys.push({
            id: kId,
            uid,
            name: val.name,
            prefix: val.prefix,
            status: val.status,
            createdAt: val.createdAt,
            lastUsedAt: val.lastUsedAt || null
          });
        }
      }
      keys.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
      res.json({ success: true, keys });
    } catch {
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR' });
    }
  });

  r.delete('/keys/:uid/:id', async (req, res) => {
    const { uid, id } = req.params;
    if (!safeId(uid) || !/^[0-9a-f-]{36}$/.test(id)) return res.status(400).json({ error: 'INVALID_REQUEST' });
    try {
      const keyRef = db.ref(`user_api_keys/${uid}/${id}`);
      const val = (await keyRef.get()).val();
      if (!val) return res.status(404).json({ error: 'NOT_FOUND' });

      // Revoke key
      await keyRef.update({ status: 'revoked' });

      // Clean key_index
      const indexSnap = await db.ref('key_index').get();
      for (const [kHash, entry] of Object.entries(indexSnap.val() || {})) {
        if (entry && entry.keyId === id && entry.uid === uid) {
          db.ref('key_index/' + kHash).set(null);
        }
      }

      await audit(req.user.uid, 'key.revoked', id, { uid });
      res.json({ success: true });
    } catch {
      return res.status(500).json({ error: 'KEY_REVOCATION_FAILED' });
    }
  });

  // ==========================================
  // 7. CREDIT MANAGEMENT
  // ==========================================
  r.post('/credits/adjust', async (req, res) => {
    const { uid, amount, reason, operationId } = req.body || {};
    if (!safeId(uid) || !Number.isSafeInteger(amount) || amount === 0 || Math.abs(amount) > 1000000 || typeof reason !== 'string' || reason.trim().length < 5 || reason.length > 300 || !/^[-a-zA-Z0-9_]{16,80}$/.test(operationId || '')) {
      return res.status(400).json({ error: 'INVALID_REQUEST', message: 'Provide a nonzero integer amount, unique operation ID, and reason.' });
    }
    try {
      if (!(await db.ref('users/' + uid).get()).val()) return res.status(404).json({ error: 'NOT_FOUND' });
      const actor = req.user.uid, now = Date.now(), ledgerKey = 'admin_adjust_' + operationId;
      const result = await db.ref('wallets/' + uid).transaction(w => {
        w = w || { balance: 0, reserved: 0, purchased: 0, consumed: 0 };
        w.ledger = w.ledger || {};
        if (w.ledger[ledgerKey]) return w;
        const current = w.balance ?? 0;
        if (!Number.isSafeInteger(current) || current < 0 || !Number.isSafeInteger(current + amount) || current + amount < 0) return;
        w.balance = current + amount;
        w.ledger[ledgerKey] = { type: 'admin_adjustment', credits: amount, reason: reason.trim(), adminId: actor, createdAt: now };
        return w;
      }, undefined, false);

      if (!result.committed) return res.status(409).json({ error: 'INSUFFICIENT_CREDITS_OR_INVALID_WALLET' });
      const w = result.snapshot.val(), record = w.ledger[ledgerKey];
      if (record.credits !== amount || record.reason !== reason.trim() || record.adminId !== actor) {
        return res.status(409).json({ error: 'IDEMPOTENCY_CONFLICT' });
      }
      await audit(actor, 'credit.adjusted', uid, { amount, operationId, reason: reason.trim() });
      res.json({ success: true, balance: w.balance, operationId });
    } catch {
      return res.status(500).json({ error: 'CREDIT_ADJUSTMENT_FAILED' });
    }
  });

  r.get(['/credits/ledger/:uid', '/wallets/:uid'], async (req, res) => {
    const uid = req.params.uid;
    if (!safeId(uid)) return res.status(400).json({ error: 'INVALID_REQUEST' });
    try {
      const snap = await db.ref('wallets/' + uid).get();
      const val = snap.val() || {};
      const ledger = Object.entries(val.ledger || {}).map(([id, item]) => ({ id, ...item })).sort((a, b) => b.createdAt - a.createdAt);
      res.json({
        success: true,
        balance: val.balance || 0,
        reserved: val.reserved || 0,
        purchased: val.purchased || 0,
        consumed: val.consumed || 0,
        ledger,
        wallet: {
          balance: val.balance || 0,
          reserved: val.reserved || 0,
          purchased: val.purchased || 0,
          consumed: val.consumed || 0,
          ledger: val.ledger || {}
        }
      });
    } catch {
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR' });
    }
  });

  // ==========================================
  // 8. RAZORPAY PAYMENTS
  // ==========================================
  r.get('/payments', async (req, res) => {
    try {
      const snap = await db.ref('payment_orders').get();
      const items = [];
      for (const [key, p] of Object.entries(snap.val() || {})) {
        items.push({
          orderId: key,
          uid: p.uid,
          amountPaise: p.amountPaise,
          credits: p.credits,
          creditRate: p.creditRate,
          status: p.status,
          paymentId: p.paymentId || null,
          refundedPaise: p.refundedPaise || 0,
          refundablePaise: getRefundableAmount(p),
          createdAt: p.createdAt || null,
          capturedAt: p.capturedAt || null
        });
      }
      items.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
      const q = String(req.query.search || '').trim().toLowerCase().slice(0, 100);
      const filtered = q ? items.filter(p => (p.orderId + ' ' + p.uid + ' ' + (p.paymentId || '')).toLowerCase().includes(q)) : items;
      res.json({ success: true, payments: filtered.slice(0, 100), truncated: filtered.length > 100, refundsSupported: true });
    } catch {
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR' });
    }
  });

  r.post('/payments/:id/reconcile', async (req, res) => {
    const id = req.params.id;
    if (!/^order_[A-Za-z0-9]+$/.test(id)) return res.status(400).json({ error: 'INVALID_REQUEST' });
    if (!paymentConfig.enabled || !String(paymentConfig.keyId || '').startsWith('rzp_test_')) {
      return res.status(503).json({ error: 'PAYMENTS_DISABLED' });
    }
    try {
      const order = (await db.ref('payment_orders/' + id).get()).val();
      if (!order) return res.status(404).json({ error: 'NOT_FOUND' });
      if (!/^pay_[A-Za-z0-9]+$/.test(order.paymentId || '')) {
        return res.status(409).json({ error: 'PAYMENT_ID_UNAVAILABLE', message: 'No captured payment ID is recorded; investigate the Razorpay dashboard.' });
      }
      const [p, w] = await Promise.all([provider.getPayment(order.paymentId), db.ref('wallets/' + order.uid).get()]);
      const paymentMatches = p.id === order.paymentId && p.order_id === id && p.amount === order.amountPaise && p.currency === 'INR' && p.status === 'captured';
      const credited = w.val()?.paymentOrders?.[id] === order.paymentId;
      const refundedPaise = Number.isSafeInteger(p.amount_refunded) ? p.amount_refunded : null;
      const warnings = [];
      if (!paymentMatches) warnings.push('PROVIDER_RECORD_MISMATCH');
      if (!credited) warnings.push('CREDIT_MARKER_MISSING');
      if (refundedPaise === null) warnings.push('REFUND_AMOUNT_UNAVAILABLE');
      else if (refundedPaise > 0) warnings.push('REFUND_REQUIRES_MANUAL_REVIEW');
      if (order.status !== 'captured') warnings.push('LOCAL_STATUS_MISMATCH');

      await audit(req.user.uid, 'payment.inspected', id);
      res.json({
        success: true,
        providerStatus: p.status,
        recordedStatus: order.status,
        paymentMatches,
        credited,
        refundedPaise,
        warnings,
        message: 'Read-only comparison. Use the Refund Management tab to initiate or inspect refunds.'
      });
    } catch {
      return res.status(502).json({ error: 'PAYMENT_RECONCILIATION_UNAVAILABLE' });
    }
  });

  // ==========================================
  // 9. REFUND MANAGEMENT
  // ==========================================
  r.get('/refunds', async (req, res) => {
    try {
      const snap = await db.ref('payment_refunds').get();
      const items = [];
      for (const [key, r] of Object.entries(snap.val() || {})) { items.push({ id: key, ...r }); }
      items.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
      res.json({ success: true, refunds: items });
    } catch {
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR' });
    }
  });

  r.post('/payments/:id/refund', async (req, res) => {
    const orderId = req.params.id;
    const { amountPaise, reason, speed } = req.body || {};
    try {
      const result = await initiateRefund({
        db,
        provider,
        orderId,
        amountPaise,
        reason,
        adminId: req.user.uid,
        speed: speed || 'normal'
      });
      await audit(req.user.uid, 'payment.refund_initiated', orderId, { refundId: result.id, amountPaise: result.amountPaise });
      res.status(201).json({ success: true, refund: result });
    } catch (err) {
      return res.status(400).json({ error: 'REFUND_FAILED', message: err.message });
    }
  });

  r.post('/refunds/:id/retry', async (req, res) => {
    const refundId = req.params.id;
    try {
      const result = await retryFailedRefund({ db, provider, refundId, adminId: req.user.uid });
      await audit(req.user.uid, 'refund.retried', refundId, { newRefundId: result.id });
      res.json({ success: true, refund: result });
    } catch (err) {
      return res.status(400).json({ error: 'REFUND_RETRY_FAILED', message: err.message });
    }
  });

  // ==========================================
  // 10. CHARGEBACK & DISPUTE MANAGEMENT
  // ==========================================
  r.get('/disputes', async (req, res) => {
    try {
      const snap = await db.ref('payment_disputes').get();
      const items = [];
      for (const [key, d] of Object.entries(snap.val() || {})) { items.push({ id: key, ...d }); }
      items.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
      res.json({ success: true, disputes: items });
    } catch {
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR' });
    }
  });

  r.post('/disputes/:id/evidence', async (req, res) => {
    const disputeId = req.params.id;
    const { evidence } = req.body || {};
    try {
      const result = await recordDisputeEvidence({ db, disputeId, evidenceText: evidence, adminId: req.user.uid });
      res.json({ success: true, dispute: result });
    } catch (err) {
      return res.status(400).json({ error: 'EVIDENCE_SUBMISSION_FAILED', message: err.message });
    }
  });

  r.post('/disputes/:id/recover', async (req, res) => {
    const disputeId = req.params.id;
    const { action, reason } = req.body || {};
    try {
      const result = await resolveDisputeRecovery({ db, disputeId, action, adminId: req.user.uid, reason });
      res.json({ success: true, dispute: result });
    } catch (err) {
      return res.status(400).json({ error: 'DISPUTE_RECOVERY_FAILED', message: err.message });
    }
  });

  // ==========================================
  // 11. FINANCIAL RECONCILIATION
  // ==========================================
  const handleFinancialReconciliationAudit = async (req, res) => {
    try {
      const report = await performReconciliation(db);
      res.json({
        success: true,
        report,
        walletsAudited: report.walletsAudited || 0,
        creditsAudited: report.creditsAudited || 0,
        issues: report.mismatches || []
      });
    } catch {
      return res.status(500).json({ error: 'FINANCIAL_RECONCILIATION_FAILED' });
    }
  };

  r.get(['/reconciliation/financial', '/reconciliation/audit'], handleFinancialReconciliationAudit);
  r.post('/reconciliation/audit', handleFinancialReconciliationAudit);

  r.post(['/reconciliation/financial/resolve', '/reconciliation/resolve'], async (req, res) => {
    const { type, orderId, refundId, uid, action, reason, operationId } = req.body || {};
    try {
      const result = await resolveReconciliationMismatch({
        db,
        type,
        orderId,
        refundId,
        uid,
        action,
        reason: reason || 'Automated ledger discrepancy resolution',
        operationId,
        adminId: req.user.uid
      });
      res.json({ success: true, result });
    } catch (err) {
      return res.status(400).json({ error: 'RECONCILIATION_RESOLUTION_FAILED', message: err.message });
    }
  });

  // ==========================================
  // 12. QUEUE & DEAD-LETTER QUEUE MONITORING
  // ==========================================
  r.get('/queue/status', async (req, res) => {
    try {
      const state = await scanQueueState(db);
      let bullmqCounts = { waiting: 0, active: 0, completed: 0, failed: 0, delayed: 0 };
      if (sendQueue) {
        try {
          bullmqCounts = await sendQueue.getJobCounts('waiting', 'active', 'completed', 'failed', 'delayed');
        } catch {}
      }
      res.json({
        success: true,
        bullmq: bullmqCounts,
        stuck: state.summary,
        details: state
      });
    } catch {
      return res.status(500).json({ error: 'QUEUE_STATUS_UNAVAILABLE' });
    }
  });

  r.get('/queue/metrics', async (req, res) => {
    try {
      const state = await scanQueueState(db);
      res.json({
        success: true,
        stuckProcessing: state.summary?.stuckProcessing || 0,
        stuckQueued: state.summary?.stuckQueued || 0,
        unknownCount: state.summary?.unknownCount || 0,
        dlqCount: state.summary?.dlqCount || 0
      });
    } catch {
      res.json({ success: true, stuckProcessing: 0, stuckQueued: 0, unknownCount: 0, dlqCount: 0 });
    }
  });

  r.post('/queue/recover', async (req, res) => {
    const { uid, id, action, outcome, evidence } = req.body || {};
    if (!id && !uid) {
      try {
        const result = await autoRecoverStuckJobs(db);
        await audit(req.user.uid, 'queue.auto_recover_run', 'system', result);
        return res.json({ success: true, recovered: result.recoveredCount || 0, result });
      } catch {
        return res.status(500).json({ error: 'AUTO_RECOVERY_FAILED' });
      }
    }
    try {
      const result = await manualRecoverJob({
        db,
        sendQueue,
        uid,
        id,
        action,
        outcome,
        evidence,
        adminId: req.user.uid
      });
      await audit(req.user.uid, 'queue.recover', id, { action, uid });
      res.json({ success: true, result });
    } catch (err) {
      return res.status(400).json({ error: 'QUEUE_RECOVERY_FAILED', message: err.message });
    }
  });

  r.post('/queue/auto-recover', async (req, res) => {
    try {
      const result = await autoRecoverStuckJobs(db);
      await audit(req.user.uid, 'queue.auto_recover_run', 'system', result);
      res.json({ success: true, result });
    } catch {
      return res.status(500).json({ error: 'AUTO_RECOVERY_FAILED' });
    }
  });

  // ==========================================
  // 13. ABUSE, BOUNCES & COMPLAINTS
  // ==========================================
  r.get(['/suppressions', '/suppression'], async (req, res) => {
    try {
      const snap = await db.ref('suppression_list').get();
      const items = [];
      for (const [hash, s] of Object.entries(snap.val() || {})) { items.push({ hash, ...s }); }
      res.json({ success: true, suppressions: items, list: items });
    } catch {
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR' });
    }
  });

  r.post(['/suppressions', '/suppression'], async (req, res) => {
    const recipient = (req.body?.recipient || req.body?.email || req.body?.target || '').trim();
    const reason = (req.body?.reason || 'manual_admin_suppression').trim();
    if (!validEmail(recipient) || typeof reason !== 'string' || reason.length < 3 || reason.length > 300) {
      return res.status(400).json({ error: 'INVALID_REQUEST', message: 'Valid email required' });
    }
    try {
      const hash = crypto.createHash('sha256').update(recipient.toLowerCase().trim()).digest('hex');
      const now = Date.now();
      await db.ref('suppression_list/' + hash).set({
        recipient: recipient.toLowerCase().trim(),
        reason: reason.trim(),
        type: 'manual',
        createdAt: now,
        adminId: req.user.uid
      });
      await audit(req.user.uid, 'suppression.created', hash, { recipient: recipient.toLowerCase().trim() });
      res.status(201).json({ success: true, recipientHash: hash, hash });
    } catch {
      return res.status(500).json({ error: 'SUPPRESSION_UPDATE_FAILED' });
    }
  });

  r.delete(['/suppressions/:hash', '/suppression/:hash'], async (req, res) => {
    const hash = req.params.hash;
    const reason = typeof req.body?.reason === 'string' && req.body.reason.trim().length >= 3 ? req.body.reason.trim() : 'admin_manual_unsuppress';
    if (!/^[a-f0-9]{64}$/.test(hash)) {
      return res.status(400).json({ error: 'INVALID_REQUEST' });
    }
    try {
      if (!(await db.ref('suppression_list/' + hash).get()).val()) return res.status(404).json({ error: 'NOT_FOUND' });
      await db.ref('suppression_list/' + hash).set(null);
      await audit(req.user.uid, 'suppression.removed', hash, { reason: reason.trim() });
      res.json({ success: true });
    } catch {
      return res.status(500).json({ error: 'SUPPRESSION_UPDATE_FAILED' });
    }
  });

  r.get('/bounces', async (req, res) => {
    try {
      const snap = await db.ref('bounce_records').get();
      const items = [];
      for (const b of Object.values(snap.val() || {})) { items.push(b); }
      items.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
      res.json({ success: true, bounces: items });
    } catch {
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR' });
    }
  });

  r.get('/complaints', async (req, res) => {
    try {
      const snap = await db.ref('complaint_records').get();
      const items = [];
      for (const comp of Object.values(snap.val() || {})) { items.push(comp); }
      items.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
      res.json({ success: true, complaints: items });
    } catch {
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR' });
    }
  });

  r.post('/bounces/ingest', async (req, res) => {
    const { recipient, type, reason, messageId } = req.body || {};
    try {
      const result = await recordBounce(db, {
        recipient,
        type: type === 'soft' ? 'soft' : 'hard',
        reason: reason || 'Manually ingested bounce',
        messageId,
        source: 'admin_manual'
      });
      await audit(req.user.uid, 'bounce.ingested', recipient, result);
      res.status(201).json({ success: true, result });
    } catch (err) {
      return res.status(400).json({ error: 'BOUNCE_INGESTION_FAILED', message: err.message });
    }
  });

  // ==========================================
  // 14. SUPPORT TICKETS (ADMIN VIEW)
  // ==========================================
  r.get(['/support', '/support/tickets'], async (req, res) => {
    try {
      const snap = await db.ref('support_tickets').get();
      const items = [];
      for (const [uid, userTickets] of Object.entries(snap.val() || {})) {
        for (const [ticketId, t] of Object.entries(userTickets || {})) {
          items.push({
            uid,
            id: ticketId,
            subject: t.subject,
            message: t.message,
            status: t.status,
            createdAt: t.createdAt,
            closedAt: t.closedAt || null,
            replies: t.replies || {}
          });
        }
      }
      items.sort((a, b) => b.createdAt - a.createdAt);
      res.json({ success: true, tickets: items.slice(0, 100), truncated: items.length > 100 });
    } catch {
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR' });
    }
  });

  r.post(['/support/tickets/:id/close', '/support/:uid/:id/close'], async (req, res) => {
    const id = req.params.id;
    const uid = req.params.uid || req.query.uid || req.body?.uid;
    try {
      if (uid) {
        await db.ref(`support_tickets/${uid}/${id}/status`).set('closed');
        await db.ref(`support_tickets/${uid}/${id}/closedAt`).set(Date.now());
      } else {
        const snap = await db.ref('support_tickets').get();
        for (const [u, val] of Object.entries(snap.val() || {})) {
          if (val && val[id]) {
            await db.ref(`support_tickets/${u}/${id}/status`).set('closed');
            await db.ref(`support_tickets/${u}/${id}/closedAt`).set(Date.now());
            break;
          }
        }
      }
      await audit(req.user.uid, 'support.ticket_closed', id, { uid });
      res.json({ success: true });
    } catch {
      return res.status(500).json({ error: 'TICKET_CLOSE_FAILED' });
    }
  });

  r.post('/support/:uid/:id/reply', async (req, res) => {
    const uid = req.params.uid, id = req.params.id;
    const message = typeof req.body?.message === 'string' ? req.body.message.trim() : '';
    if (!safeId(uid) || !/^[0-9a-f-]{36}$/.test(id) || message.length < 2 || message.length > 4000) {
      return res.status(400).json({ error: 'INVALID_REQUEST' });
    }
    try {
      const t = (await db.ref(`support_tickets/${uid}/${id}`).get()).val();
      if (!t) return res.status(404).json({ error: 'NOT_FOUND' });
      if (t.status !== 'open') return res.status(409).json({ error: 'TICKET_CLOSED' });
      const replyId = crypto.randomUUID(), now = Date.now();
      await db.ref(`support_tickets/${uid}/${id}/replies/${replyId}`).set({ message, adminId: req.user.uid, createdAt: now });
      await audit(req.user.uid, 'support.replied', id, { uid });
      const notifId = 'notif_' + now + '_' + Math.random().toString(36).slice(2, 8);
      await db.ref(`notifications/${uid}/${notifId}`).set({
        id: notifId,
        uid,
        title: `Support Ticket Reply: ${t.subject || 'Support Request'}`,
        message: message.length > 120 ? message.slice(0, 117) + '...' : message,
        category: 'system',
        type: 'info',
        link: '/support.html',
        read: false,
        readAt: null,
        createdAt: now
      }).catch(() => {});
      res.json({ success: true });
    } catch {
      return res.status(500).json({ error: 'SUPPORT_UPDATE_FAILED' });
    }
  });

  // ==========================================
  // 15. SYSTEM SETTINGS (PRICING, LIMITS, RETENTION)
  // ==========================================
  r.get(['/settings', '/pricing'], async (req, res) => {
    try {
      const data = (await db.ref('platform_settings').get()).val() || {};
      const retention = await getRetentionPolicies(db);
      res.json({
        success: true,
        creditRate: data.creditRate ?? 5,
        rateLimits: data.rateLimits || {},
        maintenanceMode: data.maintenanceMode || false,
        retention
      });
    } catch {
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR' });
    }
  });

  r.post(['/settings', '/pricing'], async (req, res) => {
    const rate = req.body?.creditRate;
    const maintenanceMode = req.body?.maintenanceMode;
    try {
      if (maintenanceMode !== undefined) {
        await db.ref('platform_settings/maintenanceMode').set(maintenanceMode === true || maintenanceMode === 'true');
      }
      if (rate !== undefined) {
        if (!Number.isSafeInteger(rate) || rate < 1 || rate > 100) {
          return res.status(400).json({ error: 'INVALID_REQUEST', message: 'Rate must be an integer from 1 to 100 credits per rupee.' });
        }
        await db.ref('platform_settings/creditRate').set(rate);
        await audit(req.user.uid, 'settings.credit_rate', 'creditRate', { value: rate });
      }
      res.json({ success: true, creditRate: rate, maintenanceMode });
    } catch {
      return res.status(500).json({ error: 'SETTINGS_UPDATE_FAILED' });
    }
  });

  r.get('/settings/retention', async (req, res) => {
    try {
      const policies = await getRetentionPolicies(db);
      res.json({ success: true, policies, retention: policies });
    } catch {
      return res.status(500).json({ error: 'RETENTION_SETTINGS_UNAVAILABLE' });
    }
  });

  r.post('/settings/retention', async (req, res) => {
    try {
      const updated = await setRetentionPolicies(db, req.body, req.user.uid);
      res.json({ success: true, policies: updated, retention: updated });
    } catch (err) {
      return res.status(400).json({ error: 'RETENTION_UPDATE_FAILED', message: err.message });
    }
  });

  r.post('/retention/run', async (req, res) => {
    try {
      const result = await runRetentionCleanup(db, req.user.uid);
      res.json({ success: true, result });
    } catch (err) {
      return res.status(500).json({ error: 'RETENTION_RUN_FAILED', message: err.message });
    }
  });

  // ==========================================
  // 16. ADMIN ACTIVITY LOGS & FINANCIAL ALERTS
  // ==========================================
  r.get('/activity', async (req, res) => {
    try {
      const snap = await db.ref('admin_logs').get();
      const items = [];
      for (const [key, l] of Object.entries(snap.val() || {})) { items.push({ id: key, ...l }); }
      items.sort((a, b) => (b.createdAt || b.timestamp || 0) - (a.createdAt || a.timestamp || 0));
      res.json({
        success: true,
        activity: items.slice(0, 100),
        logs: items.slice(0, 100),
        total: items.length,
        note: 'Credit adjustments and outcome reconciliation also have authoritative records in the affected wallet ledger.'
      });
    } catch {
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR' });
    }
  });

  r.get(['/financial-alerts', '/payments/alerts'], async (req, res) => {
    try {
      const data = (await db.ref('financial_alerts').get()).val() || {};
      const alerts = Object.entries(data).map(([id, v]) => ({ id, ...v })).sort((a, b) => b.createdAt - a.createdAt).slice(0, 100);
      res.json({ success: true, alerts });
    } catch {
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR' });
    }
  });

  r.get('/deletion-history', async (req, res) => {
    try {
      const snap = await db.ref('data_deletion_logs').get();
      const items = [];
      for (const [key, d] of Object.entries(snap.val() || {})) { items.push({ id: key, ...d }); }
      items.sort((a, b) => (b.deletedAt || 0) - (a.deletedAt || 0));
      res.json({ success: true, deletions: items });
    } catch {
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR' });
    }
  });

  // ==========================================
  // 17. ANNOUNCEMENTS BROADCAST
  // ==========================================
  r.get('/announcements', async (req, res) => {
    try {
      const snap = await db.ref('announcements').get();
      const items = [];
      for (const [id, a] of Object.entries(snap.val() || {})) {
        items.push({ id, ...a });
      }
      items.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
      res.json({ success: true, announcements: items });
    } catch {
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR' });
    }
  });

  r.post('/announcements', async (req, res) => {
    const { title, message, type } = req.body || {};
    if (typeof title !== 'string' || title.trim().length < 3 || typeof message !== 'string' || message.trim().length < 5) {
      return res.status(400).json({ error: 'INVALID_REQUEST', message: 'Title (min 3 chars) and message (min 5 chars) are required.' });
    }
    const cleanType = ['info', 'warning', 'critical'].includes(type) ? type : 'info';
    try {
      const id = 'ann_' + Date.now() + '_' + Math.random().toString(36).slice(2, 6);
      const now = Date.now();
      const announcement = {
        title: title.trim(),
        message: message.trim(),
        type: cleanType,
        active: true,
        author: req.user.email || req.user.uid,
        createdAt: now
      };
      await db.ref('announcements/' + id).set(announcement);
      await audit(req.user.uid, 'announcement.created', id, { title: announcement.title });
      res.status(201).json({ success: true, id, announcement });
    } catch {
      return res.status(500).json({ error: 'ANNOUNCEMENT_CREATE_FAILED' });
    }
  });

  r.delete('/announcements/:id', async (req, res) => {
    const id = req.params.id;
    if (!safeId(id)) return res.status(400).json({ error: 'INVALID_REQUEST' });
    try {
      await db.ref('announcements/' + id).remove();
      await audit(req.user.uid, 'announcement.deleted', id);
      res.json({ success: true });
    } catch {
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR' });
    }
  });

  // ==========================================
  // 18. BACKUPS & DISASTER RECOVERY
  // ==========================================
  r.get('/backups', async (req, res) => {
    try {
      const snap = await db.ref('backups').get();
      const items = [];
      for (const [id, b] of Object.entries(snap.val() || {})) {
        items.push({ id, ...b });
      }
      items.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
      res.json({ success: true, backups: items });
    } catch {
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR' });
    }
  });

  r.post('/backups', async (req, res) => {
    try {
      const [uSnap, wSnap, sSnap, pSnap] = await Promise.all([
        db.ref('users').get(),
        db.ref('wallets').get(),
        db.ref('sender_accounts').get(),
        db.ref('pricing').get()
      ]);
      const data = {
        users: uSnap.val() || {},
        wallets: wSnap.val() || {},
        senders: sSnap.val() || {},
        pricing: pSnap.val() || {},
        createdAt: Date.now()
      };
      const jsonStr = JSON.stringify(data);
      const hash = crypto.createHash('sha256').update(jsonStr).digest('hex');
      const id = 'bkp_' + Date.now();
      const meta = {
        id,
        createdAt: Date.now(),
        sha256: hash,
        userCount: Object.keys(data.users).length,
        senderCount: Object.keys(data.senders).length,
        sizeBytes: Buffer.byteLength(jsonStr, 'utf8'),
        author: req.user.email || req.user.uid
      };
      await db.ref('backups/' + id).set(meta);
      await audit(req.user.uid, 'backup.created', id, { sha256: hash });
      res.status(201).json({ success: true, backup: meta });
    } catch {
      return res.status(500).json({ error: 'BACKUP_CREATION_FAILED' });
    }
  });

  return r;
}

module.exports = { adminRoutes };
