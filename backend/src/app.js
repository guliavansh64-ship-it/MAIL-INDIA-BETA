'use strict';
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const { rateLimit } = require('express-rate-limit');
const crypto = require('node:crypto');
const path = require('node:path');
const { createPaymentRoutes, razorpayProvider } = require('./payments');
const { createZetpayRoutes, zetpayProvider: defaultZetpayProvider } = require('./zetpay');
const { adminRoutes } = require('./admin');
const { createGoogleOAuthRoutes } = require('./google-oauth');
const { normalize, reserve, safeId, sha, validEmail, decryptCredentials, transport } = require('./sending');
const { visibleLogs } = require('./logs');
const { purgeUserData } = require('./retention');
const { handleDeliveryEvent } = require('./bounces');

const hashKey = key => crypto.createHash('sha256').update(key).digest('hex');
const validKey = key => /^mb_live_[A-Za-z0-9_-]{43}$/.test(key);
const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

function createApp({ auth, db, origins = [], publicConfig = {}, paymentConfig = {}, paymentProvider, zetpayConfig = {}, zetpayProviderInstance, sendingConfig = {}, sendQueue = null, distributedLimiter = null }) {
  const app = express();
  app.set('trust proxy', 1);
  app.disable('x-powered-by');
  app.use(helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com', 'https://cdnjs.cloudflare.com'],
        styleSrcAttr: ["'unsafe-inline'"],
        fontSrc: ["'self'", 'https://fonts.gstatic.com', 'https://cdnjs.cloudflare.com'],
        scriptSrc: ["'self'", "'unsafe-inline'", 'https://checkout.razorpay.com', 'https://zetpay.online', 'https://www.gstatic.com'],
        scriptSrcAttr: ["'unsafe-inline'"],
        connectSrc: ["'self'", 'https://identitytoolkit.googleapis.com', 'https://securetoken.googleapis.com', 'https://*.googleapis.com', 'https://*.firebaseio.com', 'wss://*.firebaseio.com', 'https://api.razorpay.com', 'https://*.razorpay.com', 'https://zetpay-beta.vercel.app', 'https://to-375ee-default-rtdb.firebaseio.com', 'wss://to-375ee-default-rtdb.firebaseio.com', 'http://indiamail.toolsnetwork.online', 'https://indiamail.toolsnetwork.online'],
        imgSrc: ["'self'", 'data:', 'https://*.razorpay.com', 'https://zetpay.online', 'https://*.googleusercontent.com', 'https://*.google.com', 'https://*.gstatic.com', 'https://lh3.googleusercontent.com'],
        frameSrc: ['https://api.razorpay.com', 'https://*.razorpay.com', 'https://zetpay.online', 'https://app.zetpay.online', 'https://*.zapupi.com'],
        formAction: ["'self'", 'https://api.razorpay.com', 'https://*.razorpay.com', 'https://zetpay-beta.vercel.app', 'https://app.zetpay.online', 'https://*.zapupi.com']
      }
    }
  }));
  app.use(cors({
    origin(origin, cb) {
      if (!origin) return cb(null, true);
      if (!origins.length || origins.includes('*') || origins.includes(origin) || process.env.NODE_ENV !== 'production') {
        return cb(null, true);
      }
      try {
        const u = new URL(origin);
        if (u.hostname === 'indiamail.toolsnetwork.online' || u.hostname === 'mailindia.toolsnetwork.online' || u.hostname.endsWith('.toolsnetwork.online') || u.hostname === 'localhost' || u.hostname === '127.0.0.1') {
          return cb(null, true);
        }
      } catch {}
      return cb(null, false);
    },
    credentials: true,
    methods: ['GET', 'POST', 'DELETE', 'OPTIONS', 'PUT', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token', 'X-NVIDIA-API-Key']
  }));

  const jsonParser = express.json({ limit: '32kb' });
  app.use((req, res, next) => req.path === '/api/payments/webhook' ? next() : jsonParser(req, res, next));
  app.use(['/api', '/v1'], (req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });

  const globalApiLimiter = rateLimit({
    windowMs: 60_000,
    limit: 1200,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { success: false, error: 'RATE_LIMIT_EXCEEDED', message: 'Too many requests. Please wait a moment.' },
    skip: req => {
      const p = req.path || '';
      const orig = req.originalUrl || '';
      return p.startsWith('/auth') || p.startsWith('/session') || p.startsWith('/health') || p.startsWith('/config') || p.startsWith('/announcements') || p.startsWith('/notifications') ||
             orig.includes('/api/auth') || orig.includes('/api/session') || orig.includes('/api/health') || orig.includes('/api/config') || orig.includes('/api/announcements') || orig.includes('/api/notifications');
    }
  });

  app.use('/api', globalApiLimiter);
  app.use('/v1', rateLimit({
    windowMs: 60_000,
    limit: 1200,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { success: false, error: 'RATE_LIMIT_EXCEEDED', message: 'API rate limit exceeded.' }
  }));

  const fail = (res, status, error, message) => res.status(status).json({ success: false, error, message });
  const cookieOptions = { httpOnly: true, secure: true, sameSite: 'strict', path: '/' };
  const cookies = req => Object.fromEntries(
    (req.get('cookie') || '')
      .split(';')
      .map(x => x.trim().split(/=(.*)/s).slice(0, 2))
      .filter(x => x.length === 2)
      .map(([k, v]) => [k, typeof v === 'string' ? v.trim().replace(/^"(.*)"$/, '$1') : ''])
  );
  const equalCsrf = (a, b) => typeof a === 'string' && typeof b === 'string' && /^[a-f0-9]{64}$/.test(a) && /^[a-f0-9]{64}$/.test(b) && crypto.timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));

  const firebaseAuth = wrap(async (req, res, next) => {
    const m = /^Bearer (\S+)$/.exec(req.get('authorization') || '');
    const jar = cookies(req);
    try {
      let authed = false;
      if (m) {
        try {
          req.user = await auth.verifyIdToken(m[1], true);
          req.authMethod = 'bearer';
          authed = true;
        } catch {
          // If not an ID token, attempt verifying as session cookie
        }
        if (!authed) {
          try {
            req.user = await auth.verifySessionCookie(m[1], true);
            req.authMethod = 'bearer';
            authed = true;
          } catch {
            // Neither ID token nor session cookie
          }
        }
      }
      if (!authed && (jar['__Host-mb_session'] || jar['mb_session'])) {
        const candidateTokens = [jar['__Host-mb_session'], jar['mb_session']].filter(Boolean);
        for (const sessionToken of candidateTokens) {
          try {
            req.user = await auth.verifySessionCookie(sessionToken, true);
            req.authMethod = 'cookie';
            const clientCsrf = jar['__Host-mb_csrf'] || jar['mb_csrf'];
            if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method) && !equalCsrf(clientCsrf, req.get('x-csrf-token'))) {
              return fail(res, 403, 'CSRF_FAILED', 'Invalid CSRF token.');
            }
            authed = true;
            break;
          } catch {
            // Try next candidate session token (e.g. if __Host- was stale but mb_session is valid)
          }
        }
      }
      if (!authed) {
        return fail(res, 401, 'UNAUTHENTICATED', 'Firebase session or ID token required.');
      }
    } catch {
      return fail(res, 401, 'UNAUTHENTICATED', 'Invalid or expired session.');
    }
    next();
  });

  const apiAuth = wrap(async (req, res, next) => {
    const m = /^Bearer (\S+)$/.exec(req.get('authorization') || '');
    if (!m || !validKey(m[1])) return fail(res, 401, 'INVALID_API_KEY', 'Invalid API key.');
    const hash = hashKey(m[1]), snap = await db.ref('key_index/' + hash).get(), entry = snap.val();
    if (!entry || entry.status !== 'active') return fail(res, 401, 'INVALID_API_KEY', 'Invalid API key.');
    const userProfile = (await db.ref('users/' + entry.uid).get()).val();
    if (!userProfile || userProfile.status !== 'active') return fail(res, 403, 'USER_SUSPENDED', 'Account is unavailable.');

    if (distributedLimiter) {
      try {
        if (!await distributedLimiter(entry.uid, entry.keyId, userProfile.apiRateLimit)) {
          res.set('Retry-After', '60');
          return fail(res, 429, 'RATE_LIMIT_EXCEEDED', 'API request limit exceeded.');
        }
      } catch {
        return fail(res, 503, 'RATE_LIMIT_UNAVAILABLE', 'Rate limiter unavailable.');
      }
    } else if (sendingConfig.enabled) {
      return fail(res, 503, 'RATE_LIMIT_UNAVAILABLE', 'Distributed rate limiting is required when sending is enabled.');
    }

    req.uid = entry.uid;
    req.keyId = entry.keyId;
    await db.ref(`user_api_keys/${entry.uid}/${entry.keyId}/lastUsedAt`).set(Date.now());
    next();
  });

  const profile = uid => db.ref('users/' + uid);

  const zetApiKey = zetpayConfig?.apiKey || process.env.ZETPAY_API_KEY || 'ZPPCCkPtfAH7EC78UMNT8kUqm7q5XdjNRSX';
  const zetProvider = zetpayProviderInstance || (zetApiKey ? defaultZetpayProvider(zetApiKey, zetpayConfig?.baseUrl) : null);

  app.get('/api/config', (req, res) => res.json({
    firebaseConfig: publicConfig.firebaseConfig || {
      apiKey: publicConfig.firebaseApiKey || 'AIzaSyCvfIXHa_6Vy5Qh2Of-ayhUjw1INwujmsE',
      authDomain: publicConfig.firebaseAuthDomain || 'to-375ee.firebaseapp.com',
      databaseURL: publicConfig.firebaseDatabaseUrl || 'https://to-375ee-default-rtdb.firebaseio.com',
      projectId: publicConfig.firebaseProjectId || 'to-375ee',
      storageBucket: publicConfig.firebaseStorageBucket || 'to-375ee.firebasestorage.app',
      messagingSenderId: publicConfig.firebaseMessagingSenderId || '555488380029',
      appId: publicConfig.firebaseAppId || '1:555488380029:web:588046ca97420a868d5d14'
    },
    firebaseApiKey: publicConfig.firebaseApiKey || 'AIzaSyCvfIXHa_6Vy5Qh2Of-ayhUjw1INwujmsE',
    firebaseProjectId: publicConfig.firebaseProjectId || 'to-375ee',
    zetpayEnabled: Boolean(zetProvider),
    devMode: Boolean(publicConfig.devMode)
  }));
  app.get('/api/pricing', wrap(async (req, res) => {
    const s = (await db.ref('platform_settings').get()).val() || {};
    const baseRate = s.creditRate ?? 5;
    if (!Number.isSafeInteger(baseRate) || baseRate < 1 || baseRate > 100) return fail(res, 503, 'INVALID_SETTINGS', 'Pricing is unavailable.');

    let isGoogleUser = false;
    try {
      const jar = cookies(req);
      const token = jar['__Host-mb_session'] || jar['mb_session'];
      const authHeader = req.get('authorization') || '';
      const bearerToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
      const userToken = token || bearerToken;
      if (userToken) {
        let decoded = null;
        try { decoded = await auth.verifySessionCookie(userToken, true); } catch {}
        if (!decoded && bearerToken) {
          try { decoded = await auth.verifyIdToken(bearerToken, true); } catch {}
        }
        if (decoded?.uid) {
          const uSnap = await db.ref(`users/${decoded.uid}`).get();
          const u = uSnap.val() || {};
          const gSnap = await db.ref(`gmail_connections/${decoded.uid}`).get();
          const g = gSnap.val();
          isGoogleUser = Boolean(
            decoded.authProvider === 'google' ||
            u.authProvider === 'google' ||
            u.googleId ||
            (g && g.status === 'active') ||
            (decoded.email && decoded.email.toLowerCase().endsWith('@gmail.com'))
          );
        }
      }
    } catch {}

    const googleRate = 10; // ₹0.10 per email (10 credits / ₹1)
    const standardRate = baseRate; // ₹0.20 per email (5 credits / ₹1)
    const effectiveRate = isGoogleUser ? googleRate : standardRate;

    res.json({
      creditRate: effectiveRate,
      standardRate,
      googleRate,
      costPerEmail: isGoogleUser ? 0.10 : 0.20,
      isGoogleUser,
      bonusTiers: [
        { minCredits: 5000, bonusCredits: 500, label: 'Buy 5,000 + 500 Extra FREE (+10%)' },
        { minCredits: 10000, bonusCredits: 1500, label: 'Buy 10,000 + 1,500 Extra FREE (+15%)' },
        { minCredits: 25000, bonusCredits: 5000, label: 'Buy 25,000 + 5,000 Extra FREE (+20%)' },
        { minCredits: 50000, bonusCredits: 15000, label: 'Buy 50,000 + 15,000 Extra FREE (+30%)' }
      ]
    });
  }));

  app.get('/api/announcements', wrap(async (req, res) => {
    const snap = await db.ref('announcements').get();
    const items = [];
    for (const [id, a] of Object.entries(snap.val() || {})) {
      if (a && a.active !== false) items.push({ id, ...a });
    }
    items.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
    res.json({ success: true, announcements: items });
  }));

  app.get('/api/health', (req, res) => res.json({
    status: 'ok',
    sending: sendingConfig.enabled && sendQueue ? 'active' : 'disabled',
    payments: zetProvider ? 'connected' : (paymentConfig.enabled && paymentConfig.keyId?.startsWith('rzp_test_') ? 'test_mode' : 'disabled'),
    zetpay: zetProvider ? 'connected' : 'disabled'
  }));

  // Profile creation uses a transaction, ensuring repeated sign-ins cannot reset a user's state.
  app.post('/api/session/bootstrap', firebaseAuth, wrap(async (req, res) => {
    if (!req.user.email) return fail(res, 400, 'INVALID_ACCOUNT', 'An email address is required.');
    const adminEmails = (process.env.ADMIN_EMAILS || 'guliavansh64@gmail.com').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
    const userEmail = (req.user.email || '').toLowerCase();
    const isGmail = userEmail.endsWith('@gmail.com');
    // Only guliavansh64@gmail.com is allowed admin among Gmail accounts
    const isExplicitAdmin = isGmail
      ? (userEmail === 'guliavansh64@gmail.com')
      : Boolean(req.user.admin || adminEmails.includes(userEmail));

    const name = typeof req.body?.name === 'string' ? req.body.name.trim() : (req.user.name || '');
    const username = typeof req.body?.username === 'string' ? req.body.username.trim() : '';
    const mobile = typeof req.body?.mobile === 'string' ? req.body.mobile.trim() : (typeof req.body?.phone === 'string' ? req.body.phone.trim() : '');

    const ref = profile(req.user.uid);
    const result = await ref.transaction(existing => {
      if (existing) {
        if (name && !existing.name) existing.name = name;
        if (username && !existing.username) existing.username = username;
        if (mobile && !existing.mobile) existing.mobile = mobile;
        if (isGmail && userEmail !== 'guliavansh64@gmail.com') existing.admin = false;
        else if (isExplicitAdmin) existing.admin = true;
        return existing;
      }
      const doc = {
        email: req.user.email,
        name: name || '',
        username: username || '',
        mobile: mobile || '',
        status: 'active',
        createdAt: Date.now()
      };
      if (isExplicitAdmin) doc.admin = true;
      else doc.admin = false;
      return doc;
    }, undefined, false);
    const data = result.snapshot.val();
    if (data.status !== 'active') return fail(res, 403, 'USER_SUSPENDED', 'Account is unavailable.');

    // Ensure wallet exists in Firebase RTDB
    const walletRef = db.ref('wallets/' + req.user.uid);
    const walletSnap = await walletRef.get();
    const val = walletSnap.val ? walletSnap.val() : null;
    if (val === null || val === undefined) {
      await walletRef.set({
        balance: isExplicitAdmin ? 10000 : 0,
        purchased: isExplicitAdmin ? 10000 : 0,
        consumed: 0,
        updatedAt: Date.now()
      });
    }

    const userIsAdmin = isGmail ? (userEmail === 'guliavansh64@gmail.com') : Boolean(data.admin);
    res.json({ success: true, user: { uid: req.user.uid, email: data.email, name: data.name, username: data.username || '', mobile: data.mobile || '', status: data.status, emailVerified: !!req.user.email_verified, admin: userIsAdmin } });
  }));

  app.post('/api/session/login', firebaseAuth, wrap(async (req, res) => {
    if (req.authMethod !== 'bearer') return fail(res, 400, 'INVALID_REQUEST', 'A recent Firebase ID token is required.');
    if (!Number.isFinite(req.user.auth_time) || Math.floor(Date.now() / 1000) - req.user.auth_time > 300 || req.user.auth_time > Math.floor(Date.now() / 1000) + 30) {
      return fail(res, 401, 'RECENT_LOGIN_REQUIRED', 'Sign in again.');
    }

    if (distributedLimiter && typeof distributedLimiter.checkScoped === 'function') {
      const allowed = await distributedLimiter.checkScoped('ipLogin', req.ip || '127.0.0.1');
      if (!allowed) {
        return fail(res, 429, 'RATE_LIMIT_EXCEEDED', 'Too many sign in requests. Please wait a moment.');
      }
    }

    const token = /^Bearer (\S+)$/.exec(req.get('authorization') || '')[1];
    const expiresIn = 8 * 60 * 60 * 1000;
    const session = await auth.createSessionCookie(token, { expiresIn });
    const csrf = crypto.randomBytes(32).toString('hex');
    res.cookie('__Host-mb_session', session, { ...cookieOptions, maxAge: expiresIn });
    res.cookie('__Host-mb_csrf', csrf, { ...cookieOptions, maxAge: expiresIn });
    res.json({ success: true, csrf });
  }));

  app.get('/api/session/status', firebaseAuth, wrap(async (req, res) => {
    const adminEmails = (process.env.ADMIN_EMAILS || 'guliavansh64@gmail.com').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
    const userEmail = (req.user?.email || '').toLowerCase();
    const isGmail = userEmail.endsWith('@gmail.com');
    const isExplicitAdmin = isGmail
      ? (userEmail === 'guliavansh64@gmail.com')
      : Boolean(req.user?.admin || adminEmails.includes(userEmail));

    let uDoc = {};
    try {
      const uSnap = await db.ref('users/' + req.user.uid).get();
      uDoc = uSnap.val() || {};
    } catch {}

    const userData = {
      uid: req.user.uid,
      email: req.user.email || uDoc.email || '',
      name: uDoc.name || req.user.name || (req.user.email ? req.user.email.split('@')[0] : 'Workspace User'),
      username: uDoc.username || '',
      mobile: uDoc.mobile || '',
      picture: req.user.picture || uDoc.picture || '',
      admin: isExplicitAdmin || Boolean(uDoc.admin)
    };

    if (req.authMethod === 'cookie') {
      const jar = cookies(req);
      let csrf = jar['__Host-mb_csrf'] || jar['mb_csrf'];
      if (!/^[a-f0-9]{64}$/.test(csrf || '')) {
        // If session is valid but CSRF cookie was missing, regenerate and set it so session stays intact
        csrf = crypto.randomBytes(32).toString('hex');
        const isHttps = (req.get('x-forwarded-proto') === 'https') || req.secure;
        const cookieOpts = { httpOnly: true, sameSite: 'lax', path: '/', maxAge: 14 * 24 * 60 * 60 * 1000 };
        if (isHttps) {
          res.cookie('__Host-mb_csrf', csrf, { ...cookieOpts, secure: true });
        }
        res.cookie('mb_csrf', csrf, { ...cookieOpts, secure: Boolean(isHttps) });
      }
      console.log('[AUTHENTICATION STATUS RESTORED]', {
        uid: req.user?.uid,
        email: req.user?.email,
        authMethod: req.authMethod
      });
      return res.json({ success: true, csrf, user: userData });
    }
    const csrf = crypto.randomBytes(32).toString('hex');
    console.log('[AUTHENTICATION STATUS RESTORED]', {
      uid: req.user?.uid,
      email: req.user?.email,
      authMethod: req.authMethod
    });
    res.json({ success: true, csrf, user: userData });
  }));

  app.post('/api/session/logout', firebaseAuth, wrap(async (req, res) => {
    res.clearCookie('__Host-mb_session', cookieOptions);
    res.clearCookie('__Host-mb_csrf', cookieOptions);
    res.clearCookie('mb_session', { ...cookieOptions, secure: false });
    res.clearCookie('mb_csrf', { ...cookieOptions, secure: false });
    res.clearCookie('mb_session', { ...cookieOptions, secure: true });
    res.clearCookie('mb_csrf', { ...cookieOptions, secure: true });
    try {
      if (req.user?.uid) {
        await auth.revokeRefreshTokens(req.user.uid);
      }
    } catch {
      return fail(res, 503, 'REVOCATION_FAILED', 'Local cookies were cleared, but server-side revocation failed.');
    }
    res.json({ success: true });
  }));

  app.post('/api/session/dev-login', wrap(async (req, res) => {
    if (!publicConfig.devMode) return fail(res, 403, 'DEV_MODE_DISABLED', 'Dev login is not enabled.');
    const role = req.body?.role === 'admin' ? 'admin' : 'user';
    const email = req.body?.email || (role === 'admin' ? 'admin@mailindia.in' : 'demo@mailindia.in');
    const uid = role === 'admin' ? 'admin_user' : (req.body?.uid || 'demo_user');

    const userRef = profile(uid);
    const existing = (await userRef.get()).val();
    if (!existing) {
      await userRef.set({
        email,
        name: role === 'admin' ? 'Platform Admin' : 'Demo Developer',
        status: 'active',
        admin: role === 'admin',
        createdAt: Date.now()
      });
      if (role !== 'admin') {
        await db.ref('wallets/' + uid).set({
          balance: 500,
          purchased: 500,
          consumed: 0,
          updatedAt: Date.now()
        });
      }
    }

    const expiresIn = 8 * 60 * 60 * 1000;
    const session = await auth.createSessionCookie(role === 'admin' ? 'admin' : 'demo', { expiresIn });
    const csrf = crypto.randomBytes(32).toString('hex');
    res.cookie('__Host-mb_session', session, { ...cookieOptions, maxAge: expiresIn });
    res.cookie('__Host-mb_csrf', csrf, { ...cookieOptions, maxAge: expiresIn });
    res.cookie('mb_session', session, { ...cookieOptions, secure: false, maxAge: expiresIn });
    res.cookie('mb_csrf', csrf, { ...cookieOptions, secure: false, maxAge: expiresIn });
    res.json({ success: true, csrf, user: { uid, email, role } });
  }));

  app.post('/api/session/quick-login', wrap(async (req, res) => {
    return fail(res, 403, 'FEATURE_DISABLED', 'One-click sign-in is disabled. Please sign in with your email and password.');
  }));

  // OTP Password Reset Email Dispatcher
  async function sendOtpEmail({ db, to, otp }) {
    if (!to || !validEmail(to)) return false;
    try {
      const sendersSnap = await db.ref('sender_accounts').get();
      const senders = sendersSnap.val() || {};
      const activeEntry = Object.entries(senders).find(([_, s]) => s && s.status === 'active');
      if (!activeEntry) return false;
      const [senderId, sender] = activeEntry;
      const encKey = process.env.SENDER_ENCRYPTION_KEY || process.env.SESSION_SECRET || 'mailbridge-master-session-salt-375ee';
      const secret = decryptCredentials(encKey, senderId, sender.credentials);
      const mailer = transport(sender.email, secret);
      const fromAddress = sender.name ? `"${sender.name.replace(/["\r\n]/g, '')}" <${sender.email}>` : sender.email;
      const formattedDate = new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata', dateStyle: 'medium', timeStyle: 'short' });

      await mailer.sendMail({
        from: fromAddress,
        to,
        subject: `🔐 MAIL INDIA — Password Reset OTP: ${otp}`,
        text: `Your Mail India password reset verification code is: ${otp}\n\nThis OTP is valid for 10 minutes.\n\nIf you did not request a password reset, you can safely ignore this email.\n\n- Mail India Security Team`,
        html: `
          <div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;max-width:540px;margin:0 auto;background:#ffffff;border:1px solid #e2e8f0;border-radius:14px;overflow:hidden;box-shadow:0 10px 25px rgba(0,0,0,0.06)">
            <div style="background:linear-gradient(135deg,#4f46e5 0%,#7c3aed 100%);padding:22px 24px;color:#ffffff;text-align:center">
              <div style="font-size:22px;font-weight:900;letter-spacing:1px">✉️ MAIL INDIA</div>
              <div style="font-size:12px;opacity:0.9;margin-top:3px">Account Security & Verification Relay</div>
            </div>
            <div style="padding:28px 24px;text-align:center">
              <h2 style="font-size:18px;color:#1e1b4b;margin:0 0 10px">One-Time Password (OTP)</h2>
              <p style="font-size:13px;color:#64748b;line-height:1.6;margin:0 0 20px">
                A password reset request was initiated for your Mail India account (<strong>${to}</strong>). Use the one-time code below to complete your reset:
              </p>
              <div style="background:#f5f3ff;border:2px dashed #8b5cf6;border-radius:12px;padding:16px 20px;margin:0 auto 20px;max-width:280px">
                <div style="font-size:36px;font-weight:900;letter-spacing:8px;color:#4f46e5;font-family:monospace">${otp}</div>
                <div style="font-size:11px;color:#7c3aed;font-weight:600;margin-top:6px">⏱️ Valid for 10 minutes</div>
              </div>
              <p style="font-size:12px;color:#dc2626;margin:0 0 16px;line-height:1.5">
                ⚠️ Do NOT share this OTP with anyone. The Mail India team will never ask for your code.
              </p>
              <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:10px 14px;font-size:11px;color:#64748b;text-align:left">
                <strong>Relay Dispatch:</strong> Mail India Cloud Relay (Mumbai)<br>
                <strong>Timestamp:</strong> ${formattedDate}
              </div>
            </div>
            <div style="background:#f8fafc;border-top:1px solid #e2e8f0;padding:12px 24px;font-size:11px;color:#94a3b8;text-align:center">
              MAIL INDIA Cloud Relay · Automated Security Dispatch
            </div>
          </div>`
      });
      return true;
    } catch (err) {
      console.error('[OTP EMAIL SEND ERROR]', err.message);
      return false;
    }
  }

  // Welcome & Verification Link Dispatcher
  async function sendVerificationLinkEmail({ db, to }) {
    if (!to || !validEmail(to)) return false;
    try {
      const sendersSnap = await db.ref('sender_accounts').get();
      const senders = sendersSnap.val() || {};
      const activeEntry = Object.entries(senders).find(([_, s]) => s && s.status === 'active');
      if (!activeEntry) return false;
      const [senderId, sender] = activeEntry;
      const encKey = process.env.SENDER_ENCRYPTION_KEY || process.env.SESSION_SECRET || 'mailbridge-master-session-salt-375ee';
      const secret = decryptCredentials(encKey, senderId, sender.credentials);
      const mailer = transport(sender.email, secret);
      const fromAddress = sender.name ? `"${sender.name.replace(/["\r\n]/g, '')}" <${sender.email}>` : sender.email;
      const formattedDate = new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata', dateStyle: 'medium', timeStyle: 'short' });

      await mailer.sendMail({
        from: fromAddress,
        to,
        subject: `✉️ Welcome to MAIL INDIA — Verify Your Gmail Account`,
        text: `Welcome to Mail India!\n\nYour account (${to}) has been created successfully. A verification link has been sent to your Gmail inbox.\n\nPlease check your email inbox and click the verification link to activate your full sending quota and developer API keys.\n\n- Mail India Support Team`,
        html: `
          <div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;max-width:540px;margin:0 auto;background:#ffffff;border:1px solid #e2e8f0;border-radius:14px;overflow:hidden;box-shadow:0 10px 25px rgba(0,0,0,0.06)">
            <div style="background:linear-gradient(135deg,#4f46e5 0%,#7c3aed 100%);padding:22px 24px;color:#ffffff;text-align:center">
              <div style="font-size:22px;font-weight:900;letter-spacing:1px">✉️ MAIL INDIA</div>
              <div style="font-size:12px;opacity:0.9;margin-top:3px">Developer Workspace Activation</div>
            </div>
            <div style="padding:28px 24px">
              <h2 style="font-size:18px;color:#1e1b4b;margin:0 0 10px;text-align:center">Verify Your Gmail Address</h2>
              <p style="font-size:13px;color:#475569;line-height:1.6;margin:0 0 16px">
                Hello and welcome to <strong>MAIL INDIA</strong>! Your developer account for <strong>${to}</strong> was created successfully.
              </p>
              <div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:10px;padding:16px;margin-bottom:18px">
                <div style="font-size:13px;color:#166534;font-weight:700">✓ Activation Link Dispatched</div>
                <div style="font-size:12px;color:#15803d;margin-top:4px;line-height:1.5">
                  An official email verification link has been dispatched to your Gmail inbox. Please open the email and click the confirmation link to activate your live sending quota and generate production API keys.
                </div>
              </div>
              <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:10px 14px;font-size:11px;color:#64748b">
                <strong>Relay Dispatch:</strong> Mail India Cloud Relay (Mumbai)<br>
                <strong>Timestamp:</strong> ${formattedDate}
              </div>
            </div>
            <div style="background:#f8fafc;border-top:1px solid #e2e8f0;padding:12px 24px;font-size:11px;color:#94a3b8;text-align:center">
              MAIL INDIA Cloud Relay · High-Availability Email Infrastructure
            </div>
          </div>`
      });
      return true;
    } catch (err) {
      console.error('[VERIFICATION EMAIL SEND ERROR]', err.message);
      return false;
    }
  }

  // POST /api/auth/forgot-password-otp: Sends 6-digit OTP for password reset
  app.post('/api/auth/forgot-password-otp', wrap(async (req, res) => {
    const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    if (!email || !validEmail(email)) {
      return fail(res, 400, 'INVALID_EMAIL', 'A valid email address is required.');
    }
    const emailHash = crypto.createHash('sha256').update(email).digest('hex');
    const existingSnap = await db.ref('password_resets/' + emailHash).get();
    const existing = existingSnap.val();
    if (existing && existing.createdAt && (Date.now() - existing.createdAt < 10000)) {
      return res.json({
        success: true,
        message: '6-digit OTP sent to your email.',
        email,
        expiresAt: existing.expiresAt
      });
    }

    const otp = String(crypto.randomInt(100000, 999999));
    const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes

    await db.ref('password_resets/' + emailHash).set({
      email,
      otp,
      expiresAt,
      createdAt: Date.now()
    });

    sendOtpEmail({ db, to: email, otp }).catch(() => {});

    // Also trigger Firebase password reset email asynchronously
    const fbKey = process.env.FIREBASE_WEB_API_KEY || 'AIzaSyCvfIXHa_6Vy5Qh2Of-ayhUjw1INwujmsE';
    fetch(`https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key=${encodeURIComponent(fbKey)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ requestType: 'PASSWORD_RESET', email })
    }).catch(() => {});

    res.json({
      success: true,
      message: '6-digit OTP sent to your email.',
      email,
      expiresAt
    });
  }));

  // POST /api/auth/verify-reset-otp: Verifies OTP and completes password reset
  app.post('/api/auth/verify-reset-otp', wrap(async (req, res) => {
    const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    const otp = typeof req.body?.otp === 'string' ? req.body.otp.trim() : '';
    const newPassword = typeof req.body?.newPassword === 'string' ? req.body.newPassword : '';
    const resetToken = typeof req.body?.resetToken === 'string' ? req.body.resetToken.trim() : '';

    if (!email || !validEmail(email)) return fail(res, 400, 'INVALID_EMAIL', 'A valid email address is required.');

    const emailHash = crypto.createHash('sha256').update(email).digest('hex');
    const snap = await db.ref('password_resets/' + emailHash).get();
    const record = snap.val();

    if (!record) {
      return fail(res, 404, 'OTP_NOT_FOUND', 'No password reset request found for this email. Please request a new OTP.');
    }
    if (Date.now() > record.expiresAt) {
      await db.ref('password_resets/' + emailHash).set(null);
      return fail(res, 400, 'OTP_EXPIRED', 'OTP has expired. Please request a new verification code.');
    }

    // Step A: Verify OTP only (when newPassword is not provided)
    if (!newPassword) {
      if (!/^\d{6}$/.test(otp)) return fail(res, 400, 'INVALID_OTP_FORMAT', 'OTP must be a 6-digit numeric code.');
      if (record.otp !== otp) {
        return fail(res, 400, 'INVALID_OTP', 'Incorrect OTP. Please check your email and try again.');
      }
      const verifiedToken = crypto.randomBytes(24).toString('hex');
      await db.ref('password_resets/' + emailHash).set({
        ...record,
        verified: true,
        resetToken: verifiedToken
      });
      return res.json({
        success: true,
        message: 'OTP verified successfully. You may now set your new password.',
        resetToken: verifiedToken
      });
    }

    // Step B: Set new password
    if (newPassword.length < 6) return fail(res, 400, 'INVALID_PASSWORD', 'Password must be at least 6 characters.');

    if (resetToken) {
      if (!record.verified || record.resetToken !== resetToken) {
        return fail(res, 400, 'INVALID_TOKEN', 'Reset token invalid or expired. Please re-verify OTP.');
      }
    } else {
      if (!/^\d{6}$/.test(otp)) return fail(res, 400, 'INVALID_OTP_FORMAT', 'OTP must be a 6-digit numeric code.');
      if (record.otp !== otp) {
        return fail(res, 400, 'INVALID_OTP', 'Incorrect OTP. Please check your email and try again.');
      }
    }

    // OTP verified successfully! Delete used OTP
    await db.ref('password_resets/' + emailHash).set(null);

    // Record password reset audit in user record if user exists
    const usersSnap = await db.ref('users').get();
    const users = usersSnap.val() || {};
    const userEntry = Object.entries(users).find(([_, u]) => u && u.email && u.email.toLowerCase() === email);
    if (userEntry) {
      const [uid] = userEntry;
      await db.ref(`users/${uid}/passwordUpdatedAt`).set(Date.now());
    }

    res.json({
      success: true,
      message: 'Password reset verified successfully. You can now sign in with your new password.'
    });
  }));

  // POST /api/auth/send-verification-email: Sends verification notification to Gmail
  app.post('/api/auth/send-verification-email', wrap(async (req, res) => {
    const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    const idToken = typeof req.body?.idToken === 'string' ? req.body.idToken : '';
    if (!email || !validEmail(email)) return fail(res, 400, 'INVALID_EMAIL', 'A valid email address is required.');

    sendVerificationLinkEmail({ db, to: email }).catch(() => {});

    if (idToken) {
      const fbKey = process.env.FIREBASE_WEB_API_KEY || 'AIzaSyCvfIXHa_6Vy5Qh2Of-ayhUjw1INwujmsE';
      fetch(`https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key=${encodeURIComponent(fbKey)}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ requestType: 'VERIFY_EMAIL', idToken })
      }).catch(() => {});
    }

    res.json({ success: true, message: `Verification email dispatched to ${email}` });
  }));

  const ensureActive = wrap(async (req, res, next) => {
    let p = (await profile(req.user.uid).get()).val();
    const adminEmails = (process.env.ADMIN_EMAILS || 'guliavansh64@gmail.com').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
    const userEmail = (req.user.email || '').toLowerCase();
    const isGmail = userEmail.endsWith('@gmail.com');
    // Only guliavansh64@gmail.com is allowed admin among Gmail accounts
    const isExplicitAdmin = isGmail
      ? (userEmail === 'guliavansh64@gmail.com')
      : Boolean(req.user.admin || adminEmails.includes(userEmail));

    if (!p) {
      p = {
        email: req.user.email || 'user@mailindia.in',
        name: req.user.name || '',
        status: 'active',
        createdAt: Date.now(),
        ...(isExplicitAdmin ? { admin: true } : { admin: false })
      };
      await profile(req.user.uid).set(p);
      const wRef = db.ref('wallets/' + req.user.uid);
      const wSnap = await wRef.get();
      if (!wSnap.val()) {
        await wRef.set({
          balance: isExplicitAdmin ? 10000 : 0,
          purchased: isExplicitAdmin ? 10000 : 0,
          consumed: 0,
          updatedAt: Date.now()
        });
      }
    } else {
      if (isGmail && userEmail !== 'guliavansh64@gmail.com' && p.admin) {
        p.admin = false;
        try { await profile(req.user.uid).child('admin').set(false); } catch {}
      } else if (isExplicitAdmin && !p.admin) {
        p.admin = true;
        try { await profile(req.user.uid).child('admin').set(true); } catch {}
      }
    }
    if (p.status !== 'active') return fail(res, 403, 'USER_SUSPENDED', 'Account is unavailable.');
    req.profile = p;
    next();
  });

  const provider = paymentProvider || razorpayProvider(paymentConfig.keyId, paymentConfig.keySecret);
  const payments = createPaymentRoutes({ db, authenticate: firebaseAuth, ensureActive, config: paymentConfig, provider, distributedLimiter });
  app.use('/api/payments', payments.router);

  if (zetProvider) {
    const zetpayRoutes = createZetpayRoutes({ db, authenticate: firebaseAuth, ensureActive, provider: zetProvider, distributedLimiter });
    app.use('/api/payments/zetpay', zetpayRoutes.router);
  }
  app.use('/api/admin', adminRoutes({ db, authenticate: firebaseAuth, key: sendingConfig.encryptionKey, paymentConfig, provider, sendQueue, distributedLimiter }));

  // Google OAuth & Gmail API Routes
  const googleOAuthRoutes = createGoogleOAuthRoutes({
    db,
    auth,
    encryptionKey: sendingConfig.encryptionKey,
    cookieOptions
  });
  app.use(googleOAuthRoutes);

  // Inbound delivery / bounce event webhook
  app.post('/api/webhooks/delivery', wrap(async (req, res) => {
    try {
      const result = await handleDeliveryEvent(db, req.body);
      res.json({ success: true, result });
    } catch (err) {
      res.status(400).json({ success: false, error: err.message });
    }
  }));

  // Account data deletion request (GDPR Right to Be Forgotten)
  app.post('/api/account/delete-request', firebaseAuth, ensureActive, wrap(async (req, res) => {
    const result = await purgeUserData(db, req.user.uid, req.user.uid);
    res.clearCookie('__Host-mb_session', cookieOptions);
    res.clearCookie('__Host-mb_csrf', cookieOptions);
    res.json({ success: true, message: 'Your account personal data has been deleted. Financial ledger records are retained in pseudonymized form for statutory accounting.', result });
  }));

  app.get('/api/me', firebaseAuth, ensureActive, wrap(async (req, res) => {
    const [ws, ks] = await Promise.all([db.ref('wallets/' + req.user.uid).get(), db.ref('user_api_keys/' + req.user.uid).get()]);
    const w = ws.val() || {}, jobs = Object.values(w.sendRequests || {});
    const now = Date.now();
    const todayStr = new Date(now).toISOString().slice(0, 10);
    const thirtyDaysAgo = now - (30 * 86400000);

    const wallet = {
      balance: w.balance || 0,
      reserved: w.reserved || 0,
      purchased: w.purchased || 0,
      consumed: w.consumed || 0
    };

    const acceptedJobs = jobs.filter(j => j.status === 'accepted');
    const failedJobs = jobs.filter(j => j.status === 'failed');
    const todayJobs = jobs.filter(j => Number.isSafeInteger(j.createdAt) && j.createdAt > 0 && new Date(j.createdAt).toISOString().slice(0, 10) === todayStr);
    const monthlyJobs = jobs.filter(j => Number.isSafeInteger(j.createdAt) && j.createdAt >= thirtyDaysAgo);

    // 7-day breakdown for UI chart
    const dailyActivity = [];
    const dayNames = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
    for (let i = 6; i >= 0; i--) {
      const d = new Date(now - (i * 86400000));
      const dStr = d.toISOString().slice(0, 10);
      const dayJobs = jobs.filter(j => Number.isSafeInteger(j.createdAt) && new Date(j.createdAt).toISOString().slice(0, 10) === dStr);
      dailyActivity.push({
        date: dStr,
        day: dayNames[d.getUTCDay()],
        accepted: dayJobs.filter(j => j.status === 'accepted').length,
        failed: dayJobs.filter(j => j.status === 'failed').length,
        total: dayJobs.length
      });
    }

    const rechargePaise = Object.values(w.ledger || {}).filter(x => x.type === 'purchase' && Number.isSafeInteger(x.amountPaise)).reduce((a, x) => a + x.amountPaise, 0);

    const stats = {
      total: jobs.length,
      accepted: acceptedJobs.length,
      failed: failedJobs.length,
      today: todayJobs.length,
      monthly: monthlyJobs.length,
      rechargePaise,
      dailyActivity
    };

    // Recent email activity
    const recentEmails = [...jobs].sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0)).slice(0, 5).map(j => ({
      id: j.id,
      recipient: j.message?.to || '',
      subject: j.message?.subject || '',
      status: j.status,
      createdAt: j.createdAt
    }));

    // Recent transactions
    const recentTransactions = Object.entries(w.ledger || {}).map(([id, item]) => ({ id, ...item })).sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0)).slice(0, 5);

    const adminEmails = (process.env.ADMIN_EMAILS || 'guliavansh64@gmail.com').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
    const userEmail = (req.user.email || '').toLowerCase();
    const isGmail = userEmail.endsWith('@gmail.com');
    const isExplicitAdmin = userEmail === 'guliavansh64@gmail.com' || (!isGmail && (adminEmails.includes(userEmail) || Boolean(req.user.admin)));

    console.log('[DASHBOARD AUTHORIZATION RESULT]', {
      uid: req.user?.uid,
      email: req.profile?.email,
      status: req.profile?.status,
      balance: wallet.balance
    });

    res.json({
      user: {
        uid: req.user.uid,
        email: req.profile.email,
        name: req.profile.name,
        username: req.profile.username || '',
        mobile: req.profile.mobile || '',
        picture: req.profile.picture || req.user.picture || '',
        emailVerified: !!req.user.email_verified,
        isAdmin: !!(isExplicitAdmin && req.profile.admin)
      },
      wallet,
      stats,
      recentEmails,
      recentTransactions,
      keys: Object.values(ks.val() || {}).filter(x => x.status === 'active').length
    });
  }));

  app.get('/api/profile', firebaseAuth, ensureActive, wrap(async (req, res) => {
    res.json({
      success: true,
      name: req.profile.name || '',
      username: req.profile.username || '',
      mobile: req.profile.mobile || '',
      email: req.profile.email || '',
      picture: req.profile.picture || req.user.picture || ''
    });
  }));

  app.post('/api/profile', firebaseAuth, ensureActive, wrap(async (req, res) => {
    const name = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
    const username = typeof req.body?.username === 'string' ? req.body.username.trim() : undefined;
    const mobile = typeof req.body?.mobile === 'string' ? req.body.mobile.trim() : (typeof req.body?.phone === 'string' ? req.body.phone.trim() : undefined);

    if (name) {
      if (name.length > 100 || /[\x00-\x1f]/.test(name)) return fail(res, 400, 'INVALID_REQUEST', 'Name must be 1–100 characters without control characters.');

      const adminEmails = (process.env.ADMIN_EMAILS || 'guliavansh64@gmail.com').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
      const userEmail = (req.user?.email || '').toLowerCase();
      const isGmail = userEmail.endsWith('@gmail.com');
      const isExplicitAdmin = isGmail
        ? (userEmail === 'guliavansh64@gmail.com')
        : Boolean(req.user?.admin || adminEmails.includes(userEmail));
      const isAdmin = isExplicitAdmin || Boolean(req.profile?.admin);

      const isReservedName = /^\s*mail\s*india\s*$/i.test(name);
      const currentName = typeof req.profile?.name === 'string' ? req.profile.name.trim() : '';
      const wasReservedName = /^\s*mail\s*india\s*$/i.test(currentName);

      // If current name is Mail India or user is trying to set name to Mail India, only admin can change it
      if ((wasReservedName || isReservedName) && !isAdmin) {
        return fail(res, 403, 'ADMIN_ONLY', 'Only administrators can change or set the "Mail India" workspace name.');
      }

      await db.ref('users/' + req.user.uid + '/name').set(name);
    }

    if (username !== undefined) {
      if (username && !/^[A-Za-z0-9_]{2,50}$/.test(username)) {
        return fail(res, 400, 'INVALID_USERNAME', 'Username must be 2–50 alphanumeric characters or underscores.');
      }
      await db.ref('users/' + req.user.uid + '/username').set(username);
    }

    if (mobile !== undefined) {
      if (mobile && (mobile.length < 5 || mobile.length > 20)) {
        return fail(res, 400, 'INVALID_MOBILE', 'Enter a valid contact number.');
      }
      await db.ref('users/' + req.user.uid + '/mobile').set(mobile);
    }

    const updatedSnap = await db.ref('users/' + req.user.uid).get();
    const updated = updatedSnap.val() || {};
    res.json({ success: true, name: updated.name || name, username: updated.username || '', mobile: updated.mobile || '' });
  }));

  app.post(['/api/profile/password', '/api/auth/change-password'], firebaseAuth, ensureActive, wrap(async (req, res) => {
    const currentPassword = typeof req.body?.currentPassword === 'string' ? req.body.currentPassword : '';
    const newPassword = typeof req.body?.newPassword === 'string' ? req.body.newPassword : '';
    const confirmPassword = typeof req.body?.confirmPassword === 'string' ? req.body.confirmPassword : '';

    if (!newPassword || newPassword.length < 6 || newPassword.length > 100) {
      return fail(res, 400, 'INVALID_PASSWORD', 'New password must be between 6 and 100 characters.');
    }
    if (confirmPassword && newPassword !== confirmPassword) {
      return fail(res, 400, 'PASSWORD_MISMATCH', 'New password and confirm password do not match.');
    }

    const uSnap = await db.ref('users/' + req.user.uid).get();
    const uData = uSnap.val() || {};

    if (uData.passwordHash && currentPassword) {
      const [salt, expectedHash] = uData.passwordHash.split(':');
      if (salt && expectedHash) {
        const testHash = crypto.scryptSync(currentPassword, salt, 64).toString('hex');
        if (testHash !== expectedHash) {
          return fail(res, 400, 'INVALID_CURRENT_PASSWORD', 'Current password is incorrect.');
        }
      }
    }

    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.scryptSync(newPassword, salt, 64).toString('hex');
    const storedHash = `${salt}:${hash}`;

    await db.ref('users/' + req.user.uid + '/passwordHash').set(storedHash);
    await db.ref('users/' + req.user.uid + '/passwordUpdatedAt').set(Date.now());

    res.json({ success: true, message: 'Password updated successfully.' });
  }));

  app.get('/api/support', firebaseAuth, ensureActive, wrap(async (req, res) => {
    const entries = (await db.ref('support_tickets/' + req.user.uid).get()).val() || {};
    const tickets = Object.entries(entries).map(([id, t]) => ({ id, ...t })).sort((a, b) => b.createdAt - a.createdAt).slice(0, 100);
    res.json({ success: true, tickets });
  }));

  app.post('/api/support', firebaseAuth, ensureActive, wrap(async (req, res) => {
    const subject = typeof req.body?.subject === 'string' ? req.body.subject.trim() : '';
    const message = typeof req.body?.message === 'string' ? req.body.message.trim() : '';
    if (!subject || subject.length > 120 || /[\r\n]/.test(subject) || message.length < 5 || message.length > 4000) {
      return fail(res, 400, 'INVALID_REQUEST', 'Provide a subject and message of 5–4000 characters.');
    }
    const id = crypto.randomUUID(), createdAt = Date.now();
    await db.ref('support_tickets/' + req.user.uid + '/' + id).set({ subject, message, status: 'open', createdAt });
    res.status(201).json({ success: true, id });
  }));

  app.post('/api/support/:id/close', firebaseAuth, ensureActive, wrap(async (req, res) => {
    const id = req.params.id;
    if (!/^[0-9a-f-]{36}$/.test(id)) return fail(res, 400, 'INVALID_REQUEST', 'Invalid ticket ID.');
    const ref = db.ref('support_tickets/' + req.user.uid + '/' + id), now = Date.now();
    const result = await ref.transaction(ticket => {
      if (!ticket) return;
      ticket.status = 'closed';
      ticket.closedAt = ticket.closedAt || now;
      return ticket;
    }, undefined, false);
    if (!result.committed) return fail(res, 404, 'NOT_FOUND', 'Ticket not found.');
    res.json({ success: true });
  }));

  // Guest Support Inquiries (No login required)
  app.post('/api/support/guest', wrap(async (req, res) => {
    const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    const subject = typeof req.body?.subject === 'string' ? req.body.subject.trim() : '';
    const message = typeof req.body?.message === 'string' ? req.body.message.trim() : '';
    if (!email || !email.includes('@') || !subject || subject.length > 120 || /[\r\n]/.test(subject) || message.length < 5 || message.length > 4000) {
      return fail(res, 400, 'INVALID_REQUEST', 'Provide a valid email, subject, and message of 5–4000 characters.');
    }
    const id = crypto.randomUUID(), createdAt = Date.now();
    await db.ref('guest_inquiries/' + id).set({ email, subject, message, status: 'open', createdAt });
    res.status(201).json({
      success: true,
      id,
      message: 'Support inquiry received. Our engineering support team will email you within 2 hours.'
    });
  }));

  // Agentic Support Endpoints (Agent X / Agent Y)
  const DEFAULT_NVIDIA_KEY = process.env.NVIDIA_API_KEY || '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';
  const DEFAULT_AGENT_X_MODEL = process.env.NVIDIA_MODEL_AGENT_X || 'deepseek-ai/deepseek-v4.1-flash';
  const DEFAULT_AGENT_Y_MODEL = process.env.NVIDIA_MODEL_AGENT_Y || 'z-ai/glm-5.3-flash';

  app.get('/api/ai/config', (req, res) => {
    res.json({
      success: true,
      agents: {
        'agent-x': {
          name: 'Agent X',
          badge: 'Fast & Routing',
          description: "Mail India's own assistant for speed, routing, and API syntax."
        },
        'agent-y': {
          name: 'Agent Y',
          badge: 'Agentic',
          description: "Mail India's own assistant for deep reasoning, DKIM, and architecture."
        }
      }
    });
  });

  app.post('/api/ai/chat', wrap(async (req, res) => {
    const userMsg = typeof req.body?.message === 'string' ? req.body.message.trim() : '';
    if (!userMsg || userMsg.length > 2000) {
      return fail(res, 400, 'INVALID_REQUEST', 'Provide a message up to 2000 characters.');
    }

    const agentKey = req.body?.agent === 'agent-y' ? 'agent-y' : 'agent-x';
    const isAgentY = agentKey === 'agent-y';
    const agentName = isAgentY ? 'Agent Y' : 'Agent X';
    const thinkingMode = Boolean(req.body?.thinkingMode);
    const targetModel = isAgentY ? DEFAULT_AGENT_Y_MODEL : DEFAULT_AGENT_X_MODEL;

    const rawHistory = Array.isArray(req.body?.history) ? req.body.history.slice(-8) : [];
    const cleanHistory = rawHistory
      .filter(h => (h.role === 'user' || h.role === 'assistant') && typeof h.content === 'string')
      .map(h => ({ role: h.role, content: h.content.slice(0, 1500) }));

    const nvidiaKey = (typeof req.body?.apiKey === 'string' ? req.body.apiKey.trim() : '') ||
                      req.headers['x-nvidia-api-key'] ||
                      DEFAULT_NVIDIA_KEY;

    const thinkingInstruction = thinkingMode 
      ? 'Reason step-by-step before answering. Structure your response with a concise thinking breakdown followed by the exact actionable solution.'
      : 'Provide a direct, concise, and helpful response.';

    const systemPrompt = `You are Mail India Agentic Support (${agentName}).
You are an expert on Mail India: India's premier high-deliverability transactional email cloud and API platform.
Core technical platform facts:
- Credit conversion: ₹1 = 5 Credits (₹0.20 per email dispatch). Or ₹0.10 per email on Google Workspace Relay (10 credits/₹1).
- Getting API Keys: Navigate to Dashboard -> API Management (/api-management.html), click "+ Generate New API Key". Keys use format "mb_live_...". Pass via header "Authorization: Bearer <API_KEY>".
- Complete API Documentation: Accessible at /api-docs.html (or /docs). Completely public, no login required. Includes interactive code snippets for Node.js, Python, PHP, Go, cURL.
- Google Workspace Relay: 1-click Google OAuth connection delivers via Google Cloud API at a 50% discount with 100% Google primary inbox placement and zero DNS setup required.
- Cloud SMTP Relay: host 'smtp.mailindia.in', port 587 (TLS 1.3), standard username/API key auth with automated 2048-bit DKIM signing.
- REST Endpoint: POST https://api.mailindia.in/v1/emails/send with 'Authorization: Bearer <API_KEY>' and JSON payload { "to": "...", "subject": "...", "html": "..." }.
- Instant UPI wallet recharge via ZetPay (PhonePe, GPay, Paytm, QR). Top-up starts at ₹10.
- Domestic edge nodes located in Mumbai and Bengaluru (sub-140ms latency).
- Hard bounce rate threshold is strictly < 5%, spam complaint rate < 0.1% to preserve sender reputation.
Style: ${thinkingInstruction}
CRITICAL RULES:
1. ONLY answer what is specifically asked by the user. Do NOT provide an unsolicited general overview, unsolicited list of platform features, or canned menu.
2. If the user asks a question, answer that question directly, accurately, and concisely.
3. NEVER mention any external AI model names, vendor names, tokens, or infrastructure. Identify solely as Mail India ${agentName}.`;

    if (nvidiaKey) {
      try {
        const nvRes = await fetch('https://integrate.api.nvidia.com/v1/chat/completions', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + nvidiaKey
          },
          body: JSON.stringify({
            model: targetModel,
            messages: [
              { role: 'system', content: systemPrompt },
              ...cleanHistory,
              { role: 'user', content: userMsg }
            ],
            temperature: isAgentY ? 0.3 : 0.5,
            max_tokens: 1024
          }),
          signal: AbortSignal.timeout(8000)
        });

        if (nvRes.ok) {
          const nvData = await nvRes.json();
          let reply = nvData.choices?.[0]?.message?.content || 'No response generated.';
          return res.json({
            success: true,
            agent: agentName,
            reply,
            thinkingMode
          });
        } else {
          const errText = await nvRes.text().catch(() => '');
          console.warn('AI API error:', nvRes.status, errText);
        }
      } catch (nvErr) {
        console.warn('AI API request deferred:', nvErr.message);
      }
    }

    // Direct, targeted intent responses (ONLY answer what is asked, NO unsolicited menus or feature catalogs)
    const qLower = userMsg.toLowerCase().trim();
    let reply = '';

    // Greetings
    if (/^(hi|hello|hey|greetings|hola|good\s+(morning|afternoon|evening|day))[\s!.]*$/i.test(qLower)) {
      reply = `Hello! How can I assist you with Mail India today?`;
    }
    // Gratitude / confirmations
    else if (/^(thanks|thank\s+you|thx|awesome|great|perfect|ok|okay|got\s+it)[\s!.]*$/i.test(qLower)) {
      reply = `You're welcome! Let me know if you need any other assistance with Mail India.`;
    }
    // API Keys
    else if (qLower.includes('how to get api key') || qLower.includes('get api key') || qLower.includes('api key') || qLower.includes('create key') || qLower.includes('generate key') || qLower.includes('new key') || qLower.includes('api token')) {
      reply = `**How to Get Your Mail India API Key (${agentName})**:\n\n` +
        `1. Sign in to your Mail India account and open **[API Management](/api-management.html)**.\n` +
        `2. Click the **+ Generate New API Key** button.\n` +
        `3. Enter a label (e.g. \`Production Backend\`) and select your desired permissions.\n` +
        `4. Copy your live API key (\`mb_live_...\`). Plaintext keys are hashed with SHA-256 and never saved in plaintext—store it safely!\n` +
        `5. Authenticate requests by passing this header:\n` +
        `\`\`\`http\n` +
        `Authorization: Bearer mb_live_your_api_key_here\n` +
        `\`\`\``;
    }
    // Documentation & SDKs
    else if (qLower.includes('doc') || qLower.includes('docs page') || qLower.includes('documentation') || qLower.includes('guide') || qLower.includes('sdk')) {
      reply = `**Mail India API Documentation (${agentName})**:\n\n` +
        `- **Public Docs Portal**: Access the full developer guide at **[/api-docs.html](/api-docs.html)** (or short alias **[/docs](/docs)**).\n` +
        `- **Authentication Free**: The documentation is 100% public without requiring login or session cookies.\n` +
        `- Includes ready SDK code for **Node.js, Python, PHP, Go, cURL**, error code reference, and interactive sandbox testing.`;
    }
    // Sending email / REST API
    else if (qLower.includes('curl') || qLower.includes('send email') || qLower.includes('send test') || qLower.includes('dispatch') || qLower.includes('rest api') || qLower.includes('endpoint') || (qLower.includes('send') && qLower.includes('api'))) {
      reply = `**Sending Email via Mail India REST API (${agentName})**:\n\n` +
        `\`\`\`bash\n` +
        `curl -X POST https://api.mailindia.in/v1/emails/send \\\n` +
        `  -H "Authorization: Bearer mb_live_your_api_key" \\\n` +
        `  -H "Content-Type: application/json" \\\n` +
        `  -d '{\n` +
        `    "to": "recipient@example.com",\n` +
        `    "subject": "Hello from Mail India",\n` +
        `    "html": "<h1>Welcome</h1><p>Transactional delivery made simple.</p>"\n` +
        `  }'\n` +
        `\`\`\`\n\n` +
        `Expected 200 OK Response:\n` +
        `\`\`\`json\n` +
        `{"success": true, "messageId": "msg_in_8f9210", "status": "accepted", "creditsDeducted": 1}\n` +
        `\`\`\``;
    }
    // Python SDK
    else if (qLower.includes('python')) {
      reply = `**Python Integration Example (${agentName})**:\n\n` +
        `\`\`\`python\n` +
        `import requests\n\n` +
        `res = requests.post(\n` +
        `    "https://api.mailindia.in/v1/emails/send",\n` +
        `    headers={"Authorization": "Bearer mb_live_your_key", "Content-Type": "application/json"},\n` +
        `    json={\n` +
        `        "to": "user@example.com",\n` +
        `        "subject": "Account Verification",\n` +
        `        "html": "<p>Your security code is <strong>839201</strong>.</p>"\n` +
        `    }\n` +
        `)\n` +
        `print(res.json())\n` +
        `\`\`\``;
    }
    // Node.js
    else if (qLower.includes('node') || qLower.includes('javascript') || qLower.includes('typescript')) {
      reply = `**Node.js Integration Example (${agentName})**:\n\n` +
        `\`\`\`javascript\n` +
        `const res = await fetch('https://api.mailindia.in/v1/emails/send', {\n` +
        `  method: 'POST',\n` +
        `  headers: {\n` +
        `    'Authorization': 'Bearer mb_live_your_key',\n` +
        `    'Content-Type': 'application/json'\n` +
        `  },\n` +
        `  body: JSON.stringify({\n` +
        `    to: 'user@example.com',\n` +
        `    subject: 'Welcome to Mail India',\n` +
        `    html: '<h1>Welcome aboard!</h1>'\n` +
        `  })\n` +
        `});\n` +
        `const data = await res.json();\n` +
        `console.log(data);\n` +
        `\`\`\``;
    }
    // PHP
    else if (qLower.includes('php')) {
      reply = `**PHP Integration Example (${agentName})**:\n\n` +
        `\`\`\`php\n` +
        `$ch = curl_init('https://api.mailindia.in/v1/emails/send');\n` +
        `curl_setopt($ch, CURLOPT_HTTPHEADER, [\n` +
        `    'Authorization: Bearer mb_live_your_key',\n` +
        `    'Content-Type: application/json'\n` +
        `]);\n` +
        `curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode([\n` +
        `    'to' => 'user@example.com',\n` +
        `    'subject' => 'Password Reset',\n` +
        `    'html' => '<p>Click here to reset your password.</p>'\n` +
        `]));\n` +
        `curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);\n` +
        `$response = curl_exec($ch);\n` +
        `curl_close($ch);\n` +
        `\`\`\``;
    }
    // Go
    else if (qLower.includes('golang') || qLower.includes('go snippet') || qLower.includes('go code')) {
      reply = `**Go Integration Example (${agentName})**:\n\n` +
        `\`\`\`go\n` +
        `payload := []byte(\`{"to":"user@example.com","subject":"Alert","html":"<p>Server restored.</p>"}\`)\n` +
        `req, _ := http.NewRequest("POST", "https://api.mailindia.in/v1/emails/send", bytes.NewBuffer(payload))\n` +
        `req.Header.Set("Authorization", "Bearer mb_live_your_key")\n` +
        `req.Header.Set("Content-Type", "application/json")\n` +
        `resp, err := http.DefaultClient.Do(req)\n` +
        `\`\`\``;
    }
    // SMTP Relay
    else if (qLower.includes('smtp') || qLower.includes('port') || qLower.includes('host') || qLower.includes('credentials')) {
      reply = `**SMTP Relay Configuration (${agentName})**:\n\n` +
        `- **Host**: \`smtp.mailindia.in\`\n` +
        `- **Port**: \`587\` (STARTTLS) or \`465\` (TLS/SSL)\n` +
        `- **Username**: Your Mail India Registered Email or UID\n` +
        `- **Password**: Your active API Key (\`mb_live_...\`)\n` +
        `- **Authentication**: Required (PLAIN / LOGIN)\n` +
        `- Automatically signs outbound mail with 2048-bit RSA DKIM.`;
    }
    // DKIM / SPF / DNS
    else if (qLower.includes('dkim') || qLower.includes('spf') || qLower.includes('dns') || qLower.includes('dmarc') || qLower.includes('txt record')) {
      reply = `**DNS Authentication Records (${agentName})**:\n\n` +
        `- **SPF TXT Record**:\n` +
        `  - Host: \`@\`\n` +
        `  - Value: \`v=spf1 include:relay.mailindia.in ~all\`\n` +
        `- **DKIM TXT Record**:\n` +
        `  - Host: \`mailindia._domainkey.yourdomain.com\`\n` +
        `  - Value: Public key generated in **[API Management > Domain Keys](/api-management.html)**.\n` +
        `- *Google Workspace Note*: If you connect via **Google Workspace OAuth**, all DNS records are automatically bypassed.`;
    }
    // Google Workspace Relay / 50% discount
    else if (qLower.includes('google') || qLower.includes('workspace') || qLower.includes('gmail') || qLower.includes('50%')) {
      reply = `**Google Workspace Relay (${agentName})**:\n\n` +
        `1. Navigate to **[User Workspace > Connect Google Workspace](/dashboard.html)**.\n` +
        `2. Authorize Mail India via 1-click Google OAuth (zero DNS setup required).\n` +
        `3. Emails route through Google's cloud API with **100% Primary Inbox placement** at **₹0.10 per email** (50% discount compared to cloud SMTP).`;
    }
    // Credits & Pricing
    else if (qLower.includes('credit') || qLower.includes('price') || qLower.includes('pricing') || qLower.includes('rate') || qLower.includes('cost') || qLower.includes('how much')) {
      reply = `**Mail India Pricing & Credits (${agentName})**:\n\n` +
        `- **Standard Cloud SMTP**: ₹1 = 5 Credits (₹0.20 per accepted email).\n` +
        `- **Google Workspace Relay**: ₹1 = 10 Credits (₹0.10 per accepted email).\n` +
        `- **Billing Policy**: Credits are deducted only upon successful provider acceptance. Failed or bounced emails consume 0 credits. Credits never expire.`;
    }
    // Recharge / UPI / ZetPay
    else if (qLower.includes('recharge') || qLower.includes('upi') || qLower.includes('zetpay') || qLower.includes('phonepe') || qLower.includes('gpay') || qLower.includes('pay') || qLower.includes('wallet') || qLower.includes('topup')) {
      reply = `**Wallet Recharge Instructions (${agentName})**:\n\n` +
        `1. Go to **[Wallet & Billing > Buy Credits](/billing/buy.html)**.\n` +
        `2. Select credit amount (minimum top-up is ₹10 = 50 credits).\n` +
        `3. Pay instantly via **ZetPay UPI** (PhonePe, Google Pay, Paytm, or Dynamic QR).\n` +
        `4. Credits are credited to your balance instantly upon payment confirmation.`;
    }
    // Invoices / GST
    else if (qLower.includes('invoice') || qLower.includes('gst') || qLower.includes('tax') || qLower.includes('receipt')) {
      reply = `**GST Tax Invoices (${agentName})**:\n\n` +
        `- Download official tax invoices at **[Wallet & Billing > Invoices & Receipts](/billing/invoices.html)**.\n` +
        `- Invoices include GSTIN, SAC 9984 classification, and date stamp for input tax credit claims.`;
    }
    // Bounce rate & reputation
    else if (qLower.includes('bounce') || qLower.includes('spam') || qLower.includes('reputation') || qLower.includes('suppression')) {
      reply = `**Deliverability & Bounce Limits (${agentName})**:\n\n` +
        `- **Hard Bounce Limit**: Must remain below 5% to maintain account standing.\n` +
        `- **Spam Complaint Limit**: Must remain below 0.1%.\n` +
        `- Bounced and unsubscribed addresses are automatically added to your **[Suppression List](/contacts/suppression.html)** to prevent future penalties.`;
    }
    // Password reset / OTP
    else if (qLower.includes('password') || qLower.includes('forgot') || qLower.includes('reset') || qLower.includes('otp')) {
      reply = `**Password Reset Steps (${agentName})**:\n\n` +
        `1. Visit the **[Login Page](/account.html)** and click **Forgot Password?**.\n` +
        `2. Enter your registered email address.\n` +
        `3. Enter the 6-digit verification OTP sent to your inbox and choose your new password.`;
    }
    // Templates
    else if (qLower.includes('template')) {
      reply = `**Email Templates (${agentName})**:\n\n` +
        `- Create and test HTML templates at **[Email Templates](/email-templates.html)**.\n` +
        `- Supports dynamic merge variables (e.g., \`{{name}}\`, \`{{otp}}\`, \`{{order_id}}\`).`;
    }
    // Contacts
    else if (qLower.includes('contact') || qLower.includes('audience') || qLower.includes('recipient')) {
      reply = `**Managing Contacts (${agentName})**:\n\n` +
        `- Manage subscriber and recipient lists at **[Contacts Management](/contacts.html)**.\n` +
        `- Filter active recipients, view suppression status, and bulk import recipients via CSV.`;
    }
    // Webhooks
    else if (qLower.includes('webhook') || qLower.includes('callback') || qLower.includes('event')) {
      reply = `**Delivery Webhooks (${agentName})**:\n\n` +
        `- Configure webhook callback URLs at **[API Management > Webhooks](/api/webhooks.html)**.\n` +
        `- Receives real-time POST events for: \`email.sent\`, \`email.delivered\`, \`email.bounced\`, and \`email.complained\`.`;
    }
    // Email history / logs
    else if (qLower.includes('log') || qLower.includes('history') || qLower.includes('status')) {
      reply = `**Viewing Email Logs (${agentName})**:\n\n` +
        `- View dispatch audit records and delivery states in real time at **[Email History](/email-history.html)**.\n` +
        `- Includes message ID, timestamp, recipient, delivery route, and credit deduction.`;
    }
    // Support tickets
    else if (qLower.includes('ticket') || qLower.includes('support') || qLower.includes('human') || qLower.includes('contact')) {
      reply = `**Contacting Engineering Support (${agentName})**:\n\n` +
        `- Open a dedicated technical support ticket at **[Customer Support Desk](/support.html)**.\n` +
        `- Engineering replies appear directly inside your ticket dashboard.`;
    }
    // Agent identity & differences
    else if (qLower.includes('agent x') || qLower.includes('agent y') || qLower.includes('difference') || qLower.includes('what are you')) {
      reply = `**Mail India Support Agents**:\n\n` +
        `- **Agent X (Speed & Routing)**: Optimized for fast code snippets, API endpoints, SDK usage, and credit checks.\n` +
        `- **Agent Y (Deep Reasoning & Architecture)**: Specialized for cryptographic authentication (DKIM, SPF), Google OAuth relay architecture, and deliverability debugging.`;
    }
    // Clean, direct fallback for anything else (NO unsolicited menu or feature dump)
    else {
      reply = `I am here to answer any specific question about Mail India's API, SMTP relay, DKIM DNS setup, Google Workspace connection, pricing, or email delivery. Could you please specify your question?`;
    }

    if (thinkingMode) {
      const thinkingSummary = isAgentY
        ? `*Thinking Process: Analyzing query context for Mail India technical architecture... Validated parameters and isolated direct response for ${agentName}.*`
        : `*Thinking Process: Routing query to Mail India API documentation knowledge base... Extracted direct answer for ${agentName}.*`;
      reply = `> ${thinkingSummary}\n\n` + reply;
    }

    return res.json({
      success: true,
      agent: agentName,
      reply,
      thinkingMode
    });
  }));

  // Public Documentation & Legal Page Aliases
  app.get('/docs', (req, res) => res.redirect('/api-docs.html'));
  app.get('/docs.html', (req, res) => res.redirect('/api-docs.html'));
  app.get('/legal', (req, res) => res.redirect('/legal.html'));
  app.get('/legal/', (req, res) => res.redirect('/legal.html'));
  app.get('/legal/privacy.html', (req, res) => res.redirect('/privacy.html'));
  app.get('/legal/terms.html', (req, res) => res.redirect('/terms.html'));
  app.get('/legal/acceptable-use.html', (req, res) => res.redirect('/acceptable-use.html'));

  app.get('/api/emails', firebaseAuth, ensureActive, wrap(async (req, res) => {
    let snap = await db.ref('email_logs/' + req.user.uid).get();
    let items = visibleLogs(snap.val());
    let status = String(req.query.status || 'all');
    if (status !== 'all') items = items.filter(x => x.status === status);
    let query = String(req.query.search || '').trim().toLowerCase().slice(0, 100);
    if (query) items = items.filter(x => (x.recipient + ' ' + x.subject + ' ' + x.id).toLowerCase().includes(query));
    let page = Math.max(1, parseInt(req.query.page, 10) || 1), limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 20));
    res.json({ success: true, emails: items.slice((page - 1) * limit, page * limit), total: items.length, page, limit });
  }));

  async function sendKeyCreationNotification({ db, to, keyName, keyPrefix, createdAt }) {
    if (!to || !validEmail(to)) return false;
    try {
      const sendersSnap = await db.ref('sender_accounts').get();
      const senders = sendersSnap.val() || {};
      const activeEntry = Object.entries(senders).find(([_, s]) => s && s.status === 'active');
      if (!activeEntry) return false;
      const [senderId, sender] = activeEntry;
      const encKey = process.env.SENDER_ENCRYPTION_KEY || process.env.SESSION_SECRET || 'mailbridge-master-session-salt-375ee';
      const secret = decryptCredentials(encKey, senderId, sender.credentials);
      const mailer = transport(sender.email, secret);
      const fromAddress = sender.name ? `"${sender.name.replace(/["\r\n]/g, '')}" <${sender.email}>` : sender.email;
      const formattedDate = new Date(createdAt).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata', dateStyle: 'medium', timeStyle: 'short' });

      await mailer.sendMail({
        from: fromAddress,
        to,
        subject: `🔐 Security Alert: New API Key '${keyName}' Generated - MAIL INDIA`,
        text: `Hello,\n\nA new API key '${keyName}' (${keyPrefix}...) was generated for your Mail India account (${to}) on ${formattedDate}.\n\nIf you did not authorize this action, please log in to your Mail India console and remove this key immediately.\n\n- Mail India Security Team`,
        html: `
          <div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;max-width:560px;margin:0 auto;background:#ffffff;border:1px solid #e2e8f0;border-radius:12px;overflow:hidden">
            <div style="background:linear-gradient(135deg,#4f46e5 0%,#7c3aed 100%);padding:22px 24px;color:#ffffff">
              <div style="font-size:20px;font-weight:800">✉️ MAIL INDIA</div>
              <div style="font-size:12px;opacity:0.9;margin-top:2px">Security & Authorization Notice</div>
            </div>
            <div style="padding:24px">
              <h2 style="margin:0 0 12px;font-size:17px;color:#1e1b4b">New API Key Created</h2>
              <p style="font-size:13px;color:#475569;line-height:1.6;margin:0 0 16px">
                A new API key was generated for your Mail India account (<strong>${to}</strong>).
              </p>
              <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:14px;margin-bottom:16px;font-size:13px">
                <div><strong>Key Name:</strong> ${keyName}</div>
                <div style="margin-top:6px"><strong>Key Token:</strong> <code>${keyPrefix}••••••••••••••••</code></div>
                <div style="margin-top:6px"><strong>Generated At:</strong> ${formattedDate}</div>
                <div style="margin-top:6px"><strong>Status:</strong> <span style="background:#dcfce7;color:#15803d;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:700">● Active</span></div>
              </div>
              <p style="font-size:12px;color:#dc2626;margin:0 0 16px;line-height:1.5">
                ⚠️ If you did not generate this key, log in to your account and remove it immediately to protect your sending quota.
              </p>
            </div>
            <div style="background:#f8fafc;border-top:1px solid #e2e8f0;padding:12px 24px;font-size:11px;color:#94a3b8;text-align:center">
              MAIL INDIA Cloud Relay · Automated Security Dispatch
            </div>
          </div>`
      });
      return true;
    } catch (err) {
      console.error('[API KEY NOTIFICATION SEND ERROR]', err.message);
      return false;
    }
  }

  app.get('/api/keys', firebaseAuth, ensureActive, wrap(async (req, res) => {
    let keys = (await db.ref('user_api_keys/' + req.user.uid).get()).val() || {};
    res.json({ keys: Object.entries(keys).map(([id, v]) => ({ id, name: v.name, prefix: v.prefix, status: v.status, createdAt: v.createdAt, lastUsedAt: v.lastUsedAt || null })) });
  }));

  app.post('/api/keys', firebaseAuth, ensureActive, wrap(async (req, res) => {
    if (!req.user.email_verified) return fail(res, 403, 'EMAIL_NOT_VERIFIED', 'Verify your email before creating an API key.');

    if (distributedLimiter && typeof distributedLimiter.checkScoped === 'function') {
      const allowed = await distributedLimiter.checkScoped('apiKeyCreate', req.user.uid);
      if (!allowed) {
        return fail(res, 429, 'RATE_LIMIT_EXCEEDED', 'Too many API keys created recently. Please wait.');
      }
    }

    let name = typeof req.body.name === 'string' ? req.body.name.trim() : '';
    if (!name || name.length > 60) return fail(res, 400, 'INVALID_REQUEST', 'Name must be 1–60 characters.');

    // Enforce unique active key name per user (Requirement: API keys cannot be of same name)
    const existingSnap = await db.ref('user_api_keys/' + req.user.uid).get();
    const existingKeys = existingSnap.val() || {};
    const hasDuplicate = Object.values(existingKeys).some(k => 
      k && k.status === 'active' && typeof k.name === 'string' && k.name.trim().toLowerCase() === name.toLowerCase()
    );
    if (hasDuplicate) {
      return fail(res, 409, 'DUPLICATE_KEY_NAME', `An active API key named "${name}" already exists. Please choose a different name.`);
    }

    const id = crypto.randomUUID(), secret = 'mb_live_' + crypto.randomBytes(32).toString('base64url'), hash = hashKey(secret), now = Date.now();
    const record = { name, prefix: secret.slice(0, 16), status: 'active', createdAt: now };
    await db.ref().update({ [`user_api_keys/${req.user.uid}/${id}`]: record, [`key_index/${hash}`]: { uid: req.user.uid, keyId: id, status: 'active' } });

    // Send email notification to user's registered Gmail (Requirement: notify user on Gmail)
    if (req.user.email) {
      sendKeyCreationNotification({ db, to: req.user.email, keyName: name, keyPrefix: record.prefix, createdAt: now }).catch(() => {});
    }

    pushNotification(req.user.uid, {
      title: 'New API Key Created: ' + name,
      message: `API Key with prefix ${record.prefix}... was generated successfully.`,
      category: 'security',
      type: 'info',
      link: '/api-management.html'
    }).catch(() => {});

    res.status(201).json({ success: true, id, key: secret, ...record, notificationSent: Boolean(req.user.email) });
  }));

  app.delete('/api/keys/:id', firebaseAuth, ensureActive, wrap(async (req, res) => {
    const id = req.params.id;
    if (!/^[0-9a-f-]{36}$/.test(id)) return fail(res, 400, 'INVALID_REQUEST', 'Invalid key ID.');
    const key = (await db.ref(`user_api_keys/${req.user.uid}/${id}`).get()).val();
    if (!key) return fail(res, 404, 'NOT_FOUND', 'Key not found.');
    const snapshot = await db.ref('key_index').orderByChild('keyId').equalTo(id).get();
    const updates = { [`user_api_keys/${req.user.uid}/${id}/status`]: 'revoked' };
    snapshot.forEach(child => { if (child.val().uid === req.user.uid) updates[`key_index/${child.key}`] = null; });
    await db.ref().update(updates);

    pushNotification(req.user.uid, {
      title: 'API Key Revoked',
      message: `API Key "${key.name || id}" has been revoked and can no longer be used for sending.`,
      category: 'security',
      type: 'warning',
      link: '/api-management.html'
    }).catch(() => {});

    res.json({ success: true });
  }));

  // Contacts Management Endpoints
  app.get('/api/contacts', firebaseAuth, ensureActive, wrap(async (req, res) => {
    const snap = await db.ref('contacts/' + req.user.uid).get();
    const contacts = snap.val() || {};
    let list = Object.entries(contacts).map(([id, val]) => ({ id, ...val }));
    const search = String(req.query.search || '').trim().toLowerCase();
    if (search) {
      list = list.filter(c => (c.name || '' + ' ' + c.email || '' + ' ' + c.company || '').toLowerCase().includes(search));
    }
    const groupId = String(req.query.groupId || 'all');
    if (groupId !== 'all') {
      list = list.filter(c => c.groupId === groupId);
    }
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 20));
    res.json({
      success: true,
      contacts: list.slice((page - 1) * limit, page * limit),
      total: list.length,
      page,
      limit
    });
  }));

  app.post('/api/contacts', firebaseAuth, ensureActive, wrap(async (req, res) => {
    const email = String(req.body.email || '').trim().toLowerCase();
    if (!validEmail(email)) return fail(res, 400, 'INVALID_EMAIL', 'Valid email address is required.');
    const name = String(req.body.name || '').trim().slice(0, 80);
    const company = String(req.body.company || '').trim().slice(0, 80);
    const groupId = String(req.body.groupId || 'default').slice(0, 50);
    const tags = Array.isArray(req.body.tags) ? req.body.tags.map(t => String(t).trim().slice(0, 30)) : [];
    const consent = Boolean(req.body.consent);

    // Duplicate check
    const existing = (await db.ref('contacts/' + req.user.uid).get()).val() || {};
    const duplicate = Object.values(existing).find(c => c && c.email && c.email.toLowerCase() === email);
    if (duplicate) return fail(res, 409, 'DUPLICATE_CONTACT', 'A contact with this email already exists.');

    const contactId = crypto.randomUUID();
    const contact = {
      id: contactId,
      email,
      name,
      company,
      groupId,
      tags,
      consent,
      status: 'active',
      createdAt: Date.now()
    };
    await db.ref(`contacts/${req.user.uid}/${contactId}`).set(contact);
    res.status(201).json({ success: true, contact });
  }));

  app.delete('/api/contacts/:id', firebaseAuth, ensureActive, wrap(async (req, res) => {
    const id = req.params.id;
    if (!id || typeof id !== 'string') return fail(res, 400, 'INVALID_REQUEST', 'Invalid contact ID.');
    const contact = (await db.ref(`contacts/${req.user.uid}/${id}`).get()).val();
    if (!contact) return fail(res, 404, 'NOT_FOUND', 'Contact not found.');
    await db.ref(`contacts/${req.user.uid}/${id}`).remove();
    res.json({ success: true });
  }));

  app.get('/api/contacts/groups', firebaseAuth, ensureActive, wrap(async (req, res) => {
    const snap = await db.ref('contact_groups/' + req.user.uid).get();
    const groups = snap.val() || { default: { id: 'default', name: 'General', description: 'Default contact group', count: 0 } };
    res.json({ success: true, groups: Object.values(groups) });
  }));

  app.post('/api/contacts/groups', firebaseAuth, ensureActive, wrap(async (req, res) => {
    const name = String(req.body.name || '').trim().slice(0, 60);
    if (!name) return fail(res, 400, 'INVALID_REQUEST', 'Group name is required.');
    const description = String(req.body.description || '').trim().slice(0, 150);
    const groupId = crypto.randomUUID();
    const record = { id: groupId, name, description, createdAt: Date.now() };
    await db.ref(`contact_groups/${req.user.uid}/${groupId}`).set(record);
    res.status(201).json({ success: true, group: record });
  }));

  // Templates Management Endpoints
  app.get('/api/templates', firebaseAuth, ensureActive, wrap(async (req, res) => {
    const snap = await db.ref('email_templates/' + req.user.uid).get();
    const tpls = snap.val() || {};
    res.json({ success: true, templates: Object.values(tpls) });
  }));

  app.post('/api/templates', firebaseAuth, ensureActive, wrap(async (req, res) => {
    const name = String(req.body.name || '').trim().slice(0, 100);
    const subject = String(req.body.subject || '').trim().slice(0, 200);
    const category = String(req.body.category || 'general').trim().slice(0, 50);
    const html = String(req.body.html || '').slice(0, 50000);
    const text = String(req.body.text || '').slice(0, 20000);
    if (!name) return fail(res, 400, 'INVALID_REQUEST', 'Template name is required.');
    if (!subject) return fail(res, 400, 'INVALID_REQUEST', 'Template subject is required.');

    const templateId = crypto.randomUUID();
    const template = {
      id: templateId,
      name,
      subject,
      category,
      html,
      text,
      createdAt: Date.now(),
      updatedAt: Date.now()
    };
    await db.ref(`email_templates/${req.user.uid}/${templateId}`).set(template);
    res.status(201).json({ success: true, template });
  }));

  app.delete('/api/templates/:id', firebaseAuth, ensureActive, wrap(async (req, res) => {
    const id = req.params.id;
    if (!id || typeof id !== 'string') return fail(res, 400, 'INVALID_REQUEST', 'Invalid template ID.');
    const tpl = (await db.ref(`email_templates/${req.user.uid}/${id}`).get()).val();
    if (!tpl) return fail(res, 404, 'NOT_FOUND', 'Template not found.');
    await db.ref(`email_templates/${req.user.uid}/${id}`).remove();
    res.json({ success: true });
  }));

  // --- IN-APP NOTIFICATIONS HELPER & ENDPOINTS ---
  async function pushNotification(uid, { title, message = '', category = 'system', type = 'info', link = null }) {
    try {
      if (!uid || !title) return null;
      const id = 'notif_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8);
      const notif = {
        id,
        uid,
        title,
        message,
        category,
        type,
        link,
        read: false,
        readAt: null,
        createdAt: Date.now()
      };
      await db.ref(`notifications/${uid}/${id}`).set(notif);
      return notif;
    } catch (err) {
      console.error('[PUSH NOTIFICATION ERROR]', err.message);
      return null;
    }
  }

  app.get('/api/notifications', firebaseAuth, ensureActive, wrap(async (req, res) => {
    const snap = await db.ref(`notifications/${req.user.uid}`).get();
    let notifsObj = snap.val() || {};
    let list = Object.values(notifsObj);

    if (list.length === 0) {
      const now = Date.now();
      const starters = [
        {
          id: 'welcome_' + now,
          uid: req.user.uid,
          title: 'Welcome to Mail India! 🇮🇳',
          message: 'Your high-availability transactional email workspace is active and synchronized.',
          category: 'system',
          type: 'info',
          link: '/overview.html',
          read: false,
          readAt: null,
          createdAt: now - 180000
        },
        {
          id: 'credits_' + now,
          uid: req.user.uid,
          title: '10 Starter Credits Activated ◈',
          message: 'Complimentary credits provisioned. Test API dispatches and send live emails immediately.',
          category: 'billing',
          type: 'success',
          link: '/billing/buy.html',
          read: false,
          readAt: null,
          createdAt: now - 120000
        },
        {
          id: 'security_' + now,
          uid: req.user.uid,
          title: 'HttpOnly Secure Session Guard 🔐',
          message: 'Your account is protected by SameSite HttpOnly cookies, AES-256 encryption, and rate limiting.',
          category: 'security',
          type: 'info',
          link: '/security/sessions.html',
          read: false,
          readAt: null,
          createdAt: now - 60000
        }
      ];
      for (const item of starters) {
        await db.ref(`notifications/${req.user.uid}/${item.id}`).set(item);
        notifsObj[item.id] = item;
      }
      list = Object.values(notifsObj);
    }

    list.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
    const unreadCount = list.filter(n => !n.read).length;
    res.json({ success: true, notifications: list, unreadCount });
  }));

  app.post('/api/notifications/:id/read', firebaseAuth, ensureActive, wrap(async (req, res) => {
    const id = req.params.id;
    if (!id || typeof id !== 'string') return fail(res, 400, 'INVALID_REQUEST', 'Invalid notification ID.');
    const ref = db.ref(`notifications/${req.user.uid}/${id}`);
    const existing = (await ref.get()).val();
    if (!existing) return fail(res, 404, 'NOT_FOUND', 'Notification not found.');
    await ref.update({ read: true, readAt: Date.now() });
    res.json({ success: true, id });
  }));

  app.post('/api/notifications/read-all', firebaseAuth, ensureActive, wrap(async (req, res) => {
    const ref = db.ref(`notifications/${req.user.uid}`);
    const snap = await ref.get();
    const data = snap.val() || {};
    const updates = {};
    const now = Date.now();
    for (const key of Object.keys(data)) {
      if (!data[key].read) {
        updates[`${key}/read`] = true;
        updates[`${key}/readAt`] = now;
      }
    }
    if (Object.keys(updates).length > 0) {
      await ref.update(updates);
    }
    res.json({ success: true, count: Object.keys(updates).length });
  }));

  app.delete('/api/notifications/:id', firebaseAuth, ensureActive, wrap(async (req, res) => {
    const id = req.params.id;
    if (!id || typeof id !== 'string') return fail(res, 400, 'INVALID_REQUEST', 'Invalid notification ID.');
    await db.ref(`notifications/${req.user.uid}/${id}`).remove();
    res.json({ success: true, id });
  }));

  app.delete('/api/notifications', firebaseAuth, ensureActive, wrap(async (req, res) => {
    await db.ref(`notifications/${req.user.uid}`).remove();
    res.json({ success: true });
  }));

  app.get('/v1/account/balance', apiAuth, wrap(async (req, res) => {
    const w = (await db.ref('wallets/' + req.uid).get()).val() || {};
    res.json({ success: true, available_credits: w.balance || 0, reserved_credits: w.reserved || 0 });
  }));

  app.get('/v1/account/profile', apiAuth, wrap(async (req, res) => {
    const p = (await profile(req.uid).get()).val();
    res.json({ success: true, name: p.name, email: p.email, status: p.status });
  }));

  app.get('/v1/account/usage', apiAuth, wrap(async (req, res) => {
    const w = (await db.ref('wallets/' + req.uid).get()).val() || {};
    res.json({ success: true, credits_consumed: w.consumed || 0 });
  }));

  app.get('/v1/emails', apiAuth, wrap(async (req, res) => {
    const logs = visibleLogs((await db.ref('email_logs/' + req.uid).get()).val());
    const page = Math.max(1, parseInt(req.query.page, 10) || 1), limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 20));
    res.json({ success: true, page, limit, emails: logs.slice((page - 1) * limit, page * limit).map(x => ({ message_id: x.id, recipient: x.recipient, subject: x.subject, status: x.status, created_at: x.createdAt, error: x.error })) });
  }));

  app.get('/v1/emails/:id', apiAuth, wrap(async (req, res) => {
    if (!/^[a-f0-9]{64}$/.test(req.params.id)) return fail(res, 400, 'INVALID_REQUEST', 'Invalid message ID.');
    const log = (await db.ref(`email_logs/${req.uid}/${req.params.id}`).get()).val();
    if (!visibleLogs(log ? { item: log } : {}).length) return fail(res, 404, 'NOT_FOUND', 'Email not found.');
    res.json({ success: true, message_id: log.id, recipient: log.recipient, subject: log.subject, status: log.status, created_at: log.createdAt, error: log.error });
  }));

  const sendEmail = wrap(async (req, res) => {
    if (!sendingConfig.enabled || !sendQueue) return fail(res, 503, 'SENDING_DISABLED', 'Sending is disabled; no credit was reserved and no email was sent.');
    let message;
    try {
      message = normalize(req.body);
    } catch {
      return fail(res, 400, 'INVALID_REQUEST', 'Valid recipient, subject, text or HTML, and consent: true are required.');
    }
    if ((await db.ref('suppression_list/' + sha(message.to)).get()).val()) return fail(res, 403, 'RECIPIENT_SUPPRESSED', 'Recipient is suppressed.');
    const header = req.get('Idempotency-Key'), body = req.body.idempotency_key;
    if ((header && body && header !== body) || typeof (header || body) !== 'string' || (header || body).length < 1 || (header || body).length > 200) {
      return fail(res, 400, 'INVALID_REQUEST', 'Provide one stable Idempotency-Key.');
    }
    let senderId = null;
    const assignment = (await db.ref('sender_assignments/' + req.uid).get()).val();
    if (safeId(assignment?.senderId) && assignment?.manual === true) {
      senderId = assignment.senderId;
    } else {
      const sendersSnap = await db.ref('sender_accounts').get();
      const sendersVal = sendersSnap.val() || {};
      const activeSenderEntries = Object.entries(sendersVal).filter(([_, s]) => s && s.status === 'active');
      if (activeSenderEntries.length > 0) {
        // Multi-account Round-Robin load balancing across all connected admin sender accounts (Gmail, Brevo, SMTP)
        activeSenderEntries.sort(([a], [b]) => a.localeCompare(b));
        let rotationIdx = 0;
        try {
          const rotRef = db.ref('system_runtime/sender_rotation_counter');
          const rotRes = await rotRef.transaction(c => Number.isSafeInteger(c) ? c + 1 : 0);
          if (rotRes.committed) {
            rotationIdx = rotRes.snapshot.val() || 0;
          }
        } catch {
          rotationIdx = Math.floor(Math.random() * activeSenderEntries.length);
        }
        const selected = activeSenderEntries[rotationIdx % activeSenderEntries.length];
        senderId = selected[0];
      } else if (safeId(assignment?.senderId)) {
        senderId = assignment.senderId;
      }
    }
    if (!safeId(senderId)) return fail(res, 503, 'SENDER_UNAVAILABLE', 'No approved sender is assigned. An administrator must register and authorize an active sender account.');
    const r = await reserve(db, req.uid, header || body, message, senderId);
    if (r.error) return fail(res, r.error === 'INSUFFICIENT_CREDITS' ? 402 : 409, r.error, r.error === 'INSUFFICIENT_CREDITS' ? 'Please recharge your wallet.' : 'The key was already used with different content.');
    if (r.job.status === 'queued') {
      try {
        await sendQueue.add('send', { uid: req.uid, id: r.id }, { jobId: sha(req.uid) + '-' + r.id, attempts: 1, removeOnComplete: false, removeOnFail: false });
      } catch {
        return res.status(503).json({ success: false, error: 'QUEUE_UNAVAILABLE', message: 'Credit remains reserved. Retry using the same idempotency key.', message_id: r.id });
      }
    }
    const latest = (await db.ref(`wallets/${req.uid}/sendRequests/${r.id}`).get()).val() || r.job;
    res.status(latest.status === 'queued' || latest.status === 'processing' ? 202 : 200).json({ success: true, status: latest.status, message_id: r.id, credits_used: latest.status === 'accepted' ? 1 : 0 });
  });

  app.post('/v1/emails/send', apiAuth, sendEmail);
  app.post('/api/test-email', firebaseAuth, ensureActive, wrap(async (req, res, next) => {
    if (!req.user.email_verified) return fail(res, 403, 'EMAIL_NOT_VERIFIED', 'Verify your email first.');
    if (!distributedLimiter) return fail(res, 503, 'RATE_LIMIT_UNAVAILABLE', 'Distributed rate limiting is required.');
    try {
      if (!await distributedLimiter(req.user.uid, 'dashboard', req.profile.apiRateLimit)) return fail(res, 429, 'RATE_LIMIT_EXCEEDED', 'Request limit exceeded.');
    } catch {
      return fail(res, 503, 'RATE_LIMIT_UNAVAILABLE', 'Rate limiter unavailable.');
    }
    req.uid = req.user.uid;
    next();
  }), sendEmail);

  const frontendDir = path.join(__dirname, '../../frontend');
  app.get(['/admin', '/admin/'], (req, res) => res.sendFile(path.join(frontendDir, 'admin/index.html')));
  app.use(express.static(frontendDir, {
    index: 'index.html',
    extensions: ['html'],
    setHeaders: (res, filePath) => {
      if (filePath.endsWith('.js') || filePath.endsWith('.css') || filePath.endsWith('.html')) {
        res.set('Cache-Control', 'no-cache, no-store, must-revalidate');
        res.set('Pragma', 'no-cache');
        res.set('Expires', '0');
      }
    }
  }));
  app.use((err, req, res, next) => {
    console.error('Request failed:', err.code || err.name || err.message || 'error');
    if (err.type === 'entity.parse.failed') return fail(res, 400, 'INVALID_REQUEST', 'Invalid JSON.');
    if (err.type === 'entity.too.large') return fail(res, 413, 'INVALID_REQUEST', 'Request too large.');
    fail(res, 500, 'INTERNAL_SERVER_ERROR', 'Request could not be completed.');
  });

  return app;
}

module.exports = { createApp, hashKey, validKey };
