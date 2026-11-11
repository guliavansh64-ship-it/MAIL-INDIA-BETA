'use strict';
const express = require('express');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { encryptCredentials } = require('./sending');
const { sendViaConnectedGmail, disconnectUserGmail } = require('./gmail-api');

const getCookies = req => {
  if (req.cookies && Object.keys(req.cookies).length > 0) return req.cookies;
  return Object.fromEntries((req.get('cookie') || '').split(';').map(x => x.trim().split(/=(.*)/s).slice(0, 2)).filter(x => x.length === 2));
};

function createGoogleOAuthRoutes({
  db,
  auth,
  authenticate,
  encryptionKey,
  cookieOptions = { httpOnly: true, secure: true, sameSite: 'lax', path: '/' }
}) {
  const router = express.Router();

  // Load client credentials from downloaded Google Cloud Console JSON file if present
  let fileCredentials = null;
  const credentialCandidates = [
    path.join(__dirname, '../credentials/google-oauth-client.json'),
    path.join(__dirname, '../credentials/client_secret.json')
  ];
  for (const p of credentialCandidates) {
    if (fs.existsSync(p)) {
      try {
        const raw = JSON.parse(fs.readFileSync(p, 'utf8'));
        if (raw.web) {
          fileCredentials = raw.web;
          break;
        }
      } catch {}
    }
  }

  const getClientId = () => process.env.GOOGLE_CLIENT_ID || fileCredentials?.client_id || '';
  const getClientSecret = () => process.env.GOOGLE_CLIENT_SECRET || fileCredentials?.client_secret || '';

  const getBaseUrl = req => {
    const proto = req.get('x-forwarded-proto') || req.protocol || 'http';
    const host = req.get('x-forwarded-host') || req.get('host') || 'localhost:3000';
    return `${proto}://${host}`;
  };

  // Base URL of the browser-facing client app. When the frontend is hosted
  // separately from this backend (e.g. static hosting + serverless API), OAuth
  // callbacks must send the browser back to the frontend, not to the API host.
  // Set FRONTEND_URL (or CLIENT_ORIGIN) to enable cross-origin redirects.
  // Leaving it unset preserves the original same-origin behaviour.
  const getFrontendBaseUrl = () => {
    const configured = (process.env.FRONTEND_URL || process.env.CLIENT_ORIGIN || '').trim();
    return configured ? configured.replace(/\/+$/, '') : '';
  };

  // Build a browser-facing redirect target. `path` always starts with '/'.
  // Local development always stays same-origin so a production FRONTEND_URL
  // in .env cannot bounce localhost logins to the deployed site.
  const clientRedirect = (path, req) => {
    const host = req ? (req.get('x-forwarded-host') || req.get('host') || '') : '';
    const isLocal = /^(localhost|127\.0\.0\.1)(:\d+)?$/i.test(host);
    if (isLocal) return path;
    const frontendBase = getFrontendBaseUrl();
    return frontendBase ? `${frontendBase}${path}` : path;
  };

  const getGoogleAuthRedirectUri = req => {
    const baseUrl = getBaseUrl(req);
    if (baseUrl.includes('indiamail.toolsnetwork.online')) {
      const proto = baseUrl.startsWith('https') ? 'https' : 'http';
      return `${proto}://indiamail.toolsnetwork.online/oauth/oauth/google/callback`;
    }
    if (process.env.GOOGLE_AUTH_REDIRECT_URI && (!baseUrl || baseUrl.includes('localhost'))) return process.env.GOOGLE_AUTH_REDIRECT_URI;
    if (fileCredentials?.redirect_uris) {
      const match = fileCredentials.redirect_uris.find(u => u.startsWith(baseUrl) && u.includes('google'));
      if (match) return match;
    }
    if (baseUrl.includes('localhost:3000')) {
      return 'http://localhost:3000/oauth/oauth/google/callback';
    }
    return `${baseUrl}/oauth/oauth/google/callback`;
  };

  const getGmailRedirectUri = req => {
    const baseUrl = getBaseUrl(req);
    if (baseUrl.includes('indiamail.toolsnetwork.online')) {
      const proto = baseUrl.startsWith('https') ? 'https' : 'http';
      return `${proto}://indiamail.toolsnetwork.online/oauth/gmail/callback`;
    }
    if (process.env.GOOGLE_REDIRECT_URI && (!baseUrl || baseUrl.includes('localhost'))) return process.env.GOOGLE_REDIRECT_URI;
    if (fileCredentials?.redirect_uris) {
      const match = fileCredentials.redirect_uris.find(u => u.startsWith(baseUrl) && u.includes('gmail'));
      if (match) return match;
    }
    if (baseUrl.includes('mailindia.toolsnetwork.online')) {
      return 'https://mailindia.toolsnetwork.online/oauth/gmail/callback';
    }
    if (baseUrl.includes('localhost:3000')) {
      return 'http://localhost:3000/oauth/oauth/gmail/callback';
    }
    return `${baseUrl}/oauth/oauth/gmail/callback`;
  };

  // -------------------------------------------------------------
  // 1. GOOGLE SIGN-IN FLOW
  // -------------------------------------------------------------

  // GET /oauth/google/start & /oauth/oauth/google/start
  router.get(['/oauth/google/start', '/oauth/oauth/google/start'], async (req, res) => {
    try {
      const state = crypto.randomBytes(24).toString('hex');
      const redirectUri = getGoogleAuthRedirectUri(req);
      const clientId = getClientId();
      const wantsGmail = req.query.connect === 'gmail';
      const scope = wantsGmail
        ? 'openid email profile https://www.googleapis.com/auth/gmail.send'
        : (req.query.scope || 'openid email profile');

      // Store OAuth state in DB with 15-minute expiration
      await db.ref(`oauth_states/${state}`).set({
        type: 'google_signin',
        redirectUri,
        wantsGmail,
        createdAt: Date.now(),
        expiresAt: Date.now() + (15 * 60 * 1000)
      });

      const params = new URLSearchParams({
        client_id: clientId,
        redirect_uri: redirectUri,
        response_type: 'code',
        scope,
        state,
        prompt: wantsGmail ? 'consent select_account' : 'select_account',
        ...(wantsGmail ? { access_type: 'offline' } : {})
      });

      res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`);
    } catch (err) {
      console.error('[GOOGLE SIGN-IN START ERROR]', err);
      res.redirect(clientRedirect(`/account.html?error=${encodeURIComponent('Failed to initiate Google Sign-In')}`, req));
    }
  });

  // GET /oauth/google/callback & /oauth/oauth/google/callback
  router.get(['/oauth/google/callback', '/oauth/oauth/google/callback'], async (req, res) => {
    const { code, state, error } = req.query;

    console.log('[OAUTH CALLBACK RECEIVED]', {
      path: req.path,
      hasCode: Boolean(code),
      hasState: Boolean(state),
      error: error || null
    });

    if (error) {
      console.warn('[GOOGLE SIGN-IN ERROR]', error);
      return res.redirect(clientRedirect(`/account.html?error=${encodeURIComponent('Google sign-in was cancelled or denied.')}`, req));
    }

    if (!code || !state) {
      return res.redirect(clientRedirect(`/account.html?error=${encodeURIComponent('Missing authorization code or state parameter.')}`, req));
    }

    try {
      // Validate OAuth State
      const stateSnap = await db.ref(`oauth_states/${state}`).get();
      const stateRecord = stateSnap.val();
      await db.ref(`oauth_states/${state}`).set(null); // One-time use

      if (!stateRecord || stateRecord.type !== 'google_signin' || Date.now() > stateRecord.expiresAt) {
        console.warn('[GOOGLE OAUTH INVALID STATE]', { stateFound: Boolean(stateRecord) });
        return res.redirect(clientRedirect(`/account.html?error=${encodeURIComponent('Invalid or expired OAuth state. Please try signing in again.')}`, req));
      }

      const redirectUri = stateRecord.redirectUri || getGoogleAuthRedirectUri(req);
      const clientId = getClientId();
      const clientSecret = getClientSecret();

      // Exchange code for Google tokens
      const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          code,
          client_id: clientId,
          client_secret: clientSecret,
          redirect_uri: redirectUri,
          grant_type: 'authorization_code'
        })
      });

      const tokenData = await tokenResponse.json();
      if (!tokenResponse.ok || !tokenData.access_token) {
        console.error('[GOOGLE OAUTH TOKEN EXCHANGE FAILED]', tokenData.error_description || tokenData.error);
        throw new Error(tokenData.error_description || tokenData.error || 'Failed to exchange authorization code');
      }

      // Fetch Google User Profile
      const userinfoResponse = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
        headers: { Authorization: `Bearer ${tokenData.access_token}` }
      });
      const googleUser = await userinfoResponse.json();

      if (!userinfoResponse.ok || !googleUser.email || !googleUser.id) {
        throw new Error('Google did not return a valid user profile.');
      }
      if (googleUser.verified_email !== true) {
        throw new Error('Verify your email address with Google before signing in.');
      }

      const userEmail = googleUser.email.toLowerCase().trim();
      const googleId = googleUser.id;

      console.log('[GOOGLE IDENTITY VERIFIED]', {
        email: userEmail,
        googleId
      });

      // Find existing user by email or Google ID
      const usersSnap = await db.ref('users').get();
      const users = usersSnap.val() || {};
      let userEntry = Object.entries(users).find(([_, u]) => u && u.email && u.email.toLowerCase() === userEmail);
      let uid;
      let isNewUser = false;

      const adminEmails = (process.env.ADMIN_EMAILS || 'guliavansh64@gmail.com').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
      const isExplicitAdmin = (userEmail === 'guliavansh64@gmail.com');

      if (userEntry) {
        uid = userEntry[0];
        const rawName = userEntry[1]?.name || googleUser.name || '';
        const isReserved = /^\s*mail\s*india\s*$/i.test(rawName);
        const resolvedName = (!isExplicitAdmin && isReserved) ? userEmail.split('@')[0] : (rawName || userEmail.split('@')[0]);
        // Update user profile fields if new
        await db.ref(`users/${uid}`).update({
          googleId,
          lastLoginAt: Date.now(),
          picture: googleUser.picture || userEntry[1].picture || '',
          name: resolvedName,
          emailVerified: true
        });
      } else {
        isNewUser = true;
        uid = 'google_' + googleId;
        const rawName = googleUser.name || '';
        const isReserved = /^\s*mail\s*india\s*$/i.test(rawName);
        const resolvedName = (!isExplicitAdmin && isReserved) ? userEmail.split('@')[0] : (rawName || userEmail.split('@')[0]);
        const newProfile = {
          email: userEmail,
          name: resolvedName,
          picture: googleUser.picture || '',
          googleId,
          status: 'active',
          emailVerified: true,
          authProvider: 'google',
          admin: isExplicitAdmin,
          createdAt: Date.now(),
          lastLoginAt: Date.now()
        };
        await db.ref(`users/${uid}`).set(newProfile);

        // Provision initial wallet with 10 free welcome credits (or 10,000 for platform admin)
        await db.ref(`wallets/${uid}`).set({
          balance: isExplicitAdmin ? 10000 : 10,
          purchased: isExplicitAdmin ? 10000 : 10,
          consumed: 0,
          reserved: 0,
          updatedAt: Date.now(),
          ledger: {
            welcome_grant: {
              type: 'welcome_grant',
              credits: isExplicitAdmin ? 10000 : 10,
              createdAt: Date.now(),
              description: 'Initial developer welcome credits'
            }
          }
        });
      }

      console.log('[MAILBRIDGE USER IDENTIFIED]', {
        uid,
        email: userEmail,
        isNewUser
      });

      // Create session cookie with 14-day validity
      const expiresIn = 14 * 24 * 60 * 60 * 1000;
      const rawPayloadName = (userEntry ? userEntry[1]?.name : null) || googleUser.name || '';
      const isReservedPayloadName = /^\s*mail\s*india\s*$/i.test(rawPayloadName);
      const userPayloadName = (!isExplicitAdmin && isReservedPayloadName) ? userEmail.split('@')[0] : (rawPayloadName || userEmail.split('@')[0]);
      const userPayload = {
        uid,
        email: userEmail,
        name: userPayloadName,
        picture: googleUser.picture || '',
        email_verified: true,
        admin: isExplicitAdmin,
        auth_time: Math.floor(Date.now() / 1000)
      };

      let sessionCookie;
      try {
        sessionCookie = await auth.createSessionCookie(userPayload, { expiresIn });
      } catch (err1) {
        try {
          sessionCookie = await auth.createSessionCookie(uid, { expiresIn });
        } catch (err2) {
          console.error('[GOOGLE OAUTH SESSION ERROR]', err2.message);
          throw err2;
        }
      }

      const csrf = crypto.randomBytes(32).toString('hex');
      const isHttps = (req.get('x-forwarded-proto') === 'https') || req.secure;
      const cookieSecure = Boolean(isHttps);
      const oauthCookieOpts = {
        path: '/',
        httpOnly: true,
        sameSite: 'lax',
        maxAge: expiresIn
      };

      if (isHttps) {
        res.cookie('__Host-mb_session', sessionCookie, { ...oauthCookieOpts, secure: true });
        res.cookie('__Host-mb_csrf', csrf, { ...oauthCookieOpts, secure: true });
      } else {
        // Clear any lingering HTTPS-only cookies to prevent browser cookie conflicts
        res.clearCookie('__Host-mb_session', { path: '/' });
        res.clearCookie('__Host-mb_csrf', { path: '/' });
      }
      res.cookie('mb_session', sessionCookie, { ...oauthCookieOpts, secure: false });
      res.cookie('mb_csrf', csrf, { ...oauthCookieOpts, secure: false });

      console.log('[SESSION SUCCESSFULLY CREATED]', {
        uid,
        email: userEmail,
        isHttps,
        cookieSecure,
        expiresInDays: 14
      });

      // If user authorized offline access / Gmail send in Google Sign-In, automatically link Gmail
      let gmailLinked = false;
      if (tokenData.refresh_token) {
        try {
          const encryptedRefreshToken = encryptCredentials(encryptionKey, uid, { refreshToken: tokenData.refresh_token });
          await db.ref(`gmail_connections/${uid}`).set({
            email: userEmail,
            googleId,
            encryptedRefreshToken,
            status: 'active',
            scopes: tokenData.scope ? tokenData.scope.split(' ') : ['https://www.googleapis.com/auth/gmail.send'],
            connectedAt: Date.now()
          });
          gmailLinked = true;
          console.log('[GMAIL AUTO-CONNECTED VIA GOOGLE SIGNIN]', { uid, email: userEmail });
        } catch (connErr) {
          console.warn('[GMAIL AUTO-CONNECT FAILED]', connErr.message);
        }
      }

      // Redirect to dashboard with welcome toast, session token and gmail connected flag if applicable
      const gmailParam = gmailLinked ? '&gmail=connected' : '';
      const tokenParam = `&token=${encodeURIComponent(sessionCookie)}`;
      res.redirect(clientRedirect(`/dashboard.html?auth=google_success${isNewUser ? '&welcome=1' : ''}${tokenParam}${gmailParam}`, req));
    } catch (err) {
      console.error('[GOOGLE OAUTH CALLBACK ERROR]', err.message);
      res.redirect(clientRedirect(`/account.html?error=${encodeURIComponent(err.message || 'Google authentication failed.')}`, req));
    }
  });

  // -------------------------------------------------------------
  // 2. CONNECT GMAIL (GMAIL API SENDING & ADMIN SENDER POOL) FLOW
  // -------------------------------------------------------------

  const authenticateAdmin = async (req) => {
    let uid = null;
    let email = null;
    let emailVerified = false;

    const jar = getCookies(req);
    const queryToken = req.query?.token;
    const authHeader = req.get('authorization') || '';
    const bearerToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    const token = jar['__Host-mb_session'] || jar['mb_session'] || queryToken || bearerToken || '';

    if (token) {
      let decoded = await auth.verifySessionCookie(token, true).catch(() => null);
      if (!decoded) decoded = await auth.verifyIdToken(token, true).catch(() => null);
      if (decoded && decoded.uid) {
        uid = decoded.uid;
        email = decoded.email;
        emailVerified = decoded.email_verified === true;
      }
    }

    if (!uid) return { ok: false, status: 401, error: 'UNAUTHENTICATED', message: 'Authentication required.' };
    if (!emailVerified) return { ok: false, status: 403, error: 'EMAIL_NOT_VERIFIED', message: 'Email verification required.' };

    const adminEmails = (process.env.ADMIN_EMAILS || 'guliavansh64@gmail.com').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
    const userEmail = (email || '').toLowerCase();
    const isGmail = userEmail.endsWith('@gmail.com');

    // Strict rule: all Gmail cannot be admin except strictly guliavansh64@gmail.com
    if (isGmail && userEmail !== 'guliavansh64@gmail.com') {
      return { ok: false, status: 403, error: 'ADMIN_REQUIRED', message: 'Administrator privileges are required.' };
    }

    const isExplicitAdmin = userEmail === 'guliavansh64@gmail.com' || (!isGmail && adminEmails.includes(userEmail));
    let profile = null;
    try {
      profile = (await db.ref('users/' + uid).get()).val();
    } catch {}

    const isAdmin = isExplicitAdmin || (!isGmail && profile && (profile.admin || profile.role === 'admin'));
    if (!isAdmin) {
      return { ok: false, status: 403, error: 'ADMIN_REQUIRED', message: 'Administrator privileges are required.' };
    }

    return { ok: true, user: { uid, email: userEmail, admin: true } };
  };

  // GET /oauth/admin/gmail/connect & /api/admin/oauth/gmail/connect (Admin 1-Click Connect for Sender Pool)
  router.get(['/oauth/admin/gmail/connect', '/api/admin/oauth/gmail/connect', '/oauth/oauth/admin/gmail/connect'], async (req, res) => {
    const authResult = await authenticateAdmin(req);
    if (!authResult.ok) {
      const isJson = req.xhr || (req.get('accept') && req.get('accept').includes('application/json'));
      if (isJson) {
        return res.status(authResult.status).json({ success: false, error: authResult.error, message: authResult.message });
      }
      return res.redirect(clientRedirect(`/account.html?error=${encodeURIComponent(authResult.message || 'Administrator authentication required.')}`, req));
    }

    try {
      const state = crypto.randomBytes(24).toString('hex');
      const redirectUri = getGmailRedirectUri(req);
      const clientId = getClientId();

      // Store state bound to this admin session with 15-minute TTL
      await db.ref(`oauth_states/${state}`).set({
        type: 'admin_gmail_connect',
        adminUid: authResult.user.uid,
        adminEmail: authResult.user.email,
        redirectUri,
        createdAt: Date.now(),
        expiresAt: Date.now() + (15 * 60 * 1000)
      });

      const params = new URLSearchParams({
        client_id: clientId,
        redirect_uri: redirectUri,
        response_type: 'code',
        scope: 'openid email profile https://mail.google.com/ https://www.googleapis.com/auth/gmail.send',
        access_type: 'offline',
        prompt: 'consent select_account',
        state
      });

      const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;

      const isJson = req.xhr || (req.get('accept') && req.get('accept').includes('application/json'));
      if (isJson) {
        return res.json({ success: true, url: authUrl });
      }
      res.redirect(authUrl);
    } catch (err) {
      console.error('[ADMIN GMAIL CONNECT START ERROR]', err);
      res.redirect(clientRedirect(`/admin/senders.html?error=${encodeURIComponent('Failed to initiate Gmail connection.')}`, req));
    }
  });

  // GET /oauth/gmail/connect & /oauth/oauth/gmail/connect (Must be authenticated)
  router.get(['/oauth/gmail/connect', '/oauth/oauth/gmail/connect'], async (req, res) => {
    // Check session
    let uid = null;
    try {
      const jar = getCookies(req);
      const queryToken = req.query.token;
      const authHeader = req.get('authorization') || '';
      const bearerToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
      const token = jar['__Host-mb_session'] || jar['mb_session'] || queryToken || bearerToken || '';
      if (token) {
        let decoded = await auth.verifySessionCookie(token, true).catch(() => null);
        if (!decoded) decoded = await auth.verifyIdToken(token, true).catch(() => null);
        if (decoded && decoded.uid) {
          if (decoded.email_verified !== true) {
            return res.redirect(clientRedirect('/account.html?error=' + encodeURIComponent('Verify your email address before connecting Gmail.'), req));
          }
          uid = decoded.uid;
        }
      }
    } catch {}

    if (!uid) {
      return res.redirect(clientRedirect(`/account.html?msg=${encodeURIComponent('Please sign in before connecting your Gmail account.')}`, req));
    }

    try {
      const state = crypto.randomBytes(24).toString('hex');
      const redirectUri = getGmailRedirectUri(req);
      const clientId = getClientId();

      // Store state bound to this specific user UID with 15-minute TTL
      await db.ref(`oauth_states/${state}`).set({
        type: 'gmail_connect',
        uid,
        redirectUri,
        createdAt: Date.now(),
        expiresAt: Date.now() + (15 * 60 * 1000)
      });

      const params = new URLSearchParams({
        client_id: clientId,
        redirect_uri: redirectUri,
        response_type: 'code',
        scope: 'openid email profile https://www.googleapis.com/auth/gmail.send',
        access_type: 'offline',
        prompt: 'consent', // Required to receive a refresh token
        state
      });

      res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`);
    } catch (err) {
      console.error('[GMAIL CONNECT START ERROR]', err);
      res.redirect(clientRedirect(`/dashboard.html?error=${encodeURIComponent('Failed to initiate Gmail connection.')}`, req));
    }
  });

  // GET /oauth/gmail/callback & /oauth/oauth/gmail/callback
  router.get(['/oauth/gmail/callback', '/oauth/oauth/gmail/callback'], async (req, res) => {
    const { code, state, error } = req.query;

    if (error) {
      console.warn('[GMAIL OAUTH DENIED]', error);
      let isAdminFlow = false;
      if (state) {
        try {
          const sSnap = await db.ref(`oauth_states/${state}`).get();
          if (sSnap.val()?.type === 'admin_gmail_connect') isAdminFlow = true;
          await db.ref(`oauth_states/${state}`).set(null);
        } catch {}
      }
      const redirectTarget = isAdminFlow ? '/admin/senders.html' : '/dashboard.html';
      return res.redirect(clientRedirect(`${redirectTarget}?error=${encodeURIComponent('Gmail connection authorization was cancelled or denied.')}`, req));
    }

    if (!code || !state) {
      return res.redirect(clientRedirect(`/dashboard.html?error=${encodeURIComponent('Missing authorization code or state parameter.')}`, req));
    }

    let stateRecord = null;
    try {
      // Validate state
      const stateSnap = await db.ref(`oauth_states/${state}`).get();
      stateRecord = stateSnap.val();
      await db.ref(`oauth_states/${state}`).set(null); // Invalidate state

      if (!stateRecord || (stateRecord.type !== 'gmail_connect' && stateRecord.type !== 'admin_gmail_connect') || Date.now() > stateRecord.expiresAt) {
        const isAdmin = stateRecord?.type === 'admin_gmail_connect';
        return res.redirect(clientRedirect(`${isAdmin ? '/admin/senders.html' : '/dashboard.html'}?error=${encodeURIComponent('Invalid or expired Gmail connection state. Please try again.')}`, req));
      }

      // Handle Admin 1-Click Gmail Connect Flow
      if (stateRecord.type === 'admin_gmail_connect') {
        const redirectUri = stateRecord.redirectUri || getGmailRedirectUri(req);
        const clientId = getClientId();
        const clientSecret = getClientSecret();

        // Exchange code for access & refresh tokens
        const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            code,
            client_id: clientId,
            client_secret: clientSecret,
            redirect_uri: redirectUri,
            grant_type: 'authorization_code'
          })
        });

        const tokenData = await tokenResponse.json();
        if (!tokenResponse.ok || !tokenData.access_token) {
          throw new Error(tokenData.error_description || tokenData.error || 'Failed to exchange Gmail authorization code');
        }

        // Fetch the connected Gmail user profile to confirm the email
        const userinfoResponse = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
          headers: { Authorization: `Bearer ${tokenData.access_token}` }
        });
        const googleUser = await userinfoResponse.json();
        const connectedEmail = (googleUser.email || '').toLowerCase().trim();

        if (!connectedEmail) {
          throw new Error('Could not identify the authorized Gmail email address.');
        }

        // Check if this sender already exists in sender_accounts
        const sendersSnap = await db.ref('sender_accounts').get();
        const existingAccounts = sendersSnap.val() || {};
        const existingEntry = Object.entries(existingAccounts).find(([_, a]) => a && a.email && a.email.toLowerCase() === connectedEmail);
        const senderId = existingEntry ? existingEntry[0] : ('snd_' + crypto.randomUUID().replace(/-/g, '').slice(0, 16));

        let refreshToken = tokenData.refresh_token;
        if (!refreshToken) {
          if (existingEntry && existingEntry[1]?.credentials) {
            try {
              const { decryptCredentials } = require('./sending');
              const existingSecret = decryptCredentials(encryptionKey, senderId, existingEntry[1].credentials);
              if (existingSecret && existingSecret.refreshToken) {
                refreshToken = existingSecret.refreshToken;
              }
            } catch (decErr) {
              console.warn('[ADMIN GMAIL OAUTH] Could not decrypt existing credentials:', decErr.message);
            }
          }
          if (!refreshToken) {
            throw new Error('Google did not provide an offline refresh token. Please click Connect Gmail again and ensure all requested permissions are approved.');
          }
        }

        // Build secret with full OAuth2 details
        const secret = {
          type: 'oauth2',
          clientId,
          clientSecret,
          refreshToken,
          host: 'smtp.gmail.com',
          port: 465,
          secure: true
        };

        const credentials = encryptCredentials(encryptionKey, senderId, secret);
        const now = Date.now();

        await db.ref(`sender_accounts/${senderId}`).set({
          id: senderId,
          email: connectedEmail,
          name: googleUser.name || 'Gmail OAuth Sender',
          provider: 'gmail_oauth',
          authType: 'oauth2',
          host: 'smtp.gmail.com',
          port: 465,
          username: connectedEmail,
          credentials,
          dailyLimit: 500,
          status: 'active',
          verifiedAt: now,
          usage: existingEntry ? (existingEntry[1].usage || {}) : {},
          createdAt: existingEntry ? (existingEntry[1].createdAt || now) : now,
          updatedAt: now,
          connectedBy: stateRecord.adminEmail || stateRecord.adminUid || 'admin'
        });

        // Record in admin audit logs
        const logId = crypto.randomUUID();
        await db.ref(`admin_logs/${logId}`).set({
          adminId: stateRecord.adminUid || 'admin',
          action: existingEntry ? 'sender.oauth_updated' : 'sender.oauth_connected',
          target: senderId,
          details: { email: connectedEmail, provider: 'gmail_oauth', name: googleUser.name || '' },
          createdAt: now
        }).catch(() => {});

        console.log(`[ADMIN GMAIL OAUTH SENDER CONNECTED] ${connectedEmail} (ID: ${senderId})`);
        return res.redirect(clientRedirect(`/admin/senders.html?sender_connected=success&email=${encodeURIComponent(connectedEmail)}`, req));
      }

      // Handle Standard User Gmail Connect Flow
      const uid = stateRecord.uid;
      const redirectUri = stateRecord.redirectUri || getGmailRedirectUri(req);
      const clientId = getClientId();
      const clientSecret = getClientSecret();

      // Exchange code for access & refresh tokens
      const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          code,
          client_id: clientId,
          client_secret: clientSecret,
          redirect_uri: redirectUri,
          grant_type: 'authorization_code'
        })
      });

      const tokenData = await tokenResponse.json();
      if (!tokenResponse.ok || !tokenData.access_token) {
        throw new Error(tokenData.error_description || tokenData.error || 'Failed to exchange Gmail authorization code');
      }

      // Fetch the connected Gmail user profile to confirm the email
      const userinfoResponse = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
        headers: { Authorization: `Bearer ${tokenData.access_token}` }
      });
      const googleUser = await userinfoResponse.json();
      const connectedEmail = (googleUser.email || '').toLowerCase().trim();

      if (!connectedEmail) {
        throw new Error('Could not identify the authorized Gmail email address.');
      }

      // Handle refresh token
      let refreshToken = tokenData.refresh_token;

      // If Google didn't return a refresh token (can happen if already consented), check existing connection
      if (!refreshToken) {
        const existingSnap = await db.ref(`gmail_connections/${uid}`).get();
        const existing = existingSnap.val();
        if (existing && existing.encryptedRefreshToken) {
          // Keep existing encrypted refresh token
          await db.ref(`gmail_connections/${uid}`).update({
            email: connectedEmail,
            name: googleUser.name || '',
            picture: googleUser.picture || '',
            status: 'active',
            lastRefreshedAt: Date.now()
          });
          return res.redirect(clientRedirect(`/dashboard.html?gmail=connected&email=${encodeURIComponent(connectedEmail)}`, req));
        } else {
          throw new Error('Google did not provide an offline refresh token. Please click Connect Gmail and ensure all permissions are granted.');
        }
      }

      // Encrypt the refresh token using server-side AES-256-GCM
      const encryptedRefreshToken = encryptCredentials(encryptionKey, uid, {
        refreshToken,
        connectedAt: Date.now()
      });

      // Save connection securely
      await db.ref(`gmail_connections/${uid}`).set({
        email: connectedEmail,
        name: googleUser.name || '',
        picture: googleUser.picture || '',
        status: 'active',
        encryptedRefreshToken,
        scopes: tokenData.scope ? tokenData.scope.split(' ') : ['https://www.googleapis.com/auth/gmail.send'],
        connectedAt: Date.now(),
        lastRefreshedAt: Date.now()
      });

      console.log(`[GMAIL CONNECTED] Successfully connected ${connectedEmail} for user ${uid}`);
      res.redirect(clientRedirect(`/dashboard.html?gmail=connected&email=${encodeURIComponent(connectedEmail)}`, req));
    } catch (err) {
      console.error('[GMAIL OAUTH CALLBACK ERROR]', err.message);
      const isAdm = stateRecord?.type === 'admin_gmail_connect';
      const redirectTarget = isAdm ? '/admin/senders.html' : '/dashboard.html';
      res.redirect(clientRedirect(`${redirectTarget}?error=${encodeURIComponent(err.message || 'Gmail connection failed.')}`, req));
    }
  });

  // -------------------------------------------------------------
  // 3. GMAIL STATUS & MANAGEMENT API ENDPOINTS
  // -------------------------------------------------------------

  // Middleware helper to extract authenticated user from session cookie or Bearer token
  const authenticateUser = authenticate || (async (req, res, next) => {
    let uid = null;
    let email = null;
    let emailVerified = false;

    try {
      const jar = getCookies(req);
      const token = jar['__Host-mb_session'] || jar['mb_session'] || '';
      if (token) {
        const decoded = await auth.verifySessionCookie(token, true).catch(() => null);
        if (decoded && decoded.uid) {
          uid = decoded.uid;
          email = decoded.email;
          emailVerified = decoded.email_verified === true;
        }
      }
    } catch {}

    if (!uid && req.get('authorization')) {
      const authHeader = req.get('authorization') || '';
      const match = /^Bearer (\S+)$/.exec(authHeader);
      if (match) {
        try {
          let decoded = await auth.verifyIdToken(match[1]).catch(() => null);
          if (!decoded) {
            decoded = await auth.verifySessionCookie(match[1], true).catch(() => null);
          }
          if (decoded && decoded.uid) {
            uid = decoded.uid;
            email = decoded.email;
            emailVerified = decoded.email_verified === true;
          }
        } catch {}
      }
    }

    if (!uid) {
      return res.status(401).json({ success: false, error: 'UNAUTHENTICATED', message: 'Authentication required.' });
    }
    if (!emailVerified) {
      return res.status(403).json({ success: false, error: 'EMAIL_NOT_VERIFIED', message: 'Verify your email address before accessing Gmail features.' });
    }

    req.user = { uid, email, email_verified: true };
    next();
  });

  // GET /api/gmail/status
  router.get('/api/gmail/status', authenticateUser, async (req, res) => {
    try {
      const snap = await db.ref(`gmail_connections/${req.user.uid}`).get();
      const conn = snap.val();

      if (!conn || !conn.encryptedRefreshToken) {
        return res.json({
          success: true,
          connected: false
        });
      }

      res.json({
        success: true,
        connected: conn.status === 'active',
        email: conn.email,
        name: conn.name || '',
        picture: conn.picture || '',
        status: conn.status || 'active',
        connectedAt: conn.connectedAt,
        lastRefreshedAt: conn.lastRefreshedAt || null
      });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // POST /api/gmail/disconnect
  router.post('/api/gmail/disconnect', authenticateUser, async (req, res) => {
    try {
      const result = await disconnectUserGmail({ db, uid: req.user.uid });
      res.json({
        success: true,
        message: 'Gmail account disconnected successfully.',
        disconnectedEmail: result.email
      });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // POST /api/gmail/send-test
  router.post('/api/gmail/send-test', authenticateUser, async (req, res) => {
    const to = typeof req.body?.to === 'string' ? req.body.to.trim() : '';
    const subject = typeof req.body?.subject === 'string' ? req.body.subject.trim() : 'Mail India Live Test Email';
    const text = typeof req.body?.text === 'string' ? req.body.text : 'This is a verified transactional email sent via Mail India official Gmail API integration.';
    const html = typeof req.body?.html === 'string' ? req.body.html : null;

    if (!to || !to.includes('@')) {
      return res.status(400).json({ success: false, error: 'INVALID_RECIPIENT', message: 'A valid recipient email address is required.' });
    }

    try {
      const result = await sendViaConnectedGmail({
        db,
        uid: req.user.uid,
        encryptionKey,
        clientId: getClientId(),
        clientSecret: getClientSecret(),
        emailOptions: {
          to,
          subject,
          text,
          fromName: 'Mail India',
          html: html || `<div style="font-family:sans-serif;padding:20px;border:1px solid #e2e8f0;border-radius:10px">
            <h2 style="color:#4f46e5;margin:0 0 10px">⚡ Mail India Live Delivery Test</h2>
            <p style="font-size:14px;color:#334155;line-height:1.6">${text}</p>
            <hr style="border:none;border-top:1px solid #e2e8f0;margin:16px 0">
            <div style="font-size:12px;color:#94a3b8">Dispatched via Mail India official Gmail API connector · 100% Google Deliverability</div>
          </div>`
        }
      });

      // Record email in user sending activity
      const logId = crypto.randomUUID();
      await db.ref(`wallets/${req.user.uid}/sendRequests/${logId}`).set({
        id: logId,
        provider: 'gmail_api',
        senderEmail: result.connectedEmail,
        status: 'accepted',
        providerMessageId: result.messageId,
        message: { to, subject },
        createdAt: Date.now()
      }).catch(() => {});

      res.json({
        success: true,
        message: `Email dispatched successfully via Gmail API (${result.connectedEmail})`,
        messageId: result.messageId,
        from: result.from
      });
    } catch (err) {
      console.error('[GMAIL SEND TEST ERROR]', err);
      res.status(400).json({
        success: false,
        error: err.code || 'GMAIL_SEND_ERROR',
        message: err.message
      });
    }
  });

  return router;
}

module.exports = { createGoogleOAuthRoutes };
