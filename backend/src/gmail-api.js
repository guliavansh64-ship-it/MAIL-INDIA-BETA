'use strict';
const crypto = require('node:crypto');
const MailComposer = require('nodemailer/lib/mail-composer');
const { decryptCredentials, encryptCredentials } = require('./sending');

// In-memory token cache to avoid redundant Google token refreshes
const tokenCache = new Map();

function toBase64Url(buffer) {
  return Buffer.from(buffer)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Builds an RFC 2822 MIME message buffer using nodemailer MailComposer
 */
function buildMimeMessage({ from, to, cc, bcc, replyTo, subject, text, html, attachments }) {
  return new Promise((resolve, reject) => {
    try {
      const mailOptions = {
        from,
        to,
        subject: subject || '(No Subject)',
        ...(cc ? { cc } : {}),
        ...(bcc ? { bcc } : {}),
        ...(replyTo ? { replyTo } : {}),
        ...(text ? { text } : {}),
        ...(html ? { html } : {}),
        ...(Array.isArray(attachments) && attachments.length ? { attachments } : {})
      };

      const composer = new MailComposer(mailOptions);
      composer.compile().build((err, messageBuffer) => {
        if (err) return reject(err);
        resolve(messageBuffer);
      });
    } catch (err) {
      reject(err);
    }
  });
}

/**
 * Exchanges a refresh token for a fresh Google OAuth access token
 */
async function refreshAccessToken({ clientId, clientSecret, refreshToken }) {
  if (!clientId || !clientSecret || !refreshToken) {
    throw new Error('MISSING_OAUTH_CREDENTIALS');
  }

  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
      refresh_token: refreshToken,
      grant_type: 'refresh_token'
    })
  });

  const data = await response.json();
  if (!response.ok || data.error) {
    const errCode = data.error === 'invalid_grant' ? 'GMAIL_TOKEN_REVOKED' : (data.error || 'TOKEN_REFRESH_FAILED');
    const err = new Error(data.error_description || 'Failed to refresh Google access token');
    err.code = errCode;
    throw err;
  }

  return {
    accessToken: data.access_token,
    expiresIn: data.expires_in || 3600
  };
}

/**
 * Retrieves or refreshes an active access token for a connected user
 */
async function getValidAccessToken({ db, uid, encryptionKey, clientId, clientSecret }) {
  const cached = tokenCache.get(uid);
  if (cached && cached.expiresAt > Date.now() + 60000) {
    return { accessToken: cached.accessToken, email: cached.email };
  }

  const snap = await db.ref(`gmail_connections/${uid}`).get();
  const conn = snap.val();

  if (!conn || !conn.encryptedRefreshToken || conn.status !== 'active') {
    const err = new Error('No active Gmail account connected for this workspace.');
    err.code = 'GMAIL_NOT_CONNECTED';
    throw err;
  }

  let refreshToken = null;
  try {
    const secretData = decryptCredentials(encryptionKey, uid, conn.encryptedRefreshToken);
    refreshToken = secretData.refreshToken;
  } catch (err) {
    console.error(`[GMAIL DECRYPT ERROR] uid: ${uid}`, err.message);
    const decryptErr = new Error('Unable to decrypt connected Gmail credentials.');
    decryptErr.code = 'CREDENTIAL_DECRYPTION_FAILED';
    throw decryptErr;
  }

  if (!refreshToken) {
    const err = new Error('Gmail refresh token is missing. Please reconnect your account.');
    err.code = 'GMAIL_TOKEN_MISSING';
    throw err;
  }

  try {
    const { accessToken, expiresIn } = await refreshAccessToken({ clientId, clientSecret, refreshToken });
    const expiresAt = Date.now() + (expiresIn * 1000);
    tokenCache.set(uid, { accessToken, expiresAt, email: conn.email });

    // Update connection metadata (last verified / refreshed)
    await db.ref(`gmail_connections/${uid}`).update({
      lastRefreshedAt: Date.now(),
      status: 'active'
    }).catch(() => {});

    return { accessToken, email: conn.email };
  } catch (err) {
    if (err.code === 'GMAIL_TOKEN_REVOKED') {
      await db.ref(`gmail_connections/${uid}/status`).set('needs_reconnect').catch(() => {});
      tokenCache.delete(uid);
    }
    throw err;
  }
}

/**
 * Sends a raw RFC 2822 message via Google Gmail API
 */
async function sendRawGmailMessage({ accessToken, rawBase64Url }) {
  const response = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/messages/send', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ raw: rawBase64Url })
  });

  const data = await response.json();
  if (!response.ok || data.error) {
    const errorMsg = data.error?.message || 'Gmail API dispatch failed';
    const err = new Error(errorMsg);
    err.status = response.status;
    err.code = data.error?.status || 'GMAIL_API_ERROR';
    throw err;
  }

  return {
    id: data.id,
    threadId: data.threadId,
    labelIds: data.labelIds || []
  };
}

/**
 * Complete high-level sender for MailBridge users via their connected Gmail account
 */
async function sendViaConnectedGmail({ db, uid, encryptionKey, clientId, clientSecret, emailOptions }) {
  const { accessToken, email: connectedEmail } = await getValidAccessToken({
    db,
    uid,
    encryptionKey,
    clientId,
    clientSecret
  });

  const userProfileSnap = await db.ref(`users/${uid}`).get();
  const profile = userProfileSnap.val() || {};
  const senderDisplayName = (emailOptions.fromName && emailOptions.fromName.trim()) || 'Mail India';
  const fromHeader = `"${senderDisplayName.replace(/["\r\n]/g, '')}" <${connectedEmail}>`;

  const mimeBuffer = await buildMimeMessage({
    from: fromHeader,
    to: emailOptions.to,
    cc: emailOptions.cc,
    bcc: emailOptions.bcc,
    replyTo: emailOptions.replyTo,
    subject: emailOptions.subject,
    text: emailOptions.text,
    html: emailOptions.html,
    attachments: emailOptions.attachments
  });

  const rawBase64Url = toBase64Url(mimeBuffer);

  try {
    const result = await sendRawGmailMessage({ accessToken, rawBase64Url });
    return {
      success: true,
      provider: 'gmail_api',
      messageId: result.id,
      threadId: result.threadId,
      from: fromHeader,
      connectedEmail
    };
  } catch (err) {
    if (err.status === 401) {
      // Token might have just expired; purge cache and retry once
      tokenCache.delete(uid);
      const refreshed = await getValidAccessToken({ db, uid, encryptionKey, clientId, clientSecret });
      const retryResult = await sendRawGmailMessage({ accessToken: refreshed.accessToken, rawBase64Url });
      return {
        success: true,
        provider: 'gmail_api',
        messageId: retryResult.id,
        threadId: retryResult.threadId,
        from: fromHeader,
        connectedEmail: refreshed.email
      };
    }
    throw err;
  }
}

/**
 * Disconnects a user's Gmail connection
 */
async function disconnectUserGmail({ db, uid }) {
  tokenCache.delete(uid);
  const snap = await db.ref(`gmail_connections/${uid}`).get();
  const conn = snap.val();
  await db.ref(`gmail_connections/${uid}`).set(null);
  return { success: true, email: conn?.email || null };
}

module.exports = {
  buildMimeMessage,
  toBase64Url,
  refreshAccessToken,
  getValidAccessToken,
  sendRawGmailMessage,
  sendViaConnectedGmail,
  disconnectUserGmail,
  tokenCache
};
