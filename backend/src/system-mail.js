'use strict';

const { decryptCredentials, transport, validEmail, safeId } = require('./sending');
const parseAddresses = require('nodemailer/lib/addressparser');

class SystemMailError extends Error {
  constructor(code, message, status = 503, uncertain = false) {
    super(message);
    this.name = 'SystemMailError';
    this.code = code;
    this.status = status;
    this.uncertain = uncertain;
  }
}

// Provider messages can include account details or SMTP commands. Expose only
// these fixed messages, never the original response or a verification link.
function smtpError(error, phase = 'send') {
  if (error instanceof SystemMailError) return error;
  const response = Number(error?.responseCode);
  if (error?.code === 'EAUTH' || response === 534 || response === 535) {
    return new SystemMailError('SMTP_AUTH_FAILED', 'Gmail rejected the sender credentials. Save a valid 16-letter app password and verify SMTP again.', 502);
  }
  if (['ENOTFOUND', 'EAI_AGAIN', 'ECONNREFUSED'].includes(error?.code) || error?.command === 'CONN' || phase === 'verify') {
    return new SystemMailError('SMTP_CONNECTION_FAILED', 'Could not connect to Gmail SMTP. Check the sender settings and try again.', 502);
  }
  if (error?.code === 'EENVELOPE' || response === 550 || response === 551 || response === 553) {
    return new SystemMailError('SMTP_RECIPIENT_REJECTED', 'Gmail rejected the recipient address. Check the address before trying again.', 502);
  }
  if (response >= 400 && response < 500) {
    return new SystemMailError('SMTP_TEMPORARY_FAILURE', 'Gmail temporarily rejected the email. Please wait before trying again.', 503);
  }
  if (response >= 500 && response < 600) {
    return new SystemMailError('SMTP_SEND_REJECTED', 'Gmail rejected the email. Check the sender account and its sending limits.', 502);
  }
  return new SystemMailError('SMTP_OUTCOME_UNCERTAIN', 'Gmail did not confirm the email outcome. Check your inbox before requesting another email.', 502, true);
}

const escapeHtml = value => String(value).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const isVerified = sender => Number.isFinite(sender?.verifiedAt) && sender.verifiedAt > 0;
const isGmail = sender => (sender?.authType === 'app_password' || sender?.authType === 'oauth2' || sender?.provider === 'gmail_oauth' || sender?.provider === 'gmail') && String(sender.host || 'smtp.gmail.com').toLowerCase() === 'smtp.gmail.com' && validEmail(sender.email);

function createSystemMailer({ db, auth, encryptionKey, senderId = process.env.SYSTEM_SENDER_ID || '', smtpFactory = transport }) {
  async function getSender() {
    if (!db?.ref) throw new SystemMailError('DATABASE_UNAVAILABLE', 'The Realtime Database is unavailable. Contact the administrator.');
    let selected;
    try {
      if (senderId) {
        if (!safeId(senderId)) throw new SystemMailError('SYSTEM_SENDER_INVALID', 'SYSTEM_SENDER_ID must identify a configured Gmail sender.');
        const snap = (await db.ref('sender_accounts/' + senderId).get()).val();
        if (snap) {
          selected = [senderId, snap];
        } else {
          // If the configured senderId no longer exists, fall back to eligible active senders
          const senders = (await db.ref('sender_accounts').get()).val() || {};
          const eligible = Object.entries(senders).filter(([, sender]) => isGmail(sender) && sender.status === 'active' && isVerified(sender));
          if (eligible.length > 0) {
            selected = eligible[0];
          } else {
            throw new SystemMailError('SYSTEM_SENDER_NOT_FOUND', 'The configured system Gmail sender was not found.');
          }
        }
      } else {
        const senders = (await db.ref('sender_accounts').get()).val() || {};
        const eligible = Object.entries(senders).filter(([, sender]) => isGmail(sender) && sender.status === 'active' && isVerified(sender));
        if (eligible.length > 1) throw new SystemMailError('SYSTEM_SENDER_AMBIGUOUS', 'Multiple Gmail senders are available. Set SYSTEM_SENDER_ID to the sender for account emails.');
        if (!eligible.length) throw new SystemMailError('SYSTEM_SENDER_UNAVAILABLE', 'Add a Gmail app-password sender and verify SMTP before sending account emails.');
        selected = eligible[0];
      }
    } catch (err) {
      if (err instanceof SystemMailError) throw err;
      throw new SystemMailError('DATABASE_UNAVAILABLE', 'Could not read the system sender from Realtime Database.');
    }
    const [id, sender] = selected;
    if (!isGmail(sender)) throw new SystemMailError('SYSTEM_SENDER_NOT_GMAIL', 'The system sender must use Gmail (OAuth2 or app password) and smtp.gmail.com.');
    if (sender.status !== 'active') throw new SystemMailError('SYSTEM_SENDER_PAUSED', 'The configured Gmail sender is paused. Verify SMTP to activate it.');
    if (!isVerified(sender)) throw new SystemMailError('SYSTEM_SENDER_UNVERIFIED', 'Verify the configured Gmail sender with Verify SMTP before sending account emails.');
    return { id, sender };
  }

  async function prepareSender() {
    const selected = await getSender();
    if (typeof encryptionKey !== 'string' || Buffer.from(encryptionKey, 'base64').length !== 32) {
      throw new SystemMailError('SENDER_KEY_UNAVAILABLE', 'The sender encryption key is not configured correctly. Contact the administrator.');
    }
    let secret;
    try { secret = decryptCredentials(encryptionKey, selected.id, selected.sender.credentials); }
    catch { throw new SystemMailError('SENDER_DECRYPTION_FAILED', 'The Gmail credentials cannot be opened with the current encryption key. Restore the original key or save the app password again.'); }
    if (secret.type === 'oauth2') {
      if (!secret.refreshToken || !secret.clientId || !secret.clientSecret) {
        throw new SystemMailError('GMAIL_OAUTH_INVALID', 'The connected Gmail OAuth sender is missing refresh tokens. Reconnect Gmail in Admin senders.', 400);
      }
    } else if (secret.type === 'app_password') {
      if (!/^[a-z]{16}$/i.test(String(secret.password || '').replace(/\s+/g, '')) || String(secret.host || 'smtp.gmail.com').toLowerCase() !== 'smtp.gmail.com') {
        throw new SystemMailError('GMAIL_APP_PASSWORD_INVALID', 'Save a valid 16-letter Gmail app password and verify SMTP again.', 400);
      }
      secret.password = secret.password.replace(/\s+/g, '');
    } else {
      throw new SystemMailError('GMAIL_CREDENTIALS_INVALID', 'Gmail sender must use either OAuth2 or a 16-letter app password.', 400);
    }
    return { ...selected, secret };
  }

  function fromAddress(sender, requestedFrom) {
    if (requestedFrom !== undefined) {
      const parsed = typeof requestedFrom === 'string' && !/[\r\n]/.test(requestedFrom)
        ? parseAddresses(requestedFrom) : (requestedFrom && typeof requestedFrom === 'object' ? [requestedFrom] : []);
      if (parsed.length !== 1 || String(parsed[0].address || '').toLowerCase() !== sender.email.toLowerCase() || /[\r\n]/.test(String(parsed[0].name || ''))) {
        throw new SystemMailError('SYSTEM_SENDER_FROM_MISMATCH', 'The From address must match the configured Gmail sender.', 400);
      }
      return requestedFrom;
    }
    return { name: String(sender.name || 'MAIL INDIA').replace(/[\r\n]/g, ''), address: sender.email };
  }

  async function claimSenderUse(selected) {
    let reason = 'SYSTEM_SENDER_UNAVAILABLE';
    let result;
    const day = new Date().toISOString().slice(0, 10);
    try {
      result = await db.ref('sender_accounts/' + selected.id).transaction(sender => {
        reason = 'SYSTEM_SENDER_UNAVAILABLE';
        if (sender === null) return null;
        if (!sender || sender.status !== 'active' || !isVerified(sender) || sender.credentials?.ciphertext !== selected.sender.credentials?.ciphertext) return;
        const used = sender.usage?.[day] || 0;
        if (!Number.isSafeInteger(sender.dailyLimit) || sender.dailyLimit < 1 || !Number.isSafeInteger(used) || used >= sender.dailyLimit) {
          reason = 'SYSTEM_SENDER_QUOTA_EXCEEDED';
          return;
        }
        sender.usage = sender.usage || {};
        sender.usage[day] = used + 1;
        return sender;
      }, undefined, false);
    } catch { throw new SystemMailError('DATABASE_UNAVAILABLE', 'Could not reserve the Gmail sender quota in Realtime Database.'); }
    const finalVal = typeof result?.snapshot?.val === 'function' ? result.snapshot.val() : result?.snapshot?.val;
    if (!result?.committed || !finalVal) {
      if (reason === 'SYSTEM_SENDER_QUOTA_EXCEEDED') throw new SystemMailError(reason, 'The configured Gmail sender has reached its daily limit. Please try again later.', 429);
      throw new SystemMailError(reason, 'The Gmail sender changed or was paused. Check its configuration before trying again.');
    }
  }

  async function deliver(selected, message) {
    const from = fromAddress(selected.sender, message.from);
    await claimSenderUse(selected);
    let client;
    let result;
    try {
      client = smtpFactory(selected.sender.email, selected.secret);
      result = await client.sendMail({ from, to: message.to, subject: message.subject, text: message.text || '', ...(message.html ? { html: message.html } : {}) });
    } catch (err) { throw smtpError(err); }
    finally { try { client?.close?.(); } catch {} }
    const recipient = message.to.toLowerCase();
    const address = item => String(typeof item === 'string' ? item : item?.address || '').toLowerCase();
    if (Array.isArray(result?.rejected) && result.rejected.some(item => address(item) === recipient)) {
      throw new SystemMailError('SMTP_RECIPIENT_REJECTED', 'Gmail rejected the recipient address. Check the address before trying again.', 502);
    }
    if (!Array.isArray(result?.accepted) || !result.accepted.some(item => address(item) === recipient)) {
      throw new SystemMailError('SMTP_OUTCOME_UNCERTAIN', 'Gmail did not confirm acceptance of the email. Check your inbox before requesting another email.', 502, true);
    }
    return { success: true, email: message.to, provider: 'gmail_smtp', senderId: selected.id };
  }

  async function sendEmail(message = {}) {
    if (!validEmail(message.to) || typeof message.subject !== 'string' || !message.subject.trim() || /[\r\n]/.test(message.subject) || (!message.text && !message.html)) {
      throw new SystemMailError('INVALID_SYSTEM_EMAIL', 'A valid recipient, subject and email content are required.', 400);
    }
    return deliver(await prepareSender(), message);
  }

  async function sendVerificationEmail({ email, actionCodeSettings } = {}) {
    if (!validEmail(email)) throw new SystemMailError('INVALID_EMAIL', 'A valid account email address is required.', 400);
    if (typeof auth?.generateEmailVerificationLink !== 'function') throw new SystemMailError('FIREBASE_ADMIN_REQUIRED', 'Firebase Admin credentials are required to generate a verification link.');
    const selected = await prepareSender();
    let link;
    try {
      link = await auth.generateEmailVerificationLink(email, actionCodeSettings);
      if (typeof link !== 'string' || new URL(link).protocol !== 'https:') throw new Error('Invalid action link');
    } catch { throw new SystemMailError('VERIFICATION_LINK_FAILED', 'Firebase could not generate a verification link. Check the Firebase Admin configuration.'); }

    let brandedVerifyUrl = link;
    try {
      const parsedUrl = new URL(link);
      const oobCode = parsedUrl.searchParams.get('oobCode') || '';
      const backendBase = (process.env.API_BASE_URL || process.env.BACKEND_URL || 'https://mail-india-beta.vercel.app').replace(/\/$/, '');
      brandedVerifyUrl = `${backendBase}/api/auth/verify-action?code=${encodeURIComponent(oobCode)}&email=${encodeURIComponent(email)}&returnUrl=${encodeURIComponent(link)}`;
    } catch {}

    return deliver(selected, {
      to: email,
      subject: 'Verify your email — MAIL INDIA',
      text: `Verify your MAIL INDIA email address by opening this link:\n\n${brandedVerifyUrl}\n\n${link}\n\nAfter verification, return to MAIL INDIA and sign in. If you did not create this account, ignore this email.`,
      html: `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Verify your email</title>
</head>
<body style="margin:0;padding:0;background-color:#f1f5f9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;-webkit-font-smoothing:antialiased;">
  <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="background-color:#f1f5f9;padding:40px 16px;">
    <tr>
      <td align="center">
        <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width:560px;background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 10px 25px rgba(0,0,0,0.06);border:1px solid #e2e8f0;">
          <tr>
            <td style="background:linear-gradient(135deg,#4f46e5 0%,#7c3aed 100%);padding:32px 30px;text-align:center;">
              <div style="display:inline-block;background:rgba(255,255,255,0.18);border-radius:12px;padding:10px 18px;margin-bottom:10px;">
                <span style="font-size:24px;line-height:1;">✉️</span>
                <span style="font-size:20px;font-weight:900;letter-spacing:1.5px;color:#ffffff;margin-left:6px;vertical-align:middle;">MAIL INDIA</span>
              </div>
              <div style="font-size:13px;color:rgba(255,255,255,0.92);font-weight:500;letter-spacing:0.5px;">Cloud Email Relay & Security Verification</div>
            </td>
          </tr>
          <tr>
            <td style="padding:36px 32px 28px;color:#1e293b;">
              <h1 style="font-size:22px;font-weight:800;color:#0f172a;margin:0 0 14px;line-height:1.3;text-align:center;">Verify Your Email Address</h1>
              <p style="font-size:15px;line-height:1.65;color:#475569;margin:0 0 24px;text-align:center;">
                Welcome to <strong>MAIL INDIA</strong>! Please confirm <strong style="color:#0f172a;">${escapeHtml(email)}</strong> to complete your account setup and access high-speed email delivery.
              </p>
              <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="margin:28px 0;">
                <tr>
                  <td align="center">
                    <a href="${escapeHtml(brandedVerifyUrl)}" target="_blank" style="display:inline-block;background:linear-gradient(135deg,#4f46e5 0%,#6366f1 100%);color:#ffffff;text-decoration:none;font-size:16px;font-weight:700;padding:15px 36px;border-radius:10px;box-shadow:0 4px 14px rgba(79,70,229,0.35);letter-spacing:0.3px;">
                      Verify Email Address
                    </a>
                  </td>
                </tr>
              </table>
              <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;padding:16px 20px;margin:28px 0 20px;">
                <div style="font-size:12px;font-weight:700;color:#334155;text-transform:uppercase;letter-spacing:0.8px;margin-bottom:6px;">⏱️ Link Expiration</div>
                <div style="font-size:13px;color:#64748b;line-height:1.5;">This verification link is active for 24 hours. After verifying, return to MAIL INDIA to sign in to your dashboard.</div>
              </div>
              <p style="font-size:12px;line-height:1.6;color:#94a3b8;margin:24px 0 0;word-break:break-all;">
                If the button above does not work, copy and paste this link into your browser:<br>
                <a href="${escapeHtml(brandedVerifyUrl)}" style="color:#4f46e5;text-decoration:underline;">${escapeHtml(brandedVerifyUrl)}</a>
              </p>
              <div style="display:none;max-height:0;overflow:hidden;opacity:0;">${escapeHtml(link)}</div>
            </td>
          </tr>
          <tr>
            <td style="background:#f8fafc;border-top:1px solid #e2e8f0;padding:22px 32px;text-align:center;">
              <p style="font-size:12px;color:#64748b;margin:0 0 8px;line-height:1.5;">
                If you did not sign up for MAIL INDIA, you can safely disregard this email.
              </p>
              <p style="font-size:11px;color:#94a3b8;margin:0;">
                © 2026 MAIL INDIA Cloud Relay · India's High-Performance Email Infrastructure
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`
    });
  }

  return { getSender, sendEmail, sendVerificationEmail };
}

module.exports = { createSystemMailer, SystemMailError, smtpError };
