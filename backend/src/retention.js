'use strict';
const crypto = require('node:crypto');

const DEFAULT_POLICIES = {
  emailLogsDays: 90,
  recipientDataDays: 90,
  messageContentDays: 30,
  supportTicketsDays: 180,
  auditLogsDays: 365
};

/**
 * Returns current retention policies merged with defaults.
 */
async function getRetentionPolicies(db) {
  const snap = await db.ref('platform_settings/retention').get();
  return { ...DEFAULT_POLICIES, ...(snap.val() || {}) };
}

/**
 * Updates retention policies.
 */
async function setRetentionPolicies(db, updates, adminId) {
  const current = await getRetentionPolicies(db);
  const next = { ...current };

  for (const [key, val] of Object.entries(updates || {})) {
    if (key in DEFAULT_POLICIES && Number.isSafeInteger(val) && val >= 1 && val <= 3650) {
      next[key] = val;
    }
  }

  const now = Date.now();
  await db.ref('platform_settings/retention').set(next);

  await db.ref('admin_logs/' + crypto.randomUUID()).set({
    adminId: adminId || 'admin',
    action: 'settings.retention_updated',
    target: 'retention_policies',
    value: next,
    createdAt: now
  });

  return next;
}

/**
 * Executes a scheduled or manual data retention cleanup based on active policies.
 */
async function runRetentionCleanup(db, adminId = 'system') {
  const policies = await getRetentionPolicies(db);
  const now = Date.now();

  const logsCutoff = now - (policies.emailLogsDays * 86400000);
  const contentCutoff = now - (policies.messageContentDays * 86400000);
  const ticketsCutoff = now - (policies.supportTicketsDays * 86400000);
  const auditCutoff = now - (policies.auditLogsDays * 86400000);

  let logsPurged = 0;
  let messageContentPurged = 0;
  let ticketsPurged = 0;
  let auditLogsPurged = 0;

  // 1. Purge expired email logs
  const logsSnap = await db.ref('email_logs').get();
  const logsVal = logsSnap.val() || {};
  for (const [uid, userLogs] of Object.entries(logsVal)) {
    if (!userLogs || typeof userLogs !== 'object') continue;
    for (const [logKey, val] of Object.entries(userLogs)) {
      if (val && val.createdAt && val.createdAt < logsCutoff) {
        db.ref(`email_logs/${uid}/${logKey}`).set(null);
        logsPurged++;
      }
    }
  }

  // 2. Anonymize/clean expired message content in wallets (sendRequests)
  const walletsSnap = await db.ref('wallets').get();
  const walletsVal = walletsSnap.val() || {};
  for (const [uid, userWallet] of Object.entries(walletsVal)) {
    const sendRequests = userWallet?.sendRequests || {};
    for (const [jobId, job] of Object.entries(sendRequests)) {
      if (job && job.createdAt && job.createdAt < contentCutoff && (job.message?.text || job.message?.html)) {
        db.ref(`wallets/${uid}/sendRequests/${jobId}/message/text`).set('[PURGED_RETENTION_POLICY]');
        db.ref(`wallets/${uid}/sendRequests/${jobId}/message/html`).set('[PURGED_RETENTION_POLICY]');
        messageContentPurged++;
      }
    }
  }

  // 3. Purge closed support tickets older than retention
  const ticketsSnap = await db.ref('support_tickets').get();
  const ticketsVal = ticketsSnap.val() || {};
  for (const [uid, userTickets] of Object.entries(ticketsVal)) {
    if (!userTickets || typeof userTickets !== 'object') continue;
    for (const [ticketKey, t] of Object.entries(userTickets)) {
      if (t && t.status === 'closed' && (t.closedAt || t.createdAt) < ticketsCutoff) {
        db.ref(`support_tickets/${uid}/${ticketKey}`).set(null);
        ticketsPurged++;
      }
    }
  }

  // 4. Purge old audit logs older than retention
  const adminLogsSnap = await db.ref('admin_logs').get();
  const adminLogsVal = adminLogsSnap.val() || {};
  for (const [logKey, l] of Object.entries(adminLogsVal)) {
    if (l && l.createdAt && l.createdAt < auditCutoff) {
      db.ref(`admin_logs/${logKey}`).set(null);
      auditLogsPurged++;
    }
  }

  const summary = {
    logsPurged,
    messageContentPurged,
    ticketsPurged,
    auditLogsPurged,
    executedBy: adminId,
    executedAt: now
  };

  // Record retention run in admin logs
  await db.ref('admin_logs/' + crypto.randomUUID()).set({
    adminId,
    action: 'retention.cleanup_run',
    target: 'platform',
    value: summary,
    createdAt: now
  });

  return summary;
}

/**
 * Handles a user data deletion / GDPR Right to Be Forgotten request.
 * Removes personal data and email content while preserving immutable financial
 * ledger records with pseudonymization.
 */
async function purgeUserData(db, uid, requestedBy = 'user') {
  if (!uid || typeof uid !== 'string') throw new Error('INVALID_UID');

  const userSnap = await db.ref('users/' + uid).get();
  const user = userSnap.val();
  if (!user) throw new Error('USER_NOT_FOUND');

  const now = Date.now();
  const pseudonym = 'deleted-' + crypto.createHash('sha256').update(uid).digest('hex').slice(0, 16);

  // 1. Anonymize user profile
  await db.ref('users/' + uid).update({
    name: 'Anonymized User',
    email: pseudonym + '@privacy.local',
    status: 'deleted',
    deletedAt: now
  });

  // 2. Revoke and remove all API keys
  const keysSnap = await db.ref('user_api_keys/' + uid).get();
  const keys = keysSnap.val() || {};
  for (const keyId of Object.keys(keys)) {
    await db.ref(`user_api_keys/${uid}/${keyId}`).update({ status: 'revoked', deletedAt: now });
  }

  // Clear key_index for this user
  const keyIndexSnap = await db.ref('key_index').get();
  const keyIndexVal = keyIndexSnap.val() || {};
  for (const [keyHash, entry] of Object.entries(keyIndexVal)) {
    if (entry && entry.uid === uid) {
      db.ref('key_index/' + keyHash).set(null);
    }
  }

  // 3. Delete email logs for this user
  await db.ref('email_logs/' + uid).set(null);

  // 4. Anonymize wallet sendRequests (strip message contents, replace recipient with pseudonym)
  const walletSnap = await db.ref('wallets/' + uid).get();
  const wallet = walletSnap.val() || {};
  if (wallet.sendRequests) {
    for (const [id, req] of Object.entries(wallet.sendRequests)) {
      if (req && req.message) {
        await db.ref(`wallets/${uid}/sendRequests/${id}/message`).set({
          to: 'anonymized@privacy.local',
          subject: '[DELETED_UNDER_GDPR]',
          text: '[DELETED_UNDER_GDPR]',
          html: '[DELETED_UNDER_GDPR]',
          consent: false
        });
      }
    }
  }

  // 5. Delete support tickets
  await db.ref('support_tickets/' + uid).set(null);

  // 6. Delete sender assignment
  await db.ref('sender_assignments/' + uid).set(null);

  // 7. Record in data_deletion_logs
  const logId = crypto.randomUUID();
  const logEntry = {
    id: logId,
    uid,
    pseudonym,
    requestedBy,
    deletedAt: now,
    financialRecordsPreserved: true
  };
  await db.ref('data_deletion_logs/' + logId).set(logEntry);

  await db.ref('admin_logs/' + crypto.randomUUID()).set({
    adminId: requestedBy,
    action: 'user.data_deleted',
    target: uid,
    value: logEntry,
    createdAt: now
  });

  return logEntry;
}

module.exports = {
  DEFAULT_POLICIES,
  getRetentionPolicies,
  setRetentionPolicies,
  runRetentionCleanup,
  purgeUserData
};
