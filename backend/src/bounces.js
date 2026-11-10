'use strict';
const crypto = require('node:crypto');

const sha = s => crypto.createHash('sha256').update(s.toLowerCase().trim()).digest('hex');

const BOUNCE_TYPES = {
  HARD: 'hard',
  SOFT: 'soft'
};

/**
 * Records a bounce event and manages suppression list automatically.
 */
async function recordBounce(db, { recipient, type = BOUNCE_TYPES.HARD, reason, messageId = null, source = 'smtp_error' }) {
  if (!recipient || typeof recipient !== 'string') throw new Error('INVALID_RECIPIENT');

  const normalized = recipient.toLowerCase().trim();
  const hash = sha(normalized);
  const now = Date.now();
  const id = crypto.randomUUID();

  const record = {
    id,
    recipient: normalized,
    recipientHash: hash,
    type,
    reason: (reason || 'Bounce detected').slice(0, 300),
    messageId: messageId || null,
    source,
    createdAt: now
  };

  await db.ref('bounce_records/' + id).set(record);

  if (type === BOUNCE_TYPES.HARD) {
    // Hard bounces result in permanent suppression
    await db.ref('suppression_list/' + hash).set({
      recipient: normalized,
      reason: 'Hard bounce: ' + (reason || 'Permanent failure'),
      type: 'hard_bounce',
      createdAt: now,
      source
    });
  } else if (type === BOUNCE_TYPES.SOFT) {
    // Check soft bounce frequency in the past 7 days
    const recentCutoff = now - (7 * 86400000);
    const snap = await db.ref('bounce_records').get();
    const bouncesVal = snap.val() || {};
    let softBounceCount = 0;
    for (const b of Object.values(bouncesVal)) {
      if (b && b.recipientHash === hash && b.type === BOUNCE_TYPES.SOFT && b.createdAt > recentCutoff) {
        softBounceCount++;
      }
    }

    if (softBounceCount >= 3) {
      await db.ref('suppression_list/' + hash).set({
        recipient: normalized,
        reason: 'Repeated soft bounces (' + softBounceCount + ' in 7 days): ' + (reason || 'Temporary failures'),
        type: 'repeated_soft_bounce',
        createdAt: now,
        source
      });
    }
  }

  return { id, recipient: normalized, hash, type, suppressed: type === BOUNCE_TYPES.HARD };
}

/**
 * Records an abuse / spam complaint and automatically suppresses recipient.
 */
async function recordComplaint(db, { recipient, reason, messageId = null, source = 'webhook' }) {
  if (!recipient || typeof recipient !== 'string') throw new Error('INVALID_RECIPIENT');

  const normalized = recipient.toLowerCase().trim();
  const hash = sha(normalized);
  const now = Date.now();
  const id = crypto.randomUUID();

  const record = {
    id,
    recipient: normalized,
    recipientHash: hash,
    reason: (reason || 'Spam complaint').slice(0, 300),
    messageId: messageId || null,
    source,
    createdAt: now
  };

  await db.ref('complaint_records/' + id).set(record);

  // Complaints immediately add recipient to permanent suppression list
  await db.ref('suppression_list/' + hash).set({
    recipient: normalized,
    reason: 'Spam complaint: ' + (reason || 'User marked message as spam'),
    type: 'complaint',
    createdAt: now,
    source
  });

  return { id, recipient: normalized, hash, suppressed: true };
}

/**
 * Ingests delivery events from supported webhooks or administrative ingestion.
 */
async function handleDeliveryEvent(db, event) {
  const { eventType, recipient, reason, messageId, source } = event || {};
  if (!recipient) throw new Error('MISSING_RECIPIENT');

  if (eventType === 'bounce') {
    const isHard = event.bounceType === 'hard' || (event.statusCode && event.statusCode.startsWith('5'));
    return recordBounce(db, {
      recipient,
      type: isHard ? BOUNCE_TYPES.HARD : BOUNCE_TYPES.SOFT,
      reason: reason || event.diagnosticCode || 'Bounce event',
      messageId,
      source: source || 'delivery_webhook'
    });
  } else if (eventType === 'complaint') {
    return recordComplaint(db, {
      recipient,
      reason: reason || 'Spam complaint reported',
      messageId,
      source: source || 'delivery_webhook'
    });
  } else if (eventType === 'delivered') {
    // Record delivery confirmation if messageId is known
    if (messageId) {
      await db.ref('delivery_events/' + crypto.randomUUID()).set({
        messageId,
        recipient: recipient.toLowerCase().trim(),
        status: 'delivered',
        createdAt: Date.now()
      });
    }
    return { status: 'recorded_delivery', recipient };
  } else {
    throw new Error('UNSUPPORTED_DELIVERY_EVENT_TYPE');
  }
}

/**
 * Checks if a recipient is suppressed.
 */
async function isSuppressed(db, email) {
  if (!email || typeof email !== 'string') return false;
  const hash = sha(email);
  const snap = await db.ref('suppression_list/' + hash).get();
  return !!snap.val();
}

module.exports = {
  BOUNCE_TYPES,
  recordBounce,
  recordComplaint,
  handleDeliveryEvent,
  isSuppressed,
  sha
};
