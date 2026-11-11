'use strict';
const crypto = require('node:crypto');

const DISPUTE_STATUSES = {
  OPEN: 'open',
  UNDER_REVIEW: 'under_review',
  WON: 'won',
  LOST: 'lost',
  CLOSED: 'closed'
};

const RECOVERY_STATUSES = {
  PENDING: 'pending',
  RECOVERED: 'recovered',
  MANUAL_REVIEW_REQUIRED: 'manual_review_required',
  WAIVED: 'waived'
};

/**
 * Handles an incoming Razorpay dispute webhook event.
 */
async function handleDisputeWebhook({ db, event, eventId }) {
  const entity = event.payload?.dispute?.entity || event.payload?.payment?.entity?.dispute;
  if (!entity || !entity.id) {
    throw new Error('INVALID_DISPUTE_ENTITY');
  }

  const disputeId = entity.id;
  const paymentId = entity.payment_id;
  const amountPaise = entity.amount;
  const rawStatus = entity.status || 'open';
  const reasonCode = entity.reason_code || entity.reason || 'dispute_reported';
  const now = Date.now();

  // Find linked payment order
  let orderId = null;
  let uid = null;
  let order = null;

  const ordersSnap = await db.ref('payment_orders').get();
  const ordersVal = ordersSnap.val() || {};
  for (const [k, val] of Object.entries(ordersVal)) {
    if (val && val.paymentId === paymentId) {
      orderId = k;
      uid = val.uid;
      order = val;
      break;
    }
  }

  if (!order) {
    await db.ref('financial_alerts/' + disputeId).set({
      type: 'orphan_dispute',
      disputeId,
      paymentId,
      amountPaise,
      rawStatus,
      createdAt: now
    });
    return { status: 'recorded_as_alert' };
  }

  const existingDisputeSnap = await db.ref('payment_disputes/' + disputeId).get();
  const existing = existingDisputeSnap.val();

  const creditsDisputed = Math.round((amountPaise / order.amountPaise) * order.credits);

  let disputeStatus = DISPUTE_STATUSES.OPEN;
  if (['under_review', 'action_required'].includes(rawStatus)) disputeStatus = DISPUTE_STATUSES.UNDER_REVIEW;
  else if (rawStatus === 'won') disputeStatus = DISPUTE_STATUSES.WON;
  else if (rawStatus === 'lost') disputeStatus = DISPUTE_STATUSES.LOST;
  else if (rawStatus === 'closed') disputeStatus = DISPUTE_STATUSES.CLOSED;

  let recoveryStatus = existing?.recoveryStatus || RECOVERY_STATUSES.PENDING;

  // When dispute is won, restore credits to user if they were held
  if (disputeStatus === DISPUTE_STATUSES.WON) {
    if (existing && existing.recoveryStatus === RECOVERY_STATUSES.RECOVERED) {
      await restoreDisputeCredits(db, uid, disputeId, creditsDisputed, amountPaise, now);
      recoveryStatus = 'credits_restored';
    }
  } else if (!existing || existing.recoveryStatus === RECOVERY_STATUSES.PENDING) {
    recoveryStatus = await attemptCreditRecovery(db, uid, disputeId, creditsDisputed, amountPaise, now);
  }

  const disputeRecord = {
    id: disputeId,
    paymentId,
    orderId,
    uid,
    amountPaise,
    creditsDisputed,
    status: disputeStatus,
    reason: reasonCode,
    evidence: existing?.evidence || null,
    recoveryStatus,
    createdAt: existing?.createdAt || now,
    updatedAt: now
  };

  await db.ref('payment_disputes/' + disputeId).set(disputeRecord);
  return disputeRecord;
}

/**
 * Executes safe credit recovery rule on dispute.
 */
async function attemptCreditRecovery(db, uid, disputeId, creditsDisputed, amountPaise, now) {
  let outcome = RECOVERY_STATUSES.MANUAL_REVIEW_REQUIRED;

  const result = await db.ref('wallets/' + uid).transaction(wallet => {
    if (wallet === null) return null;
    wallet = wallet || { balance: 0, reserved: 0, purchased: 0, consumed: 0 };
    wallet.ledger = wallet.ledger || {};

    if (wallet.ledger['dispute_hold_' + disputeId]) {
      return wallet;
    }

    const available = wallet.balance || 0;
    // Check available vs consumed credits
    if (Number.isSafeInteger(available) && available >= creditsDisputed) {
      // User has enough available credits to hold
      wallet.balance = available - creditsDisputed;
      wallet.purchased = Math.max(0, (wallet.purchased || 0) - creditsDisputed);
      wallet.ledger['dispute_hold_' + disputeId] = {
        type: 'dispute_hold',
        credits: -creditsDisputed,
        amountPaise,
        reference: disputeId,
        createdAt: now
      };
      outcome = RECOVERY_STATUSES.RECOVERED;
    } else {
      // User has consumed some or all of the credits.
      // Rule: Never blindly deduct credits from a user's wallet into negative.
      // Require admin review.
      wallet.ledger['dispute_pending_review_' + disputeId] = {
        type: 'dispute_recovery_pending',
        creditsRequired: -creditsDisputed,
        creditsAvailable: available,
        amountPaise,
        reference: disputeId,
        createdAt: now
      };
      outcome = RECOVERY_STATUSES.MANUAL_REVIEW_REQUIRED;
    }
    return wallet;
  }, undefined, false);

  return outcome;
}

/**
 * Restores dispute credits if dispute was won.
 */
async function restoreDisputeCredits(db, uid, disputeId, creditsDisputed, amountPaise, now) {
  await db.ref('wallets/' + uid).transaction(wallet => {
    wallet = wallet || { balance: 0, reserved: 0, purchased: 0, consumed: 0 };
    wallet.ledger = wallet.ledger || {};
    if (wallet.ledger['dispute_restored_' + disputeId]) return wallet;

    wallet.balance = (wallet.balance || 0) + creditsDisputed;
    wallet.purchased = (wallet.purchased || 0) + creditsDisputed;
    wallet.ledger['dispute_restored_' + disputeId] = {
      type: 'dispute_restored',
      credits: creditsDisputed,
      amountPaise,
      reference: disputeId,
      createdAt: now
    };
    return wallet;
  }, undefined, false);
}

/**
 * Admin resolves a dispute manual credit recovery.
 */
async function resolveDisputeRecovery({ db, disputeId, action, adminId, reason }) {
  if (!reason || reason.trim().length < 5) {
    throw new Error('A reason of at least 5 characters is required.');
  }

  const snap = await db.ref('payment_disputes/' + disputeId).get();
  const dispute = snap.val();
  if (!dispute) throw new Error('DISPUTE_NOT_FOUND');

  const now = Date.now();
  const uid = dispute.uid;
  const credits = dispute.creditsDisputed;

  if (action === 'deduct_available') {
    await db.ref('wallets/' + uid).transaction(w => {
      w = w || { balance: 0, reserved: 0, purchased: 0, consumed: 0 };
      w.ledger = w.ledger || {};
      const avail = Math.max(0, w.balance || 0);
      const toDeduct = Math.min(avail, credits);
      if (toDeduct > 0) {
        w.balance = avail - toDeduct;
        w.purchased = Math.max(0, (w.purchased || 0) - toDeduct);
        w.ledger['dispute_admin_recovery_' + disputeId] = {
          type: 'admin_dispute_recovery',
          credits: -toDeduct,
          reference: disputeId,
          adminId,
          reason: reason.trim(),
          createdAt: now
        };
      }
      return w;
    }, undefined, false);
    dispute.recoveryStatus = 'partially_recovered';
  } else if (action === 'create_negative_adjustment') {
    // Explicit negative adjustment ledger entry as requested by rule:
    // "Handle negative adjustments through explicit ledger entries. Require admin review where automatic recovery is unsafe."
    await db.ref('wallets/' + uid).transaction(w => {
      w = w || { balance: 0, reserved: 0, purchased: 0, consumed: 0 };
      w.ledger = w.ledger || {};
      w.balance = (w.balance || 0) - credits;
      w.purchased = (w.purchased || 0) - credits;
      w.ledger['dispute_explicit_adjustment_' + disputeId] = {
        type: 'explicit_dispute_adjustment',
        credits: -credits,
        reference: disputeId,
        adminId,
        reason: reason.trim(),
        createdAt: now
      };
      return w;
    }, undefined, false);
    dispute.recoveryStatus = 'explicit_adjustment_applied';
  } else if (action === 'waive') {
    await db.ref('wallets/' + uid).transaction(w => {
      w = w || { balance: 0, reserved: 0, purchased: 0, consumed: 0 };
      w.ledger = w.ledger || {};
      w.ledger['dispute_waived_' + disputeId] = {
        type: 'dispute_recovery_waived',
        credits: 0,
        reference: disputeId,
        adminId,
        reason: reason.trim(),
        createdAt: now
      };
      return w;
    }, undefined, false);
    dispute.recoveryStatus = 'waived';
  } else {
    throw new Error('INVALID_RECOVERY_ACTION');
  }

  dispute.updatedAt = now;
  await db.ref('payment_disputes/' + disputeId).set(dispute);

  // Admin audit log
  await db.ref('admin_logs/' + crypto.randomUUID()).set({
    adminId,
    action: 'dispute.resolve_recovery',
    target: disputeId,
    details: { action, reason: reason.trim() },
    createdAt: now
  });

  return dispute;
}

/**
 * Admin records dispute evidence.
 */
async function recordDisputeEvidence({ db, disputeId, evidenceText, adminId }) {
  if (!evidenceText || evidenceText.trim().length < 10) {
    throw new Error('Evidence text must be at least 10 characters.');
  }

  const snap = await db.ref('payment_disputes/' + disputeId).get();
  const dispute = snap.val();
  if (!dispute) throw new Error('DISPUTE_NOT_FOUND');

  const now = Date.now();
  dispute.evidence = {
    text: evidenceText.trim(),
    submittedBy: adminId,
    submittedAt: now
  };
  dispute.status = DISPUTE_STATUSES.UNDER_REVIEW;
  dispute.updatedAt = now;

  await db.ref('payment_disputes/' + disputeId).set(dispute);

  await db.ref('admin_logs/' + crypto.randomUUID()).set({
    adminId,
    action: 'dispute.evidence_submitted',
    target: disputeId,
    createdAt: now
  });

  return dispute;
}

module.exports = {
  DISPUTE_STATUSES,
  RECOVERY_STATUSES,
  handleDisputeWebhook,
  resolveDisputeRecovery,
  recordDisputeEvidence
};
