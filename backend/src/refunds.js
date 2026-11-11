'use strict';
const crypto = require('node:crypto');

const REFUND_STATES = {
  PENDING: 'pending',
  PROCESSING: 'processing',
  COMPLETED: 'completed',
  FAILED: 'failed',
  REVERSED: 'reversed'
};

/**
 * Calculates refundable paise for an order.
 */
function getRefundableAmount(order) {
  if (!order || order.status !== 'captured') return 0;
  const total = order.amountPaise || 0;
  const alreadyRefunded = order.refundedPaise || 0;
  return Math.max(0, total - alreadyRefunded);
}

/**
 * Initiates a full or partial refund for a captured payment order.
 */
async function initiateRefund({ db, provider, orderId, amountPaise, reason, adminId, speed = 'normal' }) {
  if (!orderId || !/^order_[A-Za-z0-9]+$/.test(orderId)) {
    throw new Error('INVALID_ORDER_ID');
  }

  const orderSnap = await db.ref('payment_orders/' + orderId).get();
  const order = orderSnap.val();
  if (!order) {
    throw new Error('ORDER_NOT_FOUND');
  }
  if (order.status !== 'captured' || !order.paymentId) {
    throw new Error('ORDER_NOT_REFUNDABLE');
  }

  const refundable = getRefundableAmount(order);
  if (refundable <= 0) {
    throw new Error('ORDER_FULLY_REFUNDED');
  }

  const targetAmount = Number.isSafeInteger(amountPaise) && amountPaise > 0 ? amountPaise : refundable;
  if (targetAmount <= 0 || targetAmount > refundable) {
    throw new Error('INVALID_REFUND_AMOUNT');
  }

  const receipt = 'rfnd_' + crypto.randomBytes(12).toString('hex');
  const now = Date.now();

  // Call Razorpay Refund API
  let rzpRefund;
  try {
    rzpRefund = await provider.createRefund(order.paymentId, {
      amount: targetAmount,
      speed,
      notes: {
        orderId,
        uid: order.uid,
        reason: (reason || 'Admin initiated refund').slice(0, 200),
        adminId: adminId || 'admin'
      },
      receipt
    });
  } catch (err) {
    console.error('Razorpay refund API error:', err.message);
    const refundId = 'rfnd_failed_' + crypto.randomBytes(8).toString('hex');
    const failedRecord = {
      id: refundId,
      orderId,
      paymentId: order.paymentId,
      uid: order.uid,
      amountPaise: targetAmount,
      creditsToRecover: Math.round((targetAmount / order.amountPaise) * order.credits),
      status: REFUND_STATES.FAILED,
      reason: reason || 'Admin initiated refund',
      error: err.message || 'PROVIDER_REFUND_FAILED',
      adminId: adminId || 'admin',
      speed,
      createdAt: now,
      updatedAt: now
    };
    await db.ref('payment_refunds/' + refundId).set(failedRecord);
    throw new Error('REFUND_INITIATION_FAILED: ' + (err.message || 'Provider rejected refund'));
  }

  const refundId = rzpRefund.id;
  const initialStatus = rzpRefund.status === 'processed'
    ? REFUND_STATES.COMPLETED
    : REFUND_STATES.PROCESSING;

  const creditsToRecover = Math.round((targetAmount / order.amountPaise) * order.credits);

  const refundRecord = {
    id: refundId,
    orderId,
    paymentId: order.paymentId,
    uid: order.uid,
    amountPaise: targetAmount,
    creditsToRecover,
    status: initialStatus,
    reason: reason || 'Admin initiated refund',
    adminId: adminId || 'admin',
    speed,
    createdAt: now,
    updatedAt: now,
    error: null
  };

  // Atomically commit refund record and handle credit recovery
  await applyRefundState({ db, refundRecord, order });

  return refundRecord;
}

/**
 * Commits a refund record to RTDB, updates order refundedPaise, and executes credit recovery.
 */
async function applyRefundState({ db, refundRecord, order }) {
  const { id: refundId, orderId, uid, amountPaise, creditsToRecover, status } = refundRecord;
  const now = Date.now();

  // 1. Store refund record in payment_refunds
  await db.ref('payment_refunds/' + refundId).set(refundRecord);

  // 2. If refund completed, update order and user wallet ledger
  if (status === REFUND_STATES.COMPLETED) {
    // Update order refunded amount
    await db.ref('payment_orders/' + orderId).transaction(o => {
      if (!o) return;
      const currentRefunded = o.refundedPaise || 0;
      o.refundedPaise = currentRefunded + amountPaise;
      o.updatedAt = now;
      return o;
    }, undefined, false);

    // Credit Recovery in Wallet Transaction
    let recoveryOutcome = 'manual_review_required';
    const result = await db.ref('wallets/' + uid).transaction(wallet => {
      if (wallet === null) return null;
      wallet = wallet || { balance: 0, reserved: 0, purchased: 0, consumed: 0 };
      wallet.ledger = wallet.ledger || {};

      // Idempotency check: don't double recover
      if (wallet.ledger['refund_' + refundId]) {
        return wallet;
      }

      const available = wallet.balance || 0;
      if (Number.isSafeInteger(available) && available >= creditsToRecover) {
        // Safe automatic recovery
        wallet.balance = available - creditsToRecover;
        wallet.purchased = Math.max(0, (wallet.purchased || 0) - creditsToRecover);
        wallet.ledger['refund_' + refundId] = {
          type: 'refund',
          credits: -creditsToRecover,
          amountPaise,
          reference: refundId,
          orderId,
          createdAt: now
        };
        recoveryOutcome = 'recovered';
      } else {
        // Available balance is insufficient (credits were already partially/fully consumed).
        // Never blindly deduct into negative.
        // Record ledger entry noting manual review is required, preserving financial audit trail.
        wallet.ledger['refund_pending_review_' + refundId] = {
          type: 'refund_recovery_pending',
          creditsRequired: -creditsToRecover,
          creditsAvailable: available,
          amountPaise,
          reference: refundId,
          orderId,
          createdAt: now
        };
        recoveryOutcome = 'manual_review_required';
      }
      return wallet;
    }, undefined, false);

    refundRecord.recoveryStatus = recoveryOutcome;
    await db.ref('payment_refunds/' + refundId + '/recoveryStatus').set(recoveryOutcome);
  }

  return refundRecord;
}

/**
 * Handles incoming Razorpay refund webhook events.
 */
async function handleRefundWebhook({ db, event, eventId }) {
  const refundEntity = event.payload?.refund?.entity;
  if (!refundEntity || !refundEntity.id) {
    throw new Error('INVALID_REFUND_ENTITY');
  }

  const refundId = refundEntity.id;
  const paymentId = refundEntity.payment_id;
  const amountPaise = refundEntity.amount;
  const rzpStatus = refundEntity.status;
  const now = Date.now();

  let targetState = REFUND_STATES.PROCESSING;
  if (rzpStatus === 'processed') targetState = REFUND_STATES.COMPLETED;
  else if (rzpStatus === 'failed') targetState = REFUND_STATES.FAILED;
  else if (rzpStatus === 'reversed') targetState = REFUND_STATES.REVERSED;

  // Find existing refund or look up order by paymentId
  const existingRefundSnap = await db.ref('payment_refunds/' + refundId).get();
  let refundRecord = existingRefundSnap.val();

  let orderId = refundRecord?.orderId;
  let uid = refundRecord?.uid;
  let order = null;

  if (orderId) {
    const oSnap = await db.ref('payment_orders/' + orderId).get();
    order = oSnap.val();
  } else {
    // Search order by paymentId supporting both .forEach and .val()
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
  }

  if (!order) {
    // Order not found locally; record financial alert
    await db.ref('financial_alerts/' + refundId).set({
      type: 'orphan_refund',
      refundId,
      paymentId,
      amountPaise,
      status: targetState,
      createdAt: now
    });
    return { status: 'recorded_as_alert' };
  }

  const creditsToRecover = Math.round((amountPaise / order.amountPaise) * order.credits);

  refundRecord = {
    ...(refundRecord || {}),
    id: refundId,
    orderId,
    paymentId,
    uid,
    amountPaise,
    creditsToRecover,
    status: targetState,
    reason: refundRecord?.reason || refundEntity.notes?.reason || 'Webhook processed refund',
    adminId: refundRecord?.adminId || 'webhook',
    error: refundEntity.error_description || null,
    updatedAt: now,
    createdAt: refundRecord?.createdAt || now
  };

  await applyRefundState({ db, refundRecord, order });

  return refundRecord;
}

/**
 * Retries an eligible failed refund.
 */
async function retryFailedRefund({ db, provider, refundId, adminId }) {
  const snap = await db.ref('payment_refunds/' + refundId).get();
  const record = snap.val();
  if (!record) throw new Error('REFUND_NOT_FOUND');
  if (record.status !== REFUND_STATES.FAILED) {
    throw new Error('ONLY_FAILED_REFUNDS_CAN_BE_RETRIED');
  }

  return initiateRefund({
    db,
    provider,
    orderId: record.orderId,
    amountPaise: record.amountPaise,
    reason: 'Retry: ' + (record.reason || ''),
    adminId: adminId || 'admin',
    speed: record.speed || 'normal'
  });
}

module.exports = {
  REFUND_STATES,
  getRefundableAmount,
  initiateRefund,
  applyRefundState,
  handleRefundWebhook,
  retryFailedRefund
};
