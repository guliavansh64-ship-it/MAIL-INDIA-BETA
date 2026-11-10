'use strict';
const crypto = require('node:crypto');

/**
 * Performs a complete financial reconciliation across Razorpay orders,
 * captured payments, refunds, disputes, and wallet ledgers.
 */
async function performReconciliation(db) {
  const [ordersSnap, refundsSnap, disputesSnap, walletsSnap] = await Promise.all([
    db.ref('payment_orders').get(),
    db.ref('payment_refunds').get(),
    db.ref('payment_disputes').get(),
    db.ref('wallets').get()
  ]);

  const orders = ordersSnap.val() || {};
  const refunds = refundsSnap.val() || {};
  const disputes = disputesSnap.val() || {};
  const wallets = walletsSnap.val() || {};

  const matched = [];
  const missingWalletCredits = [];
  const duplicatePaymentEvents = [];
  const missingRefundEntries = [];
  const unmatchedTransactions = [];
  const reconciliationErrors = [];

  // Group refunds by orderId
  const refundsByOrder = {};
  for (const [rId, r] of Object.entries(refunds)) {
    if (!r || !r.orderId) continue;
    refundsByOrder[r.orderId] = refundsByOrder[r.orderId] || [];
    refundsByOrder[r.orderId].push(r);
  }

  // 1. Inspect all orders
  for (const [orderId, order] of Object.entries(orders)) {
    if (!order) continue;
    const uid = order.uid;
    const wallet = wallets[uid] || {};
    const ledger = wallet.ledger || {};

    if (order.status === 'captured') {
      const orderCredited = wallet.paymentOrders?.[orderId] === order.paymentId;
      const purchaseEntries = Object.entries(ledger).filter(
        ([k, v]) => (v.type === 'purchase' || k === 'purchase_' + orderId) &&
          (v.reference === order.paymentId || k === 'purchase_' + orderId)
      );

      if (!orderCredited || purchaseEntries.length === 0) {
        missingWalletCredits.push({
          orderId,
          paymentId: order.paymentId,
          uid,
          amountPaise: order.amountPaise,
          credits: order.credits,
          reason: 'Captured order missing wallet credit or ledger entry'
        });
      } else if (purchaseEntries.length > 1) {
        duplicatePaymentEvents.push({
          orderId,
          paymentId: order.paymentId,
          uid,
          count: purchaseEntries.length,
          entries: purchaseEntries.map(([k, v]) => ({ key: k, credits: v.credits }))
        });
      } else {
        // Exactly one purchase entry matching order
        const entry = purchaseEntries[0][1];
        if (entry.credits !== order.credits || entry.amountPaise !== order.amountPaise) {
          reconciliationErrors.push({
            orderId,
            paymentId: order.paymentId,
            uid,
            expectedCredits: order.credits,
            actualCredits: entry.credits,
            expectedPaise: order.amountPaise,
            actualPaise: entry.amountPaise,
            type: 'AMOUNT_CREDIT_MISMATCH'
          });
        } else {
          matched.push({
            orderId,
            paymentId: order.paymentId,
            uid,
            amountPaise: order.amountPaise,
            credits: order.credits,
            capturedAt: order.capturedAt || order.createdAt
          });
        }
      }

      // Check refunds for this order
      const orderRefunds = refundsByOrder[orderId] || [];
      for (const ref of orderRefunds) {
        if (ref.status === 'completed') {
          const refundLedger = ledger['refund_' + ref.id];
          if (!refundLedger) {
            missingRefundEntries.push({
              refundId: ref.id,
              orderId,
              uid,
              amountPaise: ref.amountPaise,
              creditsToRecover: ref.creditsToRecover,
              reason: 'Completed refund missing from user wallet ledger'
            });
          }
        }
      }
    }
  }

  // 2. Inspect all wallets for orphaned ledger entries and balance consistency
  for (const [uid, wallet] of Object.entries(wallets)) {
    if (!wallet) continue;
    const ledger = wallet.ledger || {};

    let calcPurchased = 0;
    let calcConsumed = 0;
    let netAdjustments = 0;
    let netRefunds = 0;

    for (const [key, item] of Object.entries(ledger)) {
      if (!item) continue;
      if (item.type === 'purchase') {
        calcPurchased += (item.credits || 0);
        // Verify order exists
        const matchedOrder = Object.values(orders).find(o => o.paymentId === item.reference || key === 'purchase_' + o.id);
        if (!matchedOrder) {
          unmatchedTransactions.push({
            uid,
            ledgerKey: key,
            type: item.type,
            reference: item.reference,
            credits: item.credits,
            amountPaise: item.amountPaise,
            reason: 'Wallet purchase entry has no corresponding order record'
          });
        }
      } else if (item.type === 'accepted') {
        calcConsumed += 1;
      } else if (item.type === 'refund') {
        netRefunds += Math.abs(item.credits || 0);
      } else if (item.type === 'admin_adjustment' || item.type === 'explicit_dispute_adjustment') {
        netAdjustments += (item.credits || 0);
      }
    }

    // Mathematical integrity: balance + reserved = purchased - consumed + adjustments - refunds
    const recordedBalance = wallet.balance || 0;
    const recordedReserved = wallet.reserved || 0;
    const expectedBalance = Math.max(0, calcPurchased - calcConsumed + netAdjustments - netRefunds - recordedReserved);

    if (recordedBalance < 0 || recordedReserved < 0) {
      reconciliationErrors.push({
        uid,
        type: 'NEGATIVE_WALLET_BALANCE',
        balance: recordedBalance,
        reserved: recordedReserved
      });
    }
  }

  return {
    matched,
    missingWalletCredits,
    duplicatePaymentEvents,
    missingRefundEntries,
    unmatchedTransactions,
    reconciliationErrors,
    summary: {
      matchedCount: matched.length,
      missingCreditsCount: missingWalletCredits.length,
      duplicateEventsCount: duplicatePaymentEvents.length,
      missingRefundsCount: missingRefundEntries.length,
      unmatchedCount: unmatchedTransactions.length,
      errorsCount: reconciliationErrors.length,
      timestamp: Date.now()
    }
  };
}

/**
 * Resolves a financial mismatch with an authoritative audit entry.
 */
async function resolveReconciliationMismatch({ db, type, orderId, refundId, uid, action, reason, operationId, adminId }) {
  if (!reason || reason.trim().length < 5) {
    throw new Error('A detailed reason of at least 5 characters is required.');
  }
  if (!operationId || !/^[-a-zA-Z0-9_]{16,80}$/.test(operationId)) {
    throw new Error('A unique alphanumeric operation ID is required for idempotency.');
  }

  const now = Date.now();
  const ledgerKey = 'reconciliation_' + operationId;

  if (type === 'missing_credit') {
    const orderSnap = await db.ref('payment_orders/' + orderId).get();
    const order = orderSnap.val();
    if (!order) throw new Error('ORDER_NOT_FOUND');

    let applied = false;
    await db.ref('wallets/' + order.uid).transaction(w => {
      w = w || { balance: 0, reserved: 0, purchased: 0, consumed: 0 };
      w.paymentOrders = w.paymentOrders || {};
      w.ledger = w.ledger || {};

      if (w.ledger[ledgerKey]) return w;

      w.balance = (w.balance || 0) + order.credits;
      w.purchased = (w.purchased || 0) + order.credits;
      w.paymentOrders[orderId] = order.paymentId;
      w.ledger[ledgerKey] = {
        type: 'reconciliation_credit',
        credits: order.credits,
        amountPaise: order.amountPaise,
        reference: order.paymentId,
        orderId,
        adminId,
        reason: reason.trim(),
        createdAt: now
      };
      applied = true;
      return w;
    }, undefined, false);

    // Audit log
    await db.ref('admin_logs/' + crypto.randomUUID()).set({
      adminId,
      action: 'reconciliation.credit_applied',
      target: orderId,
      operationId,
      reason: reason.trim(),
      createdAt: now
    });

    return { success: true, action: 'credit_applied', orderId };
  } else if (type === 'missing_refund') {
    const refundSnap = await db.ref('payment_refunds/' + refundId).get();
    const refund = refundSnap.val();
    if (!refund) throw new Error('REFUND_NOT_FOUND');

    await db.ref('wallets/' + refund.uid).transaction(w => {
      w = w || { balance: 0, reserved: 0, purchased: 0, consumed: 0 };
      w.ledger = w.ledger || {};

      if (w.ledger[ledgerKey]) return w;

      const credits = refund.creditsToRecover || 0;
      w.balance = Math.max(0, (w.balance || 0) - credits);
      w.purchased = Math.max(0, (w.purchased || 0) - credits);
      w.ledger[ledgerKey] = {
        type: 'reconciliation_refund',
        credits: -credits,
        amountPaise: refund.amountPaise,
        reference: refund.id,
        orderId: refund.orderId,
        adminId,
        reason: reason.trim(),
        createdAt: now
      };
      return w;
    }, undefined, false);

    await db.ref('admin_logs/' + crypto.randomUUID()).set({
      adminId,
      action: 'reconciliation.refund_applied',
      target: refundId,
      operationId,
      reason: reason.trim(),
      createdAt: now
    });

    return { success: true, action: 'refund_applied', refundId };
  } else {
    throw new Error('UNKNOWN_RECONCILIATION_TYPE');
  }
}

module.exports = {
  performReconciliation,
  resolveReconciliationMismatch
};
