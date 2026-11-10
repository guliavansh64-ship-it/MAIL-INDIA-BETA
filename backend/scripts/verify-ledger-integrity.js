'use strict';
require('dotenv').config();
const admin = require('firebase-admin');

async function verifyLedgerIntegrity(dbInstance) {
  let db = dbInstance;
  if (!db) {
    if (!process.env.FIREBASE_DATABASE_URL || !process.env.FIREBASE_PROJECT_ID) {
      console.error('FIREBASE_DATABASE_URL and FIREBASE_PROJECT_ID are required.');
      process.exit(1);
    }
    const { createFirebaseDatabase } = require('../src/firebase-sync');
    db = createFirebaseDatabase({
      databaseUrl: process.env.FIREBASE_DATABASE_URL
    });
    await db.ready();
  }

  const [walletsSnap, ordersSnap, refundsSnap] = await Promise.all([
    db.ref('wallets').get(),
    db.ref('payment_orders').get(),
    db.ref('payment_refunds').get()
  ]);

  const wallets = walletsSnap.val() || {};
  const orders = ordersSnap.val() || {};
  const refunds = refundsSnap.val() || {};

  const issues = [];
  let totalWalletsChecked = 0;
  let totalCreditsAudited = 0;

  for (const [uid, wallet] of Object.entries(wallets)) {
    if (!wallet) continue;
    totalWalletsChecked++;

    const balance = wallet.balance || 0;
    const reserved = wallet.reserved || 0;
    const purchased = wallet.purchased || 0;
    const consumed = wallet.consumed || 0;

    totalCreditsAudited += purchased;

    if (balance < 0) {
      issues.push({ uid, error: 'NEGATIVE_BALANCE', balance });
    }
    if (reserved < 0) {
      issues.push({ uid, error: 'NEGATIVE_RESERVED', reserved });
    }

    const ledger = wallet.ledger || {};
    let calcPurchased = 0;
    let calcConsumed = 0;
    let netAdjustments = 0;
    let netRefunds = 0;

    for (const [key, item] of Object.entries(ledger)) {
      if (!item) continue;
      if (item.type === 'purchase') {
        calcPurchased += (item.credits || 0);
      } else if (item.type === 'accepted') {
        calcConsumed += 1;
      } else if (item.type === 'refund') {
        netRefunds += Math.abs(item.credits || 0);
      } else if (item.type === 'admin_adjustment' || item.type === 'reconciliation_credit') {
        netAdjustments += (item.credits || 0);
      } else if (item.type === 'reconciliation_refund' || item.type === 'dispute_hold') {
        netAdjustments -= Math.abs(item.credits || 0);
      }
    }

    // Verify mathematical integrity
    const expectedAvailable = Math.max(0, calcPurchased - calcConsumed + netAdjustments - netRefunds - reserved);
    if (balance !== expectedAvailable) {
      issues.push({
        uid,
        error: 'BALANCE_LEDGER_MISMATCH',
        recordedBalance: balance,
        expectedBalance: expectedAvailable,
        calcPurchased,
        calcConsumed,
        netAdjustments,
        netRefunds,
        reserved
      });
    }
  }

  const result = {
    valid: issues.length === 0,
    walletsChecked: totalWalletsChecked,
    creditsAudited: totalCreditsAudited,
    issuesCount: issues.length,
    issues
  };

  console.log(`Audited ${totalWalletsChecked} wallets with ${totalCreditsAudited} total credits.`);
  if (result.valid) {
    console.log('✓ All financial ledger records are mathematically consistent.');
  } else {
    console.warn(`⚠ Found ${issues.length} ledger integrity issues:`, issues);
  }

  return result;
}

if (require.main === module) {
  verifyLedgerIntegrity().then(res => {
    process.exit(res.valid ? 0 : 1);
  }).catch(err => {
    console.error('Integrity audit failed:', err.message);
    process.exit(1);
  });
}

module.exports = { verifyLedgerIntegrity };
