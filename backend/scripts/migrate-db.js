'use strict';
require('dotenv').config();
const admin = require('firebase-admin');

async function migrate() {
  if (!process.env.FIREBASE_DATABASE_URL || !process.env.FIREBASE_PROJECT_ID) {
    console.error('FIREBASE_DATABASE_URL and FIREBASE_PROJECT_ID are required.');
    process.exit(1);
  }

  const { createFirebaseDatabase } = require('../src/firebase-sync');
  const db = createFirebaseDatabase({
    databaseUrl: process.env.FIREBASE_DATABASE_URL
  });
  await db.ready();
  console.log('Running database migrations and setting defaults...');

  // Ensure platform_settings
  const settingsRef = db.ref('platform_settings');
  const snap = await settingsRef.get();
  const current = snap.val() || {};

  const updates = {};
  if (current.creditRate === undefined) updates['creditRate'] = 5;
  if (!current.retention) {
    updates['retention'] = {
      emailLogsDays: 90,
      recipientDataDays: 90,
      messageContentDays: 30,
      supportTicketsDays: 180,
      auditLogsDays: 365
    };
  }
  if (!current.rateLimits) {
    updates['rateLimits'] = {
      userLimit: 120,
      keyLimit: 60,
      ipLoginLimit: 20,
      paymentLimit: 10,
      apiKeyCreateLimit: 5,
      dailySendingLimit: 1000,
      adminLimit: 60
    };
  }

  if (Object.keys(updates).length > 0) {
    await settingsRef.update(updates);
    console.log('Default platform settings seeded:', updates);
  } else {
    console.log('Platform settings already up to date.');
  }

  console.log('Database migration complete.');
  process.exit(0);
}

if (require.main === module) {
  migrate().catch(err => {
    console.error('Migration failed:', err.message);
    process.exit(1);
  });
}

module.exports = { migrate };
