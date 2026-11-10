'use strict';
// Dry-run by default. This only deletes email_logs projections, not wallet jobs or provider data.
require('dotenv').config();
const { createFirebaseDatabase } = require('../src/firebase-sync');
const { RETENTION_MS } = require('../src/logs');

if (!process.env.FIREBASE_DATABASE_URL || !process.env.FIREBASE_PROJECT_ID) {
  throw new Error('Firebase configuration required');
}

(async () => {
  const db = createFirebaseDatabase({ databaseUrl: process.env.FIREBASE_DATABASE_URL });
  await db.ready();
  const snap = await db.ref('email_logs').get();
  const now = Date.now();
  const updates = {};
  const data = snap.val() || {};
  for (const [userKey, logs] of Object.entries(data)) {
    if (logs && typeof logs === 'object') {
      for (const [logKey, x] of Object.entries(logs)) {
        if (x && Number.isFinite(x.createdAt) && x.createdAt + RETENTION_MS <= now) {
          updates[`email_logs/${userKey}/${logKey}`] = null;
        }
      }
    }
  }
  const paths = Object.keys(updates);
  console.log(`${paths.length} expired log projections ${process.argv.includes('--apply') ? 'to delete' : 'would be deleted (dry run)'}`);
  if (process.argv.includes('--apply')) {
    for (let i = 0; i < paths.length; i += 250) {
      const batch = {};
      for (const p of paths.slice(i, i + 250)) batch[p] = null;
      await db.ref().update(batch);
    }
  }
  db.close();
  process.exit(0);
})().catch(err => {
  console.error('Log purge failed:', err.message);
  process.exit(1);
});
