'use strict';
require('dotenv').config();
const fs = require('node:fs');
const path = require('node:path');
const admin = require('firebase-admin');

async function backup() {
  if (!process.env.FIREBASE_DATABASE_URL || !process.env.FIREBASE_PROJECT_ID) {
    console.error('FIREBASE_DATABASE_URL and FIREBASE_PROJECT_ID are required.');
    process.exit(1);
  }

  const { createFirebaseDatabase } = require('../src/firebase-sync');
  const db = createFirebaseDatabase({
    databaseUrl: process.env.FIREBASE_DATABASE_URL
  });
  await db.ready();
  console.log('Exporting database snapshot...');
  const snapshot = await db.ref().get();
  const data = snapshot.val() || {};

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const backupDir = path.join(__dirname, '../backups');
  if (!fs.existsSync(backupDir)) fs.mkdirSync(backupDir, { recursive: true });

  const backupPath = path.join(backupDir, `mailbridge-backup-${timestamp}.json`);
  fs.writeFileSync(backupPath, JSON.stringify(data, null, 2), 'utf8');

  console.log(`Backup completed successfully: ${backupPath}`);
  console.log(`Collections exported: ${Object.keys(data).join(', ')}`);
  process.exit(0);
}

if (require.main === module) {
  backup().catch(err => {
    console.error('Backup failed:', err.message);
    process.exit(1);
  });
}

module.exports = { backup };
