'use strict';
require('dotenv').config();
const fs = require('node:fs');
const path = require('node:path');
const admin = require('firebase-admin');

async function restore(backupFilePath) {
  if (!backupFilePath || !fs.existsSync(backupFilePath)) {
    console.error('Usage: node restore-db.js <path-to-backup.json>');
    process.exit(1);
  }

  if (!process.env.FIREBASE_DATABASE_URL || !process.env.FIREBASE_PROJECT_ID) {
    console.error('FIREBASE_DATABASE_URL and FIREBASE_PROJECT_ID are required.');
    process.exit(1);
  }

  const raw = fs.readFileSync(backupFilePath, 'utf8');
  const data = JSON.parse(raw);

  const { createFirebaseDatabase } = require('../src/firebase-sync');
  const db = createFirebaseDatabase({
    databaseUrl: process.env.FIREBASE_DATABASE_URL
  });
  await db.ready();
  console.log(`Restoring database from ${backupFilePath}...`);
  await db.ref().set(data);
  console.log('Database restore completed successfully.');
  process.exit(0);
}

if (require.main === module) {
  const fileArg = process.argv[2];
  restore(fileArg).catch(err => {
    console.error('Restore failed:', err.message);
    process.exit(1);
  });
}

module.exports = { restore };
