'use strict';
const path = require('node:path');
require('dotenv').config({ path: path.join(__dirname, '../../.env') });
require('dotenv').config({ path: path.join(__dirname, '../.env') });
require('dotenv').config();
const { createApp } = require('./app');
const { createRateLimiter } = require('./limiter');
const { autoRecoverStuckJobs } = require('./recovery');
const { createLocalDatabase, createLocalAuth } = require('./local-dev');
const { createFirebaseDatabase, createFirebaseAuth } = require('./firebase-sync');

let auth = null;
let db = null;
let isDev = false;

if (process.env.FIREBASE_DATABASE_URL && process.env.FIREBASE_PROJECT_ID) {
  try {
    db = createFirebaseDatabase({
      databaseUrl: process.env.FIREBASE_DATABASE_URL
    });
    auth = createFirebaseAuth({
      projectId: process.env.FIREBASE_PROJECT_ID,
      apiKey: process.env.FIREBASE_WEB_API_KEY,
      db,
      sessionSecret: process.env.SESSION_SECRET || 'mailbridge-session-secure-secret-key-375ee'
    });
    isDev = false;
    console.log(`[FIREBASE] Connected to Firebase Project: ${process.env.FIREBASE_PROJECT_ID}`);
    console.log(`[FIREBASE] Realtime Database: ${process.env.FIREBASE_DATABASE_URL}`);
    console.log(`[FIREBASE] Live data synchronization active. No demo data loaded.`);
  } catch (err) {
    console.warn(`[FIREBASE] Firebase initialization failed (${err.message}). Starting in fallback mode.`);
  }
}

if (!auth || !db) {
  isDev = true;
  console.log('[DEV MODE] Firebase credentials not configured. Starting in Standalone Local Mode.');
  db = createLocalDatabase();
  auth = createLocalAuth();
}

let queue = null, limiter = null, connection = null;

if (process.env.REDIS_URL) {
  const IORedis = require('ioredis');
  connection = new IORedis(process.env.REDIS_URL, { maxRetriesPerRequest: null, enableOfflineQueue: false });
  connection.on('error', () => console.error('Redis connection error'));
  limiter = createRateLimiter(connection);
} else {
  // In-memory distributed-compatible limiter fallback
  limiter = createRateLimiter(null);
}

const encryptionKey = (process.env.SENDER_ENCRYPTION_KEY && Buffer.from(process.env.SENDER_ENCRYPTION_KEY, 'base64').length === 32)
  ? process.env.SENDER_ENCRYPTION_KEY
  : require('node:crypto').createHash('sha256').update(process.env.SESSION_SECRET || 'mailbridge-master-session-salt-375ee').digest('base64');

if (process.env.ENABLE_EXPERIMENTAL_SENDING === 'true') {
  if (process.env.REDIS_URL && connection) {
    try {
      const { Queue, Worker } = require('bullmq');
      const { runJob } = require('./sending');
      queue = new Queue('mailbridge-send', { connection });
      const worker = new Worker('mailbridge-send', async j => runJob({
        db,
        key: encryptionKey,
        uid: j.data.uid,
        id: j.data.id
      }), { connection, concurrency: 2 });

      worker.on('failed', () => console.error('Email job failed; manual reconciliation may be required.'));
      worker.on('error', () => console.error('Email worker error'));
    } catch (err) {
      console.warn('[BULLMQ QUEUE] Redis BullMQ setup failed, falling back to in-process queue:', err.message);
    }
  }

  // Resilient in-process asynchronous queue fallback if Redis is not running
  if (!queue) {
    const { runJob } = require('./sending');
    queue = {
      async add(name, data, options) {
        setImmediate(async () => {
          try {
            await runJob({
              db,
              key: encryptionKey,
              uid: data.uid,
              id: data.id
            });
          } catch (err) {
            console.error('[ASYNC SEND JOB ERROR]', err.message);
          }
        });
        return { id: options?.jobId || data.id };
      }
    };
    console.log('[SEND QUEUE] Active (In-Process Asynchronous Dispatcher)');
  }

  // Periodic automatic stuck job recovery runner
  const recoveryInterval = setInterval(() => {
    autoRecoverStuckJobs(db).catch(err => console.error('Auto recovery error:', err.message));
  }, 60000);
  if (recoveryInterval.unref) recoveryInterval.unref();
}

const app = createApp({
  auth,
  db,
  origins: (process.env.CORS_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean),
  publicConfig: {
    firebaseApiKey: process.env.FIREBASE_WEB_API_KEY || 'AIzaSyCvfIXHa_6Vy5Qh2Of-ayhUjw1INwujmsE',
    firebaseProjectId: process.env.FIREBASE_PROJECT_ID || 'to-375ee',
    firebaseAuthDomain: process.env.FIREBASE_AUTH_DOMAIN || 'to-375ee.firebaseapp.com',
    firebaseDatabaseUrl: process.env.FIREBASE_DATABASE_URL || 'https://to-375ee-default-rtdb.firebaseio.com',
    firebaseStorageBucket: process.env.FIREBASE_STORAGE_BUCKET || 'to-375ee.firebasestorage.app',
    firebaseMessagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID || '555488380029',
    firebaseAppId: process.env.FIREBASE_APP_ID || '1:555488380029:web:588046ca97420a868d5d14',
    firebaseConfig: {
      apiKey: process.env.FIREBASE_WEB_API_KEY || 'AIzaSyCvfIXHa_6Vy5Qh2Of-ayhUjw1INwujmsE',
      authDomain: process.env.FIREBASE_AUTH_DOMAIN || 'to-375ee.firebaseapp.com',
      databaseURL: process.env.FIREBASE_DATABASE_URL || 'https://to-375ee-default-rtdb.firebaseio.com',
      projectId: process.env.FIREBASE_PROJECT_ID || 'to-375ee',
      storageBucket: process.env.FIREBASE_STORAGE_BUCKET || 'to-375ee.firebasestorage.app',
      messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID || '555488380029',
      appId: process.env.FIREBASE_APP_ID || '1:555488380029:web:588046ca97420a868d5d14'
    },
    devMode: isDev
  },
  paymentConfig: {
    enabled: process.env.ENABLE_EXPERIMENTAL_PAYMENTS === 'true',
    keyId: process.env.RAZORPAY_KEY_ID,
    keySecret: process.env.RAZORPAY_KEY_SECRET,
    webhookSecret: process.env.RAZORPAY_WEBHOOK_SECRET
  },
  zetpayConfig: {
    apiKey: process.env.ZETPAY_API_KEY || 'ZPPCCkPtfAH7EC78UMNT8kUqm7q5XdjNRSX',
    baseUrl: process.env.ZETPAY_BASE_URL || 'https://zetpay-beta.vercel.app'
  },
  sendingConfig: {
    enabled: process.env.ENABLE_EXPERIMENTAL_SENDING === 'true',
    encryptionKey: (process.env.SENDER_ENCRYPTION_KEY && Buffer.from(process.env.SENDER_ENCRYPTION_KEY, 'base64').length === 32)
      ? process.env.SENDER_ENCRYPTION_KEY
      : require('node:crypto').createHash('sha256').update(process.env.SESSION_SECRET || 'mailbridge-master-session-salt-375ee').digest('base64')
  },
  sendQueue: queue,
  distributedLimiter: limiter
});

let server = null;
if (require.main === module) {
  const port = Number(process.env.PORT) || 3000;
  server = app.listen(port, '0.0.0.0', async () => {
    if (db && typeof db.ready === 'function') {
      await db.ready();
    }
    console.log(`=================================================`);
    console.log(`MailBridge (Mail India) Server listening on ${port}`);
    console.log(`Dashboard URL:  http://localhost:${port}`);
    console.log(`Health Check:   http://localhost:${port}/api/health`);
    console.log(`Firebase:       CONNECTED (${process.env.FIREBASE_PROJECT_ID || 'to-375ee'})`);
    console.log(`RTDB Sync:      ACTIVE (${process.env.FIREBASE_DATABASE_URL || 'https://to-375ee-default-rtdb.firebaseio.com'})`);
    console.log(`Demo Data:      DISABLED (Live Firebase Data Only)`);
    console.log(`ZetPay UPI:     CONNECTED (Key: ${process.env.ZETPAY_API_KEY || 'ZPPCCkPtfAH7EC78UMNT8kUqm7q5XdjNRSX'})`);
    console.log(`=================================================`);
  });
}

app.app = app;
app.server = server;
module.exports = app;
