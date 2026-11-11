'use strict';
const path = require('node:path');
require('dotenv').config({ path: path.join(__dirname, '../../.env') });
require('dotenv').config({ path: path.join(__dirname, '../.env') });
require('dotenv').config({ path: path.join(__dirname, '../../../.env') });
require('dotenv').config();
const { createApp } = require('./app');
const { createRateLimiter } = require('./limiter');
const { autoRecoverStuckJobs } = require('./recovery');
const { createFirebaseAuth } = require('./firebase-sync');
const { createFirebaseAdminRuntime } = require('./firebase-admin-runtime');

const fbDatabaseUrl = process.env.FIREBASE_DATABASE_URL || '';
const fbProjectId = process.env.FIREBASE_PROJECT_ID || '';
const fbApiKey = process.env.FIREBASE_WEB_API_KEY || '';
const sessionSecret = process.env.SESSION_SECRET;
const runtime = createFirebaseAdminRuntime({
  projectId: fbProjectId,
  databaseURL: fbDatabaseUrl,
  credentialPath: process.env.GOOGLE_APPLICATION_CREDENTIALS
});

// REST-based Firebase database fallback (no service account needed)
const { createFirebaseDatabase } = require('./firebase-sync');
const restDb = fbDatabaseUrl ? createFirebaseDatabase({ databaseUrl: fbDatabaseUrl }) : null;

// Database proxy: uses Admin SDK when connected, REST API otherwise
const db = {
  ref(referencePath = '') {
    if (runtime.getStatus().database.state === 'connected') {
      return runtime.db.ref(referencePath);
    }
    if (restDb) return restDb.ref(referencePath);
    return runtime.db.ref(referencePath);
  }
};

const auth = createFirebaseAuth({ projectId: fbProjectId, db, sessionSecret, adminAuth: runtime.adminAuth });
const connectionStatus = () => {
  const status = runtime.getStatus();
  if (!sessionSecret) {
    status.authentication = { ...status.authentication, state: 'unavailable', configured: false, reason: 'MISSING_SESSION_SECRET' };
  }
  return status;
};

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
  : sessionSecret ? require('node:crypto').createHash('sha256').update(sessionSecret).digest('base64') : null;

const sendingEnabled = process.env.ENABLE_EXPERIMENTAL_SENDING !== 'false' && Boolean(encryptionKey);
if (sendingEnabled) {
  if (process.env.REDIS_URL && connection) {
    try {
      const { Queue, Worker } = require('bullmq');
      const { runJob } = require('./sending');
      queue = new Queue('mailbridge-send', { connection });
      const worker = new Worker('mailbridge-send', async j => {
        await runtime.ready();
        if (runtime.getStatus().database.state !== 'connected' && !restDb) throw new Error('DATABASE_UNAVAILABLE');
        return runJob({
          db,
          key: encryptionKey,
          uid: j.data.uid,
          id: j.data.id
        });
      }, { connection, concurrency: 2 });

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
        await runtime.ready();
        if (runtime.getStatus().database.state !== 'connected' && !restDb) throw new Error('DATABASE_UNAVAILABLE');
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
    if (runtime.getStatus().database.state !== 'connected' && !restDb) return;
    autoRecoverStuckJobs(db).catch(err => console.error('Auto recovery error:', err.message));
  }, 60000);
  if (recoveryInterval.unref) recoveryInterval.unref();
}

const app = createApp({
  auth,
  db,
  connectionStatus,
  origins: (process.env.CORS_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean),
  publicConfig: {
    firebaseApiKey: fbApiKey,
    firebaseProjectId: fbProjectId,
    firebaseAuthDomain: process.env.FIREBASE_AUTH_DOMAIN || (fbProjectId ? fbProjectId + '.firebaseapp.com' : ''),
    firebaseDatabaseUrl: fbDatabaseUrl,
    firebaseConfig: {
      apiKey: fbApiKey,
      authDomain: process.env.FIREBASE_AUTH_DOMAIN || (fbProjectId ? fbProjectId + '.firebaseapp.com' : ''),
      databaseURL: fbDatabaseUrl,
      projectId: fbProjectId,
      storageBucket: process.env.FIREBASE_STORAGE_BUCKET || '',
      messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID || '',
      appId: process.env.FIREBASE_APP_ID || ''
    },
    devMode: false
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
    enabled: sendingEnabled,
    encryptionKey
  },
  sendQueue: queue,
  distributedLimiter: limiter
});

let server = null;
if (require.main === module) {
  const port = Number(process.env.PORT) || 3000;
  server = app.listen(port, '0.0.0.0', () => {
    console.log('MailBridge (Mail India) listening at http://localhost:' + port);
    console.log('Connection status: http://localhost:' + port + '/api/health');
    runtime.ready().then(() => {
      const status = connectionStatus();
      console.log('[FIREBASE DATABASE]', status.database.state, status.database.reason || '');
      console.log('[FIREBASE AUTH]', status.authentication.state, status.authentication.reason || '');
      if (status.database.state !== 'connected' && restDb) {
        console.log('[DATABASE FALLBACK] Using REST-based Firebase database (no service account)');
      }
    });
  });
}

app.app = app;
app.server = server;
app.firebaseRuntime = runtime;
module.exports = app;
