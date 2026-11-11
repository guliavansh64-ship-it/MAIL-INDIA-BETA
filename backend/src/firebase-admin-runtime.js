'use strict';
const fs = require('node:fs');
const path = require('node:path');

function unavailable(code, message) {
  return Object.assign(new Error(message), { code, status: 503 });
}

function bounded(operation, timeoutMs, code) {
  let timer;
  return Promise.race([
    Promise.resolve().then(operation),
    new Promise((_, reject) => { timer = setTimeout(() => reject(unavailable(code, 'Firebase connection check timed out.')), timeoutMs); })
  ]).finally(() => clearTimeout(timer));
}

function defaultSdk() {
  return {
    ...require('firebase-admin/app'),
    getDatabase: require('firebase-admin/database').getDatabase,
    getAuth: require('firebase-admin/auth').getAuth
  };
}

// All persistence is performed by official Admin SDK references and transactions.
// The wrapper only prevents operations from waiting on an unconfigured connection.
function createFirebaseAdminRuntime({
  projectId,
  databaseURL,
  credentialPath,
  sdk = defaultSdk(),
  readCredentialFile = file => fs.readFileSync(file, 'utf8'),
  probeTimeoutMs = 5000,
  probeIntervalMs = 60000,
  appName = 'mailbridge-runtime'
} = {}) {
  const state = {
    database: { provider: 'firebase-realtime-database', state: 'connecting', configured: false, reason: null, checkedAt: null },
    authentication: { provider: 'firebase-auth', state: 'connecting', configured: false, reason: null }
  };
  let nativeApp;
  let nativeDb;
  let nativeAuth;
  let closed = false;
  let monitor;
  let activeProbe;

  function markUnavailable(reason) {
    state.database.state = 'unavailable';
    state.database.reason = reason;
    state.database.checkedAt = Date.now();
  }

  const initialized = (async () => {
    if (!projectId || !databaseURL) {
      markUnavailable('MISSING_FIREBASE_CONFIG');
      state.authentication.state = 'unavailable';
      state.authentication.reason = 'MISSING_FIREBASE_CONFIG';
      return false;
    }
    try {
      const url = new URL(databaseURL);
      if (url.protocol !== 'https:' || !/\.(firebaseio\.com|firebasedatabase\.app)$/.test(url.hostname)) throw new Error('Invalid database URL');
    } catch {
      markUnavailable('INVALID_DATABASE_URL');
      state.authentication.state = 'unavailable';
      state.authentication.reason = 'INVALID_DATABASE_URL';
      return false;
    }
    let credential;
    try {
      if (credentialPath) {
        const serviceAccount = JSON.parse(readCredentialFile(path.resolve(credentialPath)));
        if (serviceAccount.type !== 'service_account' || !serviceAccount.client_email || !serviceAccount.private_key) throw new Error('Invalid service account');
        credential = sdk.cert(serviceAccount);
      } else if (process.env.FIREBASE_SERVICE_ACCOUNT_JSON || process.env.FIREBASE_SERVICE_ACCOUNT) {
        const rawJson = process.env.FIREBASE_SERVICE_ACCOUNT_JSON || process.env.FIREBASE_SERVICE_ACCOUNT;
        const serviceAccount = JSON.parse(rawJson);
        if (serviceAccount.type !== 'service_account' || !serviceAccount.client_email || !serviceAccount.private_key) throw new Error('Invalid service account');
        credential = sdk.cert(serviceAccount);
      } else {
        credential = sdk.applicationDefault();
      }
      const accessToken = await bounded(() => credential.getAccessToken(), probeTimeoutMs, 'ADMIN_CREDENTIALS_TIMEOUT');
      if (!accessToken?.access_token) throw new Error('Admin credentials did not provide an access token');
    } catch (err) {
      const reason = err.code === 'ADMIN_CREDENTIALS_TIMEOUT' ? err.code : 'ADMIN_CREDENTIALS_UNAVAILABLE';
      markUnavailable(reason);
      state.authentication.state = 'unavailable';
      state.authentication.reason = reason;
      return false;
    }
    if (closed) return false;
    try {
      nativeApp = sdk.initializeApp({ projectId, databaseURL, credential }, appName);
      nativeDb = sdk.getDatabase(nativeApp);
      nativeAuth = sdk.getAuth(nativeApp);
      state.database.configured = true;
      state.authentication = { provider: 'firebase-auth', state: 'ready', configured: true, reason: null };
      return true;
    } catch {
      markUnavailable('FIREBASE_INITIALIZATION_FAILED');
      state.authentication.state = 'unavailable';
      state.authentication.reason = 'FIREBASE_INITIALIZATION_FAILED';
      return false;
    }
  })();

  async function probe() {
    if (!await initialized || closed) return false;
    if (activeProbe) return activeProbe;
    activeProbe = (async () => {
      try {
        await bounded(() => nativeDb.ref('platform_settings').get(), probeTimeoutMs, 'DATABASE_TIMEOUT');
        if (closed) return false;
        state.database.state = 'connected';
        state.database.reason = null;
        state.database.checkedAt = Date.now();
        return true;
      } catch (err) {
        if (closed) return false;
        const denied = /PERMISSION_DENIED|permission.denied/i.test(String(err.code || err.message));
        markUnavailable(err.code === 'DATABASE_TIMEOUT' ? err.code : denied ? 'DATABASE_ACCESS_DENIED' : 'DATABASE_UNAVAILABLE');
        return false;
      } finally {
        activeProbe = null;
      }
    })();
    return activeProbe;
  }

  const readyPromise = probe();
  readyPromise.then(() => {
    if (!closed && nativeDb && probeIntervalMs > 0) {
      monitor = setInterval(() => { probe().catch(() => {}); }, probeIntervalMs);
      monitor.unref?.();
    }
  });

  function connectedDatabase() {
    if (closed || state.database.state !== 'connected') {
      throw unavailable('DATABASE_UNAVAILABLE', 'Firebase Realtime Database is unavailable. Check the backend connection configuration.');
    }
    return nativeDb;
  }

  function reference(resolve, referencePath) {
    const ref = {
      key: referencePath ? referencePath.split('/').filter(Boolean).at(-1) : null,
      child(childPath) {
        return reference(db => resolve(db).child(childPath), [referencePath, childPath].filter(Boolean).join('/'));
      },
      push(...args) {
        return resolve(connectedDatabase()).push(...args);
      }
    };
    for (const method of ['get', 'once', 'set', 'update', 'remove', 'transaction']) {
      ref[method] = async (...args) => resolve(connectedDatabase())[method](...args);
    }
    for (const method of ['orderByChild', 'orderByKey', 'orderByValue', 'equalTo', 'startAt', 'endAt', 'limitToFirst', 'limitToLast']) {
      ref[method] = (...args) => reference(db => resolve(db)[method](...args), referencePath);
    }
    return ref;
  }

  const db = {
    ref(referencePath = '') { return reference(database => database.ref(referencePath), referencePath); }
  };
  const adminAuth = {};
  for (const method of ['verifyIdToken', 'generateEmailVerificationLink', 'getUserByEmail', 'updateUser', 'getUser']) {
    adminAuth[method] = async (...args) => {
      if (!await initialized || closed || !nativeAuth) {
        throw unavailable('AUTH_UNAVAILABLE', 'Firebase Admin credentials are unavailable. Check the backend connection configuration.');
      }
      return nativeAuth[method](...args);
    };
  }

  return {
    db,
    adminAuth,
    ready: () => readyPromise,
    checkConnection: probe,
    getStatus: () => structuredClone(state),
    async close() {
      closed = true;
      clearInterval(monitor);
      markUnavailable('CONNECTION_CLOSED');
      state.authentication.state = 'unavailable';
      state.authentication.reason = 'CONNECTION_CLOSED';
      await initialized;
      if (nativeApp) await sdk.deleteApp(nativeApp);
    }
  };
}

module.exports = { createFirebaseAdminRuntime };
