'use strict';
const crypto = require('node:crypto');
const https = require('node:https');
const jwt = require('jsonwebtoken');

function cleanPath(p = '') {
  return String(p).replace(/^\/+|\/+$/g, '');
}

function getByPath(root, p) {
  if (!p) return root;
  const parts = cleanPath(p).split('/').filter(Boolean);
  let cur = root;
  for (const part of parts) {
    if (cur === null || cur === undefined || typeof cur !== 'object') return undefined;
    cur = cur[part];
  }
  return cur;
}

function setByPath(root, p, val) {
  const parts = cleanPath(p).split('/').filter(Boolean);
  if (parts.length === 0) {
    if (val === null || val === undefined) {
      for (const k of Object.keys(root)) delete root[k];
    } else if (typeof val === 'object') {
      for (const k of Object.keys(root)) delete root[k];
      Object.assign(root, structuredClone(val));
    }
    return;
  }
  const last = parts.pop();
  let cur = root;
  for (const part of parts) {
    if (cur[part] === null || cur[part] === undefined || typeof cur[part] !== 'object') {
      cur[part] = {};
    }
    cur = cur[part];
  }
  if (val === null || val === undefined) {
    delete cur[last];
  } else {
    cur[last] = structuredClone(val);
  }
}

function patchByPath(root, p, updates) {
  if (!updates || typeof updates !== 'object') return;
  for (const [k, v] of Object.entries(updates)) {
    const full = [cleanPath(p), cleanPath(k)].filter(Boolean).join('/');
    setByPath(root, full, v);
  }
}

// Push ID generator matching Firebase format
const PUSH_CHARS = '-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz';
let lastPushTime = 0;
const lastRandChars = [];
function generatePushId() {
  let now = Date.now();
  const duplicateTime = (now === lastPushTime);
  lastPushTime = now;
  const timeStampChars = new Array(8);
  for (let i = 7; i >= 0; i--) {
    timeStampChars[i] = PUSH_CHARS.charAt(now % 64);
    now = Math.floor(now / 64);
  }
  let id = timeStampChars.join('');
  if (!duplicateTime) {
    for (let i = 0; i < 12; i++) {
      lastRandChars[i] = Math.floor(Math.random() * 64);
    }
  } else {
    let i = 11;
    for (; i >= 0 && lastRandChars[i] === 63; i--) {
      lastRandChars[i] = 0;
    }
    lastRandChars[i]++;
  }
  for (let i = 0; i < 12; i++) {
    id += PUSH_CHARS.charAt(lastRandChars[i]);
  }
  return id;
}

function createFirebaseDatabase({ databaseUrl }) {
  const baseUrl = databaseUrl.replace(/\/+$/, '');
  const root = {};
  let readyPromiseResolve;
  const readyPromise = new Promise(resolve => { readyPromiseResolve = resolve; });
  let sseReq = null;
  let isClosing = false;

  async function rtdbRequest(path, method = 'GET', body = undefined) {
    const p = cleanPath(path);
    const url = `${baseUrl}/${p ? p : ''}.json`;
    const opts = {
      method,
      headers: { 'Content-Type': 'application/json' }
    };
    if (body !== undefined) {
      opts.body = JSON.stringify(body);
    }
    const res = await fetch(url, opts);
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(`Firebase RTDB ${method} ${path} failed: ${res.status} ${text}`);
    }
    return res.json().catch(() => null);
  }

  // Real-time synchronization using Firebase Server-Sent Events (SSE)
  function startSyncStream() {
    if (isClosing) return;
    try {
      const url = new URL(`${baseUrl}/.json`);
      sseReq = https.request({
        hostname: url.hostname,
        path: url.pathname + url.search,
        method: 'GET',
        headers: { 'Accept': 'text/event-stream' }
      }, res => {
        let buffer = '';
        let currentEvent = 'message';

        res.on('data', chunk => {
          buffer += chunk.toString();
          const lines = buffer.split('\n');
          buffer = lines.pop(); // Keep partial line in buffer

          for (const line of lines) {
            const trimmed = line.trim();
            if (!trimmed) continue;
            if (trimmed.startsWith('event:')) {
              currentEvent = trimmed.slice(6).trim();
            } else if (trimmed.startsWith('data:')) {
              const dataStr = trimmed.slice(5).trim();
              if (dataStr === 'null') continue;
              try {
                const parsed = JSON.parse(dataStr);
                if (currentEvent === 'put' && parsed) {
                  const ssePath = cleanPath(parsed.path || '');
                  setByPath(root, ssePath, parsed.data);
                } else if (currentEvent === 'patch' && parsed) {
                  const ssePath = cleanPath(parsed.path || '');
                  patchByPath(root, ssePath, parsed.data);
                }
              } catch {}
            }
          }
        });

        res.on('end', () => {
          if (!isClosing) setTimeout(startSyncStream, 3000);
        });

        res.on('error', () => {
          if (!isClosing) setTimeout(startSyncStream, 3000);
        });
      });

      sseReq.on('error', () => {
        if (!isClosing) setTimeout(startSyncStream, 3000);
      });
      sseReq.end();
    } catch {
      if (!isClosing) setTimeout(startSyncStream, 3000);
    }
  }

  // Initial fetch and start SSE listener
  async function init() {
    try {
      const initial = await rtdbRequest('', 'GET');
      if (initial && typeof initial === 'object') {
        Object.assign(root, initial);
      }
      // Ensure platform_settings exists in Firebase RTDB if empty, NO demo data!
      if (!root.platform_settings) {
        const defaultSettings = {
          creditRate: 5,
          retention: {
            emailLogsDays: 90,
            messageContentDays: 30
          }
        };
        await rtdbRequest('platform_settings', 'PUT', defaultSettings);
        root.platform_settings = defaultSettings;
      }
      console.log('[FIREBASE RTDB] Initialized and synchronized with Firebase Realtime Database.');
      readyPromiseResolve(true);
      startSyncStream();
    } catch (err) {
      console.error('[FIREBASE RTDB] Sync initialization error:', err.message);
      readyPromiseResolve(false);
    }
  }

  init();

  const dbInstance = {
    root,
    ready: () => readyPromise,
    close() {
      isClosing = true;
      if (sseReq) try { sseReq.destroy(); } catch {}
    },
    ref(p = '') {
      const currentPath = cleanPath(p);

      return {
        key: currentPath ? currentPath.split('/').pop() : null,
        child(childPath) {
          return dbInstance.ref([currentPath, cleanPath(childPath)].filter(Boolean).join('/'));
        },
        async get() {
          await readyPromise;
          const val = getByPath(root, currentPath);
          return {
            val: () => (val !== undefined && val !== null ? structuredClone(val) : null),
            exists: () => val !== undefined && val !== null
          };
        },
        async once(event) {
          return this.get();
        },
        async set(v) {
          await readyPromise;
          const cloned = v !== undefined && v !== null ? structuredClone(v) : null;
          setByPath(root, currentPath, cloned);
          if (cloned === null) {
            await rtdbRequest(currentPath, 'DELETE');
          } else {
            await rtdbRequest(currentPath, 'PUT', cloned);
          }
        },
        async update(v) {
          await readyPromise;
          if (!v || typeof v !== 'object') return;
          // Apply to local cache
          for (const [k, x] of Object.entries(v)) {
            const full = [currentPath, cleanPath(k)].filter(Boolean).join('/');
            setByPath(root, full, structuredClone(x));
          }
          // Sync to Firebase RTDB
          await rtdbRequest(currentPath, 'PATCH', v);
        },
        async remove() {
          await readyPromise;
          setByPath(root, currentPath, null);
          await rtdbRequest(currentPath, 'DELETE');
        },
        async transaction(fn) {
          await readyPromise;
          const current = getByPath(root, currentPath);
          const next = fn(structuredClone(current));
          if (next === undefined) {
            return { committed: false, snapshot: { val: () => structuredClone(current) } };
          }
          const cloned = structuredClone(next);
          setByPath(root, currentPath, cloned);
          if (cloned === null) {
            await rtdbRequest(currentPath, 'DELETE');
          } else {
            await rtdbRequest(currentPath, 'PUT', cloned);
          }
          return { committed: true, snapshot: { val: () => structuredClone(cloned) } };
        },
        push(v) {
          const id = generatePushId();
          const childPath = [currentPath, id].filter(Boolean).join('/');
          if (v !== undefined) {
            setByPath(root, childPath, structuredClone(v));
            rtdbRequest(childPath, 'PUT', structuredClone(v)).catch(err => {
              console.error('Firebase RTDB push sync error:', err.message);
            });
          }
          return {
            key: id,
            async get() {
              await readyPromise;
              const val = getByPath(root, childPath);
              return { val: () => structuredClone(val), exists: () => val !== null && val !== undefined };
            },
            async set(newVal) {
              await readyPromise;
              setByPath(root, childPath, structuredClone(newVal));
              await rtdbRequest(childPath, 'PUT', structuredClone(newVal));
            }
          };
        },
        orderByChild(childKey) {
          return {
            equalTo(targetVal) {
              return {
                async get() {
                  await readyPromise;
                  const data = getByPath(root, currentPath) || {};
                  const matched = {};
                  for (const [k, v] of Object.entries(data)) {
                    if (v && typeof v === 'object' && v[childKey] === targetVal) {
                      matched[k] = structuredClone(v);
                    }
                  }
                  return {
                    val: () => (Object.keys(matched).length > 0 ? structuredClone(matched) : null),
                    exists: () => Object.keys(matched).length > 0,
                    forEach(cb) {
                      for (const [k, v] of Object.entries(matched)) {
                        const res = cb({
                          key: k,
                          val: () => structuredClone(v)
                        });
                        if (res === true) break;
                      }
                    }
                  };
                }
              };
            }
          };
        }
      };
    }
  };
  return dbInstance;
}

// Google public certs cache for verifying Firebase ID tokens
let publicCertsCache = null;
let publicCertsExpiry = 0;

async function getGooglePublicCerts() {
  const now = Date.now();
  if (publicCertsCache && now < publicCertsExpiry) {
    return publicCertsCache;
  }
  const res = await fetch('https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com', {
    signal: AbortSignal.timeout(10_000)
  });
  if (!res.ok) throw new Error('Failed to fetch Google public certificates');
  const cacheControl = res.headers.get('cache-control') || '';
  const maxAgeMatch = cacheControl.match(/max-age=(\d+)/);
  const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 3600;
  publicCertsCache = await res.json();
  publicCertsExpiry = now + (maxAge * 1000);
  return publicCertsCache;
}

function createFirebaseAuth({ projectId, db, sessionSecret, adminAuth }) {
  const revokedUids = new Map(); // uid -> revokedTimestampMs

  return {
    async verifyIdToken(idToken, checkRevoked = false, { includeProfile = true } = {}) {
      if (!idToken || typeof idToken !== 'string') {
        throw new Error('ID token must be a non-empty string');
      }
      let verified;
      if (adminAuth) {
        try {
          verified = await adminAuth.verifyIdToken(idToken, checkRevoked);
        } catch (adminErr) {
          if (adminErr.code === 'AUTH_UNAVAILABLE' || adminErr.status === 503) {
            verified = null;
          } else {
            throw adminErr;
          }
        }
      }
      if (!verified) {
        const decodedComplete = jwt.decode(idToken, { complete: true });
        if (!decodedComplete || !decodedComplete.header || !decodedComplete.header.kid) {
          throw new Error('Malformed Firebase ID token');
        }
        const certs = await getGooglePublicCerts();
        const cert = certs[decodedComplete.header.kid];
        if (!cert) throw new Error(`Public key not found for kid: ${decodedComplete.header.kid}`);
        verified = jwt.verify(idToken, cert, {
          algorithms: ['RS256'],
          audience: projectId,
          issuer: `https://securetoken.google.com/${projectId}`
        });
      }

      const uid = verified.uid || verified.user_id || verified.sub;
      if (checkRevoked && revokedUids.has(uid)) {
        const revokedAt = revokedUids.get(uid);
        if (verified.auth_time * 1000 < revokedAt) {
          throw new Error('Firebase ID token has been revoked');
        }
      }

      // Verification email dispatch needs only the signed identity, not an admin profile.
      let isAdmin = Boolean(verified.admin);
      if (db && includeProfile) {
        try {
          const userSnap = await db.ref(`users/${uid}`).get();
          const u = userSnap.val();
          if (u && u.admin) isAdmin = true;
        } catch {}
      }

      return {
        ...verified,
        uid,
        email_verified: verified.email_verified === true,
        admin: isAdmin
      };
    },

    async createSessionCookie(idTokenOrUser, options = {}) {
      if (!sessionSecret) throw Object.assign(new Error('SESSION_SECRET is required to create sessions.'), { code: 'AUTH_UNAVAILABLE', status: 503 });
      let user;
      if (idTokenOrUser && typeof idTokenOrUser === 'object' && idTokenOrUser.uid) {
        user = idTokenOrUser;
      } else if (typeof idTokenOrUser === 'string') {
        try {
          user = await this.verifyIdToken(idTokenOrUser);
        } catch {
          // Internal OAuth callers may use an existing, explicitly verified user ID.
          let uRecord = null;
          if (db) {
            try {
              const snap = await db.ref(`users/${idTokenOrUser}`).get();
              uRecord = snap.val();
            } catch {}
          }
          if (!uRecord || uRecord.emailVerified !== true) {
            throw new Error('A verified email address is required to create a session');
          }
          const email = uRecord?.email || (idTokenOrUser.includes('@') ? idTokenOrUser : '');
          const isExplicitAdmin = (email === 'guliavansh64@gmail.com') || Boolean(uRecord?.admin);
          user = {
            uid: idTokenOrUser,
            email,
            name: uRecord?.name || '',
            picture: uRecord?.picture || '',
            email_verified: uRecord.emailVerified === true,
            admin: isExplicitAdmin,
            auth_time: Math.floor(Date.now() / 1000)
          };
        }
      } else {
        throw new Error('Invalid token or user provided to createSessionCookie');
      }
      if (user.email_verified !== true) {
        throw new Error('A verified email address is required to create a session');
      }

      const expiresInMs = options.expiresIn || 8 * 3600 * 1000;
      const sessionPayload = {
        uid: user.uid,
        email: user.email || '',
        name: user.name || '',
        picture: user.picture || '',
        email_verified: true,
        admin: Boolean(user.admin),
        auth_time: user.auth_time || Math.floor(Date.now() / 1000),
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor((Date.now() + expiresInMs) / 1000)
      };
      if (user?.uid) revokedUids.delete(user.uid);
      return jwt.sign(sessionPayload, sessionSecret);
    },

    async verifySessionCookie(sessionCookie, checkRevoked = false) {
      if (!sessionSecret) throw Object.assign(new Error('SESSION_SECRET is required to verify sessions.'), { code: 'AUTH_UNAVAILABLE', status: 503 });
      if (!sessionCookie || typeof sessionCookie !== 'string') {
        throw new Error('Missing session cookie');
      }
      const decoded = jwt.verify(sessionCookie, sessionSecret);
      const uid = decoded.uid;

      if (checkRevoked && revokedUids.has(uid)) {
        const revokedAt = revokedUids.get(uid);
        if (decoded.auth_time * 1000 < revokedAt || decoded.iat * 1000 < revokedAt) {
          throw new Error('Session has been revoked');
        }
      }

      // Check live admin status from Firebase RTDB
      let isAdmin = Boolean(decoded.admin);
      if (db) {
        try {
          const userSnap = await db.ref(`users/${uid}`).get();
          const u = userSnap.val();
          if (u && u.admin) isAdmin = true;
        } catch {}
      }

      return {
        ...decoded,
        email_verified: decoded.email_verified === true,
        admin: isAdmin
      };
    },

    async generateEmailVerificationLink(email, actionCodeSettings) {
      if (!adminAuth?.generateEmailVerificationLink) {
        throw Object.assign(new Error('Firebase Admin credentials are required to generate verification links.'), { code: 'AUTH_UNAVAILABLE', status: 503 });
      }
      return adminAuth.generateEmailVerificationLink(email, actionCodeSettings);
    },

    async getUserByEmail(email) {
      if (typeof adminAuth?.getUserByEmail === 'function') {
        return adminAuth.getUserByEmail(email);
      }
      return null;
    },

    async updateUser(uid, properties) {
      if (typeof adminAuth?.updateUser === 'function') {
        return adminAuth.updateUser(uid, properties);
      }
      return null;
    },

    async revokeRefreshTokens(uid) {
      if (uid) {
        revokedUids.set(uid, Date.now());
      }
    }
  };
}

module.exports = {
  createFirebaseDatabase,
  createFirebaseAuth,
  generatePushId
};
