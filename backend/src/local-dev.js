'use strict';
const crypto = require('node:crypto');

function createLocalDatabase(initial = {}) {
  const root = structuredClone(initial);

  function getPath(p) {
    if (!p) return root;
    return p.split('/').filter(Boolean).reduce((o, k) => o?.[k], root);
  }

  function putPath(p, v) {
    const a = p.split('/').filter(Boolean);
    if (a.length === 0) return;
    const k = a.pop();
    let o = root;
    for (const x of a) o = o[x] ??= {};
    if (v === null || v === undefined) {
      delete o[k];
    } else {
      o[k] = structuredClone(v);
    }
  }

  return {
    root,
    ref(p = '') {
      return {
        async get() {
          const val = getPath(p);
          return {
            val: () => (val !== undefined ? structuredClone(val) : null),
            exists: () => val !== undefined && val !== null
          };
        },
        async set(v) {
          putPath(p, structuredClone(v));
        },
        async update(v) {
          if (!v || typeof v !== 'object') return;
          for (const [k, x] of Object.entries(v)) {
            putPath([p, k].filter(Boolean).join('/'), structuredClone(x));
          }
        },
        async remove() {
          putPath(p, null);
        },
        async transaction(fn) {
          const current = getPath(p);
          const v = fn(structuredClone(current));
          if (v === undefined) return { committed: false };
          putPath(p, v);
          return { committed: true, snapshot: { val: () => structuredClone(v) } };
        },
        push(v) {
          const id = '-MB' + crypto.randomBytes(8).toString('hex');
          const childPath = [p, id].filter(Boolean).join('/');
          if (v !== undefined) {
            putPath(childPath, structuredClone(v));
          }
          return {
            key: id,
            async get() {
              const val = getPath(childPath);
              return { val: () => structuredClone(val), exists: () => val != null };
            },
            async set(newVal) { putPath(childPath, structuredClone(newVal)); }
          };
        }
      };
    }
  };
}

function createLocalAuth() {
  const sessions = new Map();
  const idTokens = new Map();

  const demoUser = {
    uid: 'demo_user',
    email: 'demo@mailindia.in',
    name: 'Demo Developer',
    email_verified: true,
    auth_time: Math.floor(Date.now() / 1000)
  };
  const adminUser = {
    uid: 'admin_user',
    email: 'admin@mailindia.in',
    name: 'Platform Admin',
    email_verified: true,
    admin: true,
    auth_time: Math.floor(Date.now() / 1000)
  };

  idTokens.set('demo', demoUser);
  idTokens.set('demo_token', demoUser);
  idTokens.set('admin', adminUser);
  idTokens.set('admin_token', adminUser);

  return {
    async verifyIdToken(token, checkRevoked) {
      if (idTokens.has(token)) {
        return { ...idTokens.get(token), auth_time: Math.floor(Date.now() / 1000) };
      }
      if (token && typeof token === 'string' && (token.startsWith('dev_') || token.includes('@'))) {
        const uid = token.startsWith('dev_') ? token : 'user_' + crypto.createHash('md5').update(token).digest('hex').slice(0, 10);
        const email = token.includes('@') ? token : `${token}@mailindia.in`;
        const isAdmin = email.includes('admin') || token.includes('admin');
        const user = {
          uid,
          email,
          email_verified: true,
          name: isAdmin ? 'Platform Admin' : 'Developer',
          admin: isAdmin,
          auth_time: Math.floor(Date.now() / 1000)
        };
        idTokens.set(token, user);
        return user;
      }
      throw new Error('Invalid or unknown ID token in local dev auth');
    },
    async createSessionCookie(idTokenOrUser, options = {}) {
      let user;
      if (idTokenOrUser && typeof idTokenOrUser === 'object' && idTokenOrUser.uid) {
        user = idTokenOrUser;
      } else if (typeof idTokenOrUser === 'string') {
        try {
          user = await this.verifyIdToken(idTokenOrUser);
        } catch {
          let uRecord = null;
          if (db) {
            try {
              const snap = await db.ref(`users/${idTokenOrUser}`).get();
              uRecord = snap.val();
            } catch {}
          }
          const email = uRecord?.email || (idTokenOrUser.includes('@') ? idTokenOrUser : `${idTokenOrUser}@mailindia.in`);
          const isAdmin = email.includes('admin') || idTokenOrUser.includes('admin') || Boolean(uRecord?.admin);
          user = {
            uid: idTokenOrUser,
            email,
            name: uRecord?.name || (isAdmin ? 'Platform Admin' : 'Developer'),
            picture: uRecord?.picture || '',
            email_verified: true,
            admin: isAdmin,
            auth_time: Math.floor(Date.now() / 1000)
          };
        }
      } else {
        throw new Error('Invalid token or user provided to createSessionCookie');
      }
      const session = 'mb-dev-session-' + crypto.randomBytes(24).toString('hex');
      sessions.set(session, { user, expiresAt: Date.now() + (options.expiresIn || 8 * 3600 * 1000) });
      return session;
    },
    async verifySessionCookie(sessionCookie, checkRevoked) {
      if (!sessionCookie) throw new Error('Missing session cookie');
      const entry = sessions.get(sessionCookie);
      if (entry && entry.expiresAt > Date.now()) {
        return { ...entry.user, auth_time: Math.floor(Date.now() / 1000) };
      }
      throw new Error('Invalid or expired dev session');
    },
    async revokeRefreshTokens(uid) {
      for (const [k, v] of sessions.entries()) {
        if (v.user.uid === uid) sessions.delete(k);
      }
    }
  };
}

function seedInitialData() {
  const now = Date.now();
  return {
    platform_settings: {
      creditRate: 5,
      retention: {
        emailLogsDays: 90,
        messageContentDays: 30
      }
    },
    users: {},
    wallets: {},
    payment_orders: {},
    payment_refunds: {},
    payment_disputes: {},
    sender_accounts: {},
    sender_assignments: {},
    email_logs: {},
    user_api_keys: {},
    key_index: {},
    processed_webhook_events: {},
    support_tickets: {}
  };
}

module.exports = {
  createLocalDatabase,
  createLocalAuth,
  seedInitialData
};
