'use strict';
const crypto = require('node:crypto');

const hash = x => crypto.createHash('sha256').update(String(x)).digest('hex');

// Multi-counter atomic Lua script for Redis
const redisRateScript = `
local a = redis.call('INCR', KEYS[1])
if a == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end

local b = redis.call('INCR', KEYS[2])
if b == 1 then redis.call('PEXPIRE', KEYS[2], ARGV[1]) end

if a > tonumber(ARGV[2]) or b > tonumber(ARGV[3]) then
  return 0
end
return 1
`;

// Single-key atomic Lua script
const redisSingleScript = `
local current = redis.call('INCR', KEYS[1])
if current == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
if current > tonumber(ARGV[2]) then
  return 0
end
return 1
`;

const DEFAULT_LIMITS = {
  userLimit: 120,          // requests / min
  keyLimit: 60,            // requests / min
  ipLoginLimit: 20,        // logins / min / IP
  paymentLimit: 10,        // orders / min / user
  apiKeyCreateLimit: 5,    // key creates / min / user
  dailySendingLimit: 1000, // emails / day / user
  adminLimit: 60           // admin actions / min
};

/**
 * In-memory sliding-window counter for test environments or when Redis is absent.
 */
class InMemoryRateStore {
  constructor() {
    this.hits = new Map();
  }

  checkAndIncrement(key, windowMs, max) {
    const now = Date.now();
    const entry = this.hits.get(key) || [];
    const valid = entry.filter(t => t > now - windowMs);
    if (valid.length >= max) {
      this.hits.set(key, valid);
      return false;
    }
    valid.push(now);
    this.hits.set(key, valid);
    return true;
  }
}

/**
 * Creates the complete rate limiting system.
 */
function createRateLimiter(redis, options = {}) {
  const limits = { ...DEFAULT_LIMITS, ...options };
  const memoryStore = new InMemoryRateStore();

  /**
   * Checks dual user + API key rate limit (for /v1 and /api endpoints).
   */
  async function checkUserAndKey(uid, keyId, userOverride) {
    const uLimit = Number.isSafeInteger(userOverride) && userOverride > 0 ? userOverride : limits.userLimit;
    const kLimit = limits.keyLimit;
    const windowMs = 60000;

    if (redis) {
      const res = await redis.eval(
        redisRateScript,
        2,
        'mb:rate:user:' + hash(uid),
        'mb:rate:key:' + hash(uid + ':' + keyId),
        windowMs,
        uLimit,
        kLimit
      );
      return Number(res) === 1;
    }

    // In-memory fallback
    const okUser = memoryStore.checkAndIncrement('user:' + uid, windowMs, uLimit);
    const okKey = memoryStore.checkAndIncrement('key:' + uid + ':' + keyId, windowMs, kLimit);
    return okUser && okKey;
  }

  /**
   * Checks rate limit for a single scope (e.g. IP login, payment creation, API key creation).
   */
  async function checkScoped(scope, id, customLimit, windowMs = 60000) {
    const limit = (customLimit !== undefined && customLimit !== null) ? customLimit : (limits[scope + 'Limit'] || 60);
    const key = `mb:rate:${scope}:${hash(id)}`;

    if (redis) {
      const res = await redis.eval(redisSingleScript, 1, key, windowMs, limit);
      return Number(res) === 1;
    }

    return memoryStore.checkAndIncrement(`${scope}:${id}`, windowMs, limit);
  }

  // Callable function interface preserving existing signature (uid, keyId, userOverride)
  const fn = (uid, keyId, userOverride) => checkUserAndKey(uid, keyId, userOverride);
  fn.checkUserAndKey = checkUserAndKey;
  fn.checkScoped = checkScoped;
  fn.limits = limits;

  return fn;
}

// Backwards-compatible factory
function redisLimiter(redis, options = {}) {
  return createRateLimiter(redis, options);
}

module.exports = {
  createRateLimiter,
  redisLimiter,
  DEFAULT_LIMITS
};
