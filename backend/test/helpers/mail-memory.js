'use strict';

function memoryDb(seed = {}) {
  const root = structuredClone(seed);
  const get = path => path.split('/').filter(Boolean).reduce((value, key) => value?.[key], root);
  const put = (path, value) => {
    const parts = path.split('/').filter(Boolean);
    const last = parts.pop();
    let target = root;
    for (const part of parts) target = target[part] ||= {};
    if (value === null || value === undefined) delete target[last];
    else target[last] = structuredClone(value);
  };
  const snapshot = value => ({ val: () => value === undefined ? null : structuredClone(value), exists: () => value !== undefined && value !== null });
  return {
    root,
    ref(path = '') {
      return {
        async get() { return snapshot(get(path)); },
        async set(value) { put(path, value); },
        async remove() { put(path, null); },
        async update(values) { for (const [key, value] of Object.entries(values)) put(path + '/' + key, value); },
        child(key) { return this.ref ? this.ref(path + '/' + key) : { set: async value => put(path + '/' + key, value) }; },
        async transaction(update) {
          const next = update(structuredClone(get(path) ?? null));
          if (next === undefined) return { committed: false, snapshot: snapshot(get(path)) };
          put(path, next);
          return { committed: true, snapshot: snapshot(next) };
        }
      };
    }
  };
}

module.exports = { memoryDb };
