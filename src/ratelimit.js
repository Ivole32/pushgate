// In-memory rate limiting. State is per process and resets on restart, which is acceptable
// for a single-instance service: limits exist to contain floods, not to meter usage.

const MAX_TRACKED = 10000;

// Bounded memory: when full, drop the oldest tenth of the entries (Map keeps insertion order),
// skipping entries for which keep() is true. Kept entries may use up to twice the normal
// size; beyond that the oldest go regardless, so memory stays bounded under any churn.
function makeRoom(map, keep = () => false) {
  if (map.size < MAX_TRACKED) return;
  const hardLimit = map.size >= 2 * MAX_TRACKED;
  let n = Math.ceil(MAX_TRACKED / 10);
  for (const [key, value] of map) {
    if (keep(value) && !hardLimit) continue;
    map.delete(key);
    if (--n === 0) break;
  }
}

// Token bucket: `perMinute` tokens per minute with a burst of the same size.
export function createRateLimiter(perMinute, { now = () => Date.now() } = {}) {
  const buckets = new Map();
  const ratePerMs = perMinute / 60000;

  return {
    // Returns 0 when allowed, otherwise the number of seconds to wait.
    take(id) {
      const t = now();
      let b = buckets.get(id);
      if (!b) {
        makeRoom(buckets);
        b = { tokens: perMinute, at: t };
        buckets.set(id, b);
      }
      b.tokens = Math.min(perMinute, b.tokens + (t - b.at) * ratePerMs);
      b.at = t;
      if (b.tokens >= 1) {
        b.tokens -= 1;
        return 0;
      }
      return Math.max(1, Math.ceil((1 - b.tokens) / ratePerMs / 1000));
    },
  };
}

// Counts failures per client within a window; once `limit` is reached the client is blocked
// for `blockMs`. Used against credential guessing on the API and the admin login.
export function createFailureLimiter({ limit, windowMs, blockMs, now = () => Date.now() }) {
  const entries = new Map();

  return {
    // Seconds remaining in a block, or 0.
    blockedFor(id) {
      const e = entries.get(id);
      if (!e || !e.blockedUntil) return 0;
      const left = e.blockedUntil - now();
      if (left <= 0) {
        entries.delete(id);
        return 0;
      }
      return Math.ceil(left / 1000);
    },
    fail(id) {
      const t = now();
      let e = entries.get(id);
      if (!e || t - e.start > windowMs) {
        entries.delete(id);
        // Active blocks are kept (up to the hard limit), so address churn cannot lift them.
        makeRoom(entries, (v) => v.blockedUntil > t);
        e = { start: t, count: 0, blockedUntil: 0 };
        entries.set(id, e);
      }
      e.count += 1;
      if (e.count >= limit) e.blockedUntil = t + blockMs;
      return e.count >= limit;
    },
    reset(id) {
      entries.delete(id);
    },
  };
}
