const CorsairBloom = (() => {
  'use strict';

  /* ============================================================
     BLOOM FILTER — fast negative lookups for allowlists.
     ------------------------------------------------------------
     A Bloom filter can tell us with 100% certainty when a key is
     NOT present (fast path) but only "maybe present" when it is
     (fallback to authoritative Set lookup). This lets us skip the
     O(n) iteration over 20,000+ remote allowlist entries for
     domains that are obviously not on the list.

     We use the standard Kirsch-Mitzenmacher optimization:
       h_i(x) = (h1(x) + i * h2(x)) mod m
     which derives k independent hash functions from two FNV-1a
     hashes with different seeds.

     Sized for 22,000 entries with ~0.2% false positive rate:
       m = 2^18 bits (32 KB), k = 7

     Callers must pass a POWER-OF-TWO sizeBits so we can use
     bitwise AND instead of modulo.
     ============================================================ */

  function fnv1a(str, seed = 0x811c9dc5) {
    let h = seed >>> 0;
    for (let i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = Math.imul(h, 0x01000193) >>> 0;
    }
    return h >>> 0;
  }

  function hashPair(str) {
    return [fnv1a(str), fnv1a(str, 0x9dc5811c)];
  }

  function create(sizeBits, k) {
    if (!Number.isInteger(sizeBits) || sizeBits <= 0) {
      throw new Error('bloom: sizeBits must be a positive integer');
    }
    if ((sizeBits & (sizeBits - 1)) !== 0) {
      throw new Error('bloom: sizeBits must be a power of two');
    }
    const kHashes = Math.max(1, Math.min(32, Number(k) || 7));
    const mask = sizeBits - 1;
    const bits = new Uint32Array(sizeBits >>> 5);
    let count = 0;

    function add(str) {
      const s = String(str);
      const [h1, h2] = hashPair(s);
      for (let i = 0; i < kHashes; i++) {
        const idx = (h1 + i * h2) & mask;
        bits[idx >>> 5] |= (1 << (idx & 31));
      }
      count++;
    }

    function has(str) {
      const s = String(str);
      const [h1, h2] = hashPair(s);
      for (let i = 0; i < kHashes; i++) {
        const idx = (h1 + i * h2) & mask;
        if (!(bits[idx >>> 5] & (1 << (idx & 31)))) return false;
      }
      return true;
    }

    function addAll(iterable) {
      for (const x of iterable) add(x);
    }

    function approximateCount() {
      return count;
    }

    return { add, has, addAll, approximateCount, sizeBits, k: kHashes };
  }

  /* Approximate the registrable domain (eTLD+1) without a full
     public-suffix list. This matches the heuristic already used
     in core/heuristics.js so behavior is consistent across the
     extension. Only used for bloom pre-checks — the authoritative
     answer always comes from a real Set/suffix match. */
  const KNOWN_SECOND_LEVEL = new Set(['co', 'com', 'org', 'net', 'gov', 'edu', 'ac', 'sch']);

  function approximateRegistrableDomain(host) {
    const parts = String(host || '').toLowerCase().split('.').filter(Boolean);
    if (parts.length <= 2) return parts.join('.');
    if (KNOWN_SECOND_LEVEL.has(parts[parts.length - 2])) {
      return parts.slice(-3).join('.');
    }
    return parts.slice(-2).join('.');
  }

  return { create, fnv1a, approximateRegistrableDomain };
})();

globalThis.CorsairBloom = CorsairBloom;