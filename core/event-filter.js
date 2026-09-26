const CorsairEventFilter = (() => {
  'use strict';

  /**
   * Filter and sort events based on user-controlled filters.
   *
   * @param {Array} events
   * @param {Object} filters
   * @param {string} [filters.search='']      free-text on domain/type/reason/destination
   * @param {string} [filters.severity='all'] 'all' | 'high' | 'medium' | 'low' | 'info'
   * @param {string} [filters.type='all']     'all' or a specific event type
   * @param {number} [filters.limit=200]      max results, clamped to [1, 1000]
   * @returns {Array}
   */
  function filterEvents(events, filters = {}) {
    if (!Array.isArray(events)) return [];
    const search = String(filters.search || '').trim().toLowerCase();
    const severity = String(filters.severity || 'all').toLowerCase();
    const type = String(filters.type || 'all').toLowerCase();
    // NOTE: We must distinguish "limit not provided" (→ default 200)
    // from "limit explicitly 0" (→ clamp to 1). Using `Number(x) || 200`
    // treats 0 as falsy and silently returns 200, which contradicts the
    // documented "clamped to [1, 1000]" contract. `0` is a real value
    // that must be clamped, not treated as "no preference".
    const rawLimit = filters.limit;
    const numLimit = Number(rawLimit);
    const limit = (rawLimit == null || !Number.isFinite(numLimit))
      ? 200
      : Math.max(1, Math.min(1000, numLimit));

    const out = [];
    for (const e of events) {
      if (!e || typeof e !== 'object') continue;

      if (severity !== 'all') {
        const s = String(e.severity || 'low').toLowerCase();
        if (s !== severity) continue;
      }

      if (type !== 'all') {
        const t = String(e.type || '').toLowerCase();
        if (t !== type) continue;
      }

      if (search) {
        const haystack = [
          e.type, e.domain, e.destination, e.reason,
          e.source, e.kind
        ].filter(Boolean).join(' ').toLowerCase();
        if (!haystack.includes(search)) continue;
      }

      out.push(e);
      if (out.length >= limit) break;
    }
    return out;
  }

  function collectEventTypes(events) {
    if (!Array.isArray(events)) return [];
    const set = new Set();
    for (const e of events) {
      if (e && typeof e === 'object' && e.type) {
        set.add(String(e.type));
      }
    }
    return [...set].sort();
  }

  return { filterEvents, collectEventTypes };
})();

globalThis.CorsairEventFilter = CorsairEventFilter;