import { describe, it, expect, beforeAll } from 'vitest';
import { loadCore } from './helpers/load-core.js';

beforeAll(() => {
  loadCore('core/event-filter.js');
});

const FIXTURES = [
  { type: 'popup_blocked',         domain: 'evil.com',   severity: 'high',   reason: 'burst' },
  { type: 'navigation_contained',  domain: 'bad.org',    severity: 'high' },
  { type: 'auto_fortress_armed',   domain: 'shady.net',  severity: 'medium' },
  { type: 'extension_updated',     domain: '',           severity: 'info' },
  { type: 'download_blocked',      domain: 'malware.io', severity: 'high',   destination: 'file.exe' },
  { type: 'domain_removed',        domain: 'old.com',    severity: 'info' },
  { type: 'popup_blocked',         domain: 'spam.tk',    severity: 'medium' }
];

describe('CorsairEventFilter.filterEvents — no filters', () => {
  it('returns all events when no filters are given', () => {
    expect(CorsairEventFilter.filterEvents(FIXTURES)).toHaveLength(FIXTURES.length);
  });

  it('returns empty array for non-array input', () => {
    expect(CorsairEventFilter.filterEvents(null)).toEqual([]);
    expect(CorsairEventFilter.filterEvents(undefined)).toEqual([]);
    expect(CorsairEventFilter.filterEvents('not-array')).toEqual([]);
  });

  it('skips null / non-object entries', () => {
    const out = CorsairEventFilter.filterEvents([null, 'x', 42, FIXTURES[0]]);
    expect(out).toHaveLength(1);
  });
});

describe('CorsairEventFilter.filterEvents — severity', () => {
  it('filters to high', () => {
    const out = CorsairEventFilter.filterEvents(FIXTURES, { severity: 'high' });
    expect(out).toHaveLength(3);
    expect(out.every(e => e.severity === 'high')).toBe(true);
  });

  it('filters to medium', () => {
    expect(CorsairEventFilter.filterEvents(FIXTURES, { severity: 'medium' })).toHaveLength(2);
  });

  it('filters to info', () => {
    expect(CorsairEventFilter.filterEvents(FIXTURES, { severity: 'info' })).toHaveLength(2);
  });

  it('treats missing severity as low', () => {
    const out = CorsairEventFilter.filterEvents([{ type: 'x' }], { severity: 'low' });
    expect(out).toHaveLength(1);
  });

  it('"all" returns everything', () => {
    expect(CorsairEventFilter.filterEvents(FIXTURES, { severity: 'all' })).toHaveLength(FIXTURES.length);
  });
});

describe('CorsairEventFilter.filterEvents — type', () => {
  it('filters to a specific type', () => {
    const out = CorsairEventFilter.filterEvents(FIXTURES, { type: 'popup_blocked' });
    expect(out).toHaveLength(2);
  });

  it('returns empty for unknown type', () => {
    expect(CorsairEventFilter.filterEvents(FIXTURES, { type: 'nope' })).toEqual([]);
  });

  it('is case-insensitive', () => {
    expect(CorsairEventFilter.filterEvents(FIXTURES, { type: 'POPUP_BLOCKED' })).toHaveLength(2);
  });
});

describe('CorsairEventFilter.filterEvents — search', () => {
  it('searches domain', () => {
    const out = CorsairEventFilter.filterEvents(FIXTURES, { search: 'evil' });
    expect(out).toHaveLength(1);
    expect(out[0].domain).toBe('evil.com');
  });

  it('searches reason', () => {
    expect(CorsairEventFilter.filterEvents(FIXTURES, { search: 'burst' })).toHaveLength(1);
  });

  it('searches destination', () => {
    expect(CorsairEventFilter.filterEvents(FIXTURES, { search: 'file.exe' })).toHaveLength(1);
  });

  it('searches type', () => {
    expect(CorsairEventFilter.filterEvents(FIXTURES, { search: 'download' })).toHaveLength(1);
  });

  it('is case-insensitive', () => {
    expect(CorsairEventFilter.filterEvents(FIXTURES, { search: 'EVIL' })).toHaveLength(1);
  });

  it('trims whitespace', () => {
    expect(CorsairEventFilter.filterEvents(FIXTURES, { search: '  evil  ' })).toHaveLength(1);
  });

  it('empty search returns everything', () => {
    expect(CorsairEventFilter.filterEvents(FIXTURES, { search: '' })).toHaveLength(FIXTURES.length);
  });

  it('no match returns empty', () => {
    expect(CorsairEventFilter.filterEvents(FIXTURES, { search: 'zzz-not-found' })).toEqual([]);
  });
});

describe('CorsairEventFilter.filterEvents — combined', () => {
  it('severity + type + search together', () => {
    const out = CorsairEventFilter.filterEvents(FIXTURES, {
      severity: 'high', type: 'popup_blocked', search: 'evil'
    });
    expect(out).toHaveLength(1);
    expect(out[0].domain).toBe('evil.com');
  });

  it('returns empty when filters conflict', () => {
    const out = CorsairEventFilter.filterEvents(FIXTURES, {
      severity: 'info', type: 'popup_blocked'
    });
    expect(out).toEqual([]);
  });
});

describe('CorsairEventFilter.filterEvents — limit', () => {
  it('respects the limit', () => {
    expect(CorsairEventFilter.filterEvents(FIXTURES, { limit: 3 })).toHaveLength(3);
  });

  it('clamps limit to [1, 1000]', () => {
    expect(CorsairEventFilter.filterEvents(FIXTURES, { limit: 0 })).toHaveLength(1);
    expect(CorsairEventFilter.filterEvents(FIXTURES, { limit: -5 })).toHaveLength(1);
  });

  it('defaults to 200 when missing', () => {
    const many = Array.from({ length: 500 }, (_, i) => ({ type: 'x', domain: `d${i}` }));
    expect(CorsairEventFilter.filterEvents(many)).toHaveLength(200);
  });
});

describe('CorsairEventFilter.collectEventTypes', () => {
  it('collects unique types', () => {
    const types = CorsairEventFilter.collectEventTypes(FIXTURES);
    expect(types).toContain('popup_blocked');
    expect(types).toContain('navigation_contained');
    expect(types.filter(t => t === 'popup_blocked')).toHaveLength(1);
  });

  it('returns sorted list', () => {
    const types = CorsairEventFilter.collectEventTypes(FIXTURES);
    expect(types).toEqual([...types].sort());
  });

  it('handles empty / invalid input', () => {
    expect(CorsairEventFilter.collectEventTypes([])).toEqual([]);
    expect(CorsairEventFilter.collectEventTypes(null)).toEqual([]);
    expect(CorsairEventFilter.collectEventTypes('nope')).toEqual([]);
  });

  it('skips events without type', () => {
    const types = CorsairEventFilter.collectEventTypes([
      { type: 'a' }, { domain: 'x' }, { type: '' }, { type: 'b' }
    ]);
    expect(types).toEqual(['a', 'b']);
  });
});