import { describe, it, expect, beforeAll } from 'vitest';
import { loadCore } from './helpers/load-core.js';

beforeAll(() => {
  loadCore('core/bloom.js');
});

describe('CorsairBloom.create — construction', () => {
  it('rejects non-power-of-two sizeBits', () => {
    expect(() => CorsairBloom.create(1000, 7)).toThrow(/power of two/);
  });

  it('rejects zero / negative sizeBits', () => {
    expect(() => CorsairBloom.create(0, 7)).toThrow();
    expect(() => CorsairBloom.create(-1, 7)).toThrow();
    expect(() => CorsairBloom.create(1.5, 7)).toThrow();
  });

  it('accepts 2^18 bits with 7 hashes (production sizing)', () => {
    const bf = CorsairBloom.create(1 << 18, 7);
    expect(bf.sizeBits).toBe(1 << 18);
    expect(bf.k).toBe(7);
  });

  it('uses the default 7 when k is missing or falsy (0)', () => {
    // NOTE: bloom.js uses `Number(k) || 7`, so 0 → 7 (default). This
    // is idiomatic JS "default value" behavior, not a clamp. Testing
    // it as such documents the actual API contract.
    expect(CorsairBloom.create(1 << 10).k).toBe(7);
    expect(CorsairBloom.create(1 << 10, 0).k).toBe(7);
  });

  it('clamps explicit non-zero k to [1, 32]', () => {
    expect(CorsairBloom.create(1 << 10, 1).k).toBe(1);
    expect(CorsairBloom.create(1 << 10, 999).k).toBe(32);
  });
});

describe('CorsairBloom — add / has consistency', () => {
  it('returns true for every value that was added', () => {
    const bf = CorsairBloom.create(1 << 14, 7);
    const inserted = ['apple.com', 'google.com', 'x', 'test-value-42'];
    bf.addAll(inserted);
    for (const v of inserted) {
      expect(bf.has(v)).toBe(true);
    }
  });

  it('returns false for values never added (empty filter)', () => {
    const bf = CorsairBloom.create(1 << 14, 7);
    expect(bf.has('nothing')).toBe(false);
    expect(bf.has('apple.com')).toBe(false);
  });

  it('reports the inserted count via approximateCount()', () => {
    const bf = CorsairBloom.create(1 << 12, 5);
    bf.add('a');
    bf.add('b');
    bf.add('c');
    // approximateCount counts add() calls, not distinct values.
    expect(bf.approximateCount()).toBe(3);
  });

  it('is stable: same value → same answer every time', () => {
    const bf = CorsairBloom.create(1 << 12, 7);
    bf.add('stable');
    for (let i = 0; i < 20; i++) expect(bf.has('stable')).toBe(true);
  });

  it('treats duplicate adds as separate count events but one membership', () => {
    const bf = CorsairBloom.create(1 << 10, 7);
    bf.add('dup');
    bf.add('dup');
    bf.add('dup');
    expect(bf.has('dup')).toBe(true);
    expect(bf.approximateCount()).toBe(3);
  });

  it('coerces non-string values via String()', () => {
    const bf = CorsairBloom.create(1 << 10, 7);
    bf.add(42);
    bf.add(true);
    expect(bf.has(42)).toBe(true);
    expect(bf.has('42')).toBe(true);   // same key, coerced
    expect(bf.has(true)).toBe(true);
    expect(bf.has('true')).toBe(true);
  });
});

describe('CorsairBloom — false positive measurement', () => {
  // The production sizing (2^18 bits, k=7) is spec'd for ~22,000 items
  // with a ~0.2% false-positive rate. We do not test at that scale
  // (too slow for a unit test), but we DO verify the filter is doing
  // its job: inserting 5,000 values must not make unrelated values
  // appear present at a high rate.

  it('keeps FP rate under 1% for 5,000 inserted values at production sizing', () => {
    const bf = CorsairBloom.create(1 << 18, 7);

    const inserted = [];
    for (let i = 0; i < 5000; i++) inserted.push('host-' + i + '.example');
    bf.addAll(inserted);

    // Every inserted value must still be present (no false negatives).
    for (const v of inserted) {
      expect(bf.has(v)).toBe(true);
    }

    // Now query 5,000 fresh, unrelated values.
    let fp = 0;
    const QUERIES = 5000;
    for (let i = 0; i < QUERIES; i++) {
      if (bf.has('absent-' + i + '.example')) fp++;
    }
    const rate = fp / QUERIES;
    expect(rate, `FP rate ${(rate * 100).toFixed(3)}% exceeds 1%`).toBeLessThan(0.01);
  });

  it('never produces a false negative for any inserted value', () => {
    const bf = CorsairBloom.create(1 << 14, 7);
    const values = [];
    for (let i = 0; i < 500; i++) values.push('v' + i);
    bf.addAll(values);
    for (const v of values) expect(bf.has(v)).toBe(true);
  });
});

describe('CorsairBloom.approximateRegistrableDomain', () => {
  it('returns the host unchanged when it has ≤ 2 labels', () => {
    expect(CorsairBloom.approximateRegistrableDomain('example.com')).toBe('example.com');
    expect(CorsairBloom.approximateRegistrableDomain('localhost')).toBe('localhost');
  });

  it('peels subdomains down to eTLD+1 for common TLDs', () => {
    expect(CorsairBloom.approximateRegistrableDomain('a.b.example.com')).toBe('example.com');
  });

  it('handles known second-level labels (co.uk)', () => {
    expect(CorsairBloom.approximateRegistrableDomain('www.example.co.uk')).toBe('example.co.uk');
    expect(CorsairBloom.approximateRegistrableDomain('a.b.example.co.uk')).toBe('example.co.uk');
  });
});