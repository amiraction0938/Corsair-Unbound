import { describe, it, expect, beforeAll } from 'vitest';
import { loadCore } from './helpers/load-core.js';

beforeAll(() => {
  loadCore('core/risk-aggregator.js');
});

describe('CorsairRiskAggregator.aggregate — empty / degenerate inputs', () => {
  it('returns unknown + no-active-sources for an empty object', () => {
    const r = CorsairRiskAggregator.aggregate({});
    expect(r.verdict).toBe('unknown');
    expect(r.risk).toBe(0);
    expect(r.confidence).toBe(0);
    expect(r.reason).toBe('no-active-sources');
  });

  it('handles null/undefined sources', () => {
    expect(CorsairRiskAggregator.aggregate(null).verdict).toBe('unknown');
    expect(CorsairRiskAggregator.aggregate(undefined).verdict).toBe('unknown');
  });

  it('excludes failed sources (ok:false) from the weighted average', () => {
    const r = CorsairRiskAggregator.aggregate({
      virusTotal: { ok: false, error: 'network' }
    });
    expect(r.verdict).toBe('unknown');
    expect(r.reason).toBe('no-active-sources');
    // The failed source is still reported in the sources array…
    expect(r.sources).toHaveLength(1);
    expect(r.sources[0].verdict).toBe('error');
    // …but its weight is zero.
    expect(r.sources[0].weight).toBe(0);
  });

  it('drops sources whose confidence is below the 0.3 noise floor', () => {
    const r = CorsairRiskAggregator.aggregate({
      heuristics: { ok: true, verdict: 'malicious', score: 100, confidence: 0.2 }
    });
    expect(r.reason).toBe('no-active-sources');
    // The source is present in the output but not counted.
    expect(r.sources[0].weight).toBe(0);
  });
});

describe('CorsairRiskAggregator.aggregate — single source', () => {
  it('clean VT → clean verdict, risk 0', () => {
    const r = CorsairRiskAggregator.aggregate({
      virusTotal: { ok: true, verdict: 'clean', score: 0, confidence: 0.85 }
    });
    expect(r.verdict).toBe('clean');
    expect(r.risk).toBe(0);
    expect(r.confidence).toBeCloseTo(0.6, 2);
  });

  it('malicious VT → malicious verdict, high risk', () => {
    const r = CorsairRiskAggregator.aggregate({
      virusTotal: { ok: true, verdict: 'malicious', score: 90, confidence: 0.9 }
    });
    expect(r.verdict).toBe('malicious');
    expect(r.risk).toBeGreaterThanOrEqual(90);
  });
});

describe('CorsairRiskAggregator.aggregate — weighted average', () => {
  it('respects explicit weights', () => {
    const r = CorsairRiskAggregator.aggregate({
      a: { ok: true, verdict: 'clean', score: 0,   confidence: 1, weight: 0.9 },
      b: { ok: true, verdict: 'unknown', score: 30, confidence: 1, weight: 0.1 }
    });
    // Weighted avg: (0*0.9 + 30*0.1) / (0.9 + 0.1) = 3
    expect(r.risk).toBe(3);
  });

  it('assigns default weights to known sources (VT > URLhaus > heuristics)', () => {
    // VT (0.50) reports clean; heuristics (0.25) reports malicious but
    // not strongly enough to trigger escalation. Result should be
    // dominated by VT.
    const r = CorsairRiskAggregator.aggregate({
      virusTotal:  { ok: true, verdict: 'clean',      score: 0,  confidence: 0.9 },
      heuristics:  { ok: true, verdict: 'suspicious', score: 40, confidence: 0.5 }
    });
    // heuristics weight = 0.25 * 0.5 = 0.125
    // VT weight         = 0.50 * 0.9 = 0.45
    // weighted avg = (0*0.45 + 40*0.125) / (0.45 + 0.125) ≈ 8.7
    expect(r.risk).toBeLessThan(15);
  });
});

describe('CorsairRiskAggregator.aggregate — escalation', () => {
  it('escalates to ≥75 when a single high-confidence source says MALICIOUS', () => {
    const r = CorsairRiskAggregator.aggregate({
      virusTotal:  { ok: true, verdict: 'clean',     score: 0,  confidence: 0.85 },
      heuristics:  { ok: true, verdict: 'clean',     score: 0,  confidence: 0.6  },
      urlhaus:     { ok: true, verdict: 'malicious', score: 90, confidence: 0.85 }
    });
    // Without escalation the weighted average would be ~31;
    // escalation must pull it up to at least 75.
    expect(r.risk).toBeGreaterThanOrEqual(75);
    expect(r.verdict).toBe('malicious');
  });

  it('escalates to ≥45 when a single high-confidence source says SUSPICIOUS', () => {
    const r = CorsairRiskAggregator.aggregate({
      virusTotal:  { ok: true, verdict: 'clean',      score: 0,  confidence: 0.9 },
      heuristics:  { ok: true, verdict: 'suspicious', score: 50, confidence: 0.65 }
    });
    expect(r.risk).toBeGreaterThanOrEqual(45);
  });

  it('does NOT escalate when confidence is below the 0.7 threshold', () => {
    const r = CorsairRiskAggregator.aggregate({
      virusTotal: { ok: true, verdict: 'clean', score: 0, confidence: 0.9 },
      custom: {
        ok: true, verdict: 'malicious', score: 90, confidence: 0.5, weight: 0.05
      }
    });
    // custom weight = 0.05 * 0.5 = 0.025
    // VT weight     = 0.50 * 0.9 = 0.45
    // weighted avg  = 90 * 0.025 / 0.475 ≈ 4.7 → risk ≈ 5
    expect(r.risk).toBeLessThan(20);
  });
});

describe('CorsairRiskAggregator.aggregate — verdict boundaries', () => {
  // We drive risk with a single source whose verdict does NOT match
  // an escalation rule (verdict 'unknown'), so the aggregated risk
  // is exactly the score we supply.
  const at = (score) => CorsairRiskAggregator.aggregate({
    custom: { ok: true, verdict: 'unknown', score, confidence: 1, weight: 1 }
  });

  it('risk 0 → clean',   () => expect(at(0).verdict).toBe('clean'));
  it('risk 19 → clean',  () => expect(at(19).verdict).toBe('clean'));
  it('risk 20 → review', () => expect(at(20).verdict).toBe('review'));
  it('risk 39 → review', () => expect(at(39).verdict).toBe('review'));
  it('risk 40 → suspicious', () => expect(at(40).verdict).toBe('suspicious'));
  it('risk 69 → suspicious', () => expect(at(69).verdict).toBe('suspicious'));
  it('risk 70 → malicious', () => expect(at(70).verdict).toBe('malicious'));
  it('risk 100 → malicious', () => expect(at(100).verdict).toBe('malicious'));
});

describe('CorsairRiskAggregator.aggregate — malformed inputs', () => {
  it('ignores null / non-object source entries', () => {
    const r = CorsairRiskAggregator.aggregate({
      virusTotal: null,
      urlhaus: 'string-not-object'
    });
    expect(r.reason).toBe('no-active-sources');
  });

  it('clamps out-of-range scores and confidence to [0, 100] / [0, 1]', () => {
    const r = CorsairRiskAggregator.aggregate({
      custom: { ok: true, verdict: 'unknown', score: 9999, confidence: 5, weight: 1 }
    });
    expect(r.risk).toBe(100);
    expect(r.sources[0].confidence).toBe(1);
    expect(r.sources[0].score).toBe(100);
  });

  it('coerces missing score / confidence to safe defaults', () => {
    const r = CorsairRiskAggregator.aggregate({
      custom: { ok: true, verdict: 'clean' }
    });
    expect(r.risk).toBe(0);
  });
});

describe('CorsairRiskAggregator.aggregate — determinism', () => {
  it('produces byte-identical output for the same input', () => {
    const input = {
      virusTotal: { ok: true, verdict: 'suspicious', score: 55, confidence: 0.7 },
      heuristics: { ok: true, verdict: 'clean',      score: 10, confidence: 0.6 },
      urlhaus:    { ok: true, verdict: 'clean',      score: 0,  confidence: 0.5 }
    };
    const a = CorsairRiskAggregator.aggregate(input);
    const b = CorsairRiskAggregator.aggregate(input);
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
  });

  it('is order-independent (same result regardless of insertion order)', () => {
    const a = CorsairRiskAggregator.aggregate({
      virusTotal: { ok: true, verdict: 'malicious', score: 90, confidence: 0.9 },
      urlhaus:    { ok: true, verdict: 'clean',     score: 0,  confidence: 0.7 }
    });
    const b = CorsairRiskAggregator.aggregate({
      urlhaus:    { ok: true, verdict: 'clean',     score: 0,  confidence: 0.7 },
      virusTotal: { ok: true, verdict: 'malicious', score: 90, confidence: 0.9 }
    });
    expect(a.verdict).toBe(b.verdict);
    expect(a.risk).toBe(b.risk);
    expect(a.confidence).toBe(b.confidence);
  });
});