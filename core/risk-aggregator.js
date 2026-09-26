const CorsairRiskAggregator = (() => {
  'use strict';

  /* ============================================================
     RISK AGGREGATOR
     ------------------------------------------------------------
     Combines per-source verdicts into a single unified risk score.
     Key properties:

       • Weighted average of scores, weighted by source confidence
         (a low-confidence signal can't dominate a high-confidence
         one, even if the low-confidence source reports a strong
         score).

       • Escalation rule: a single high-confidence "malicious" from
         any source pushes the aggregated risk to >= 75. This
         prevents a strong signal from being averaged away by
         weaker "clean" reports.

       • Confidence grows with the number of sources that agree
         with the aggregated verdict.

       • All weights are deterministic constants, so the same
         inputs always produce the same output — critical for the
         regression suite in core/replay.js.
     ============================================================ */

  const DEFAULT_WEIGHTS = {
    virusTotal: 0.50,
    urlhaus:    0.35,
    heuristics: 0.25,
    domainAge:  0.10
  };

  function clamp(n, lo, hi) {
    if (!Number.isFinite(n)) return lo;
    return Math.max(lo, Math.min(hi, n));
  }

  function sourceWeight(key, source) {
    if (!source || source.ok === false) return 0;
    const base = Number(source.weight) || DEFAULT_WEIGHTS[key] || 0.2;
    const conf = clamp(Number(source.confidence) || 0.5, 0, 1);
    // Below 0.3 confidence the source is treated as background noise.
    if (conf < 0.3) return 0;
    return base * conf;
  }

  function normalizeSource(key, s) {
    if (!s || typeof s !== 'object') return null;
    if (s.ok === false) {
      return {
        name: key,
        verdict: 'error',
        score: 0,
        confidence: 0,
        weight: 0,
        error: String(s.error || 'error')
      };
    }
    return {
      name: key,
      verdict: String(s.verdict || 'unknown'),
      score: clamp(Number(s.score) || 0, 0, 100),
      confidence: clamp(Number(s.confidence) || 0.5, 0, 1),
      weight: sourceWeight(key, s),
      evidence: s.evidence || null
    };
  }

  function aggregate(sources) {
    const list = [];
    for (const [key, s] of Object.entries(sources || {})) {
      const n = normalizeSource(key, s);
      if (n) list.push(n);
    }

    const active = list.filter(x => x.weight > 0);
    if (active.length === 0) {
      return {
        verdict: 'unknown',
        risk: 0,
        confidence: 0,
        sources: list,
        reason: 'no-active-sources'
      };
    }

    let totalW = 0;
    let weighted = 0;
    for (const s of active) {
      weighted += s.score * s.weight;
      totalW += s.weight;
    }
    let risk = totalW > 0 ? weighted / totalW : 0;

    // Escalation: strong single-signal overrides weaker averages.
    for (const s of active) {
      if (s.verdict === 'malicious' && s.score >= 70 && s.confidence >= 0.7) {
        risk = Math.max(risk, 75);
      } else if (s.verdict === 'suspicious' && s.score >= 40 && s.confidence >= 0.6) {
        risk = Math.max(risk, 45);
      }
    }

    risk = Math.round(clamp(risk, 0, 100));

    let verdict = 'clean';
    if (risk >= 70) verdict = 'malicious';
    else if (risk >= 40) verdict = 'suspicious';
    else if (risk >= 20) verdict = 'review';

    const agreeCount = active.filter(s => {
      if (verdict === 'malicious')  return s.verdict === 'malicious';
      if (verdict === 'suspicious') return s.verdict === 'suspicious' || s.verdict === 'malicious';
      if (verdict === 'clean')      return s.verdict === 'clean';
      return true;
    }).length;
    const confidence = clamp(0.4 + agreeCount * 0.15 + active.length * 0.05, 0, 0.99);

    return { verdict, risk, confidence, sources: list };
  }

  return { aggregate, DEFAULT_WEIGHTS };
})();

globalThis.CorsairRiskAggregator = CorsairRiskAggregator;