const CorsairReplay = (() => {
'use strict';

function createRegressionCase({
title = 'Regression Test Case',
origin = '',
destination = '',
timestamp = Date.now(),
now = null,
chain = null,
events = [],
expectedVerdict = 'low-risk',
expectedRisk = 0
} = {}) {
return {
id: crypto.randomUUID(),
title: String(title).slice(0, 100),
origin: CorsairSecurity.normalizeHostname(origin),
destination: CorsairSecurity.normalizeHostname(destination),
timestamp: Number(timestamp) || Date.now(),
now: now !== null ? Number(now) : null,
chain: CorsairSecurity.sanitizeObject(chain),
events: Array.isArray(events) ? events.map(e => CorsairSecurity.sanitizeObject(e)) : [],
expected: {
verdict: expectedVerdict,
risk: expectedRisk
}
};
}

async function runCase(caseObj) {
if (!caseObj || typeof caseObj !== 'object') {
return { passed: false, error: 'invalid-case-object' };
}
const evaluation = CorsairIntelligence.classifySignals({
  events: caseObj.events || [],
  chain: caseObj.chain || null,
  destination: caseObj.destination || '',
  source: caseObj.origin || '',
  now: caseObj.now !== null ? caseObj.now : caseObj.timestamp
});

const expectedVerdict = caseObj.expected?.verdict || 'low-risk';
const passed = evaluation.verdict === expectedVerdict;

return {
  caseId: caseObj.id,
  title: caseObj.title,
  passed,
  hermetic: true,
  expected: caseObj.expected,
  actual: {
    verdict: evaluation.verdict,
    risk: evaluation.risk,
    reasons: evaluation.reasons
  }
};
}

async function runAll(cases = null) {
const fixtureCases = cases !== null ? cases : await CorsairStorage.getRegressionCases();
const results = [];
let passedCount = 0;
for (const c of fixtureCases) {
  const res = await runCase(c);
  results.push(res);
  if (res.passed) passedCount++;
}

return {
  total: results.length,
  passedCount,
  failedCount: results.length - passedCount,
  allPassed: results.length > 0 && passedCount === results.length,
  results
};
}

return {
createRegressionCase,
runCase,
runAll
};
})();

globalThis.CorsairReplay = CorsairReplay;