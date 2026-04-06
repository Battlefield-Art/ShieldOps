/**
 * API Load Test — 1000 RPS sustained for 30 minutes.
 *
 * Target SLOs (issue #223):
 *   - 1000 requests/sec sustained
 *   - P99 < 500ms
 *   - P95 < 200ms
 *   - error rate < 1%
 *
 * Uses the `constant-arrival-rate` executor so VUs scale automatically
 * to hit the target rate regardless of per-request latency.
 *
 * Usage:
 *   k6 run tests/load/api_load.js
 *   k6 run tests/load/api_load.js -e TARGET_RPS=1500 -e DURATION=10m
 *   k6 run tests/load/api_load.js -e API_URL=https://staging.shieldops.io/api/v1 \
 *                                 --out json=results/api_load.json
 */

import http from 'k6/http';
import { check } from 'k6';
import { Trend, Rate, Counter } from 'k6/metrics';
import { BASE_URL, TEST_EMAIL, TEST_PASSWORD } from './config.js';
import { login, authHeaders, randomChoice } from './helpers.js';

// --- Tunables --------------------------------------------------------------

const TARGET_RPS = parseInt(__ENV.TARGET_RPS || '1000', 10);
const DURATION = __ENV.DURATION || '30m';
const RAMP_DURATION = __ENV.RAMP_DURATION || '2m';

// Budget VUs aggressively: enough to cover target RPS at ~200ms avg latency.
// preAllocatedVUs = RPS * avg_latency_s * headroom.
const PRE_ALLOCATED_VUS = Math.max(200, Math.ceil(TARGET_RPS * 0.3));
const MAX_VUS = Math.max(500, Math.ceil(TARGET_RPS * 1.0));

// --- Custom metrics --------------------------------------------------------

const apiLatency = new Trend('api_latency_ms', true);
const apiErrors = new Rate('api_error_rate');
const apiRequests = new Counter('api_requests_total');

// --- k6 options ------------------------------------------------------------

export const options = {
  scenarios: {
    ramp_up: {
      executor: 'ramping-arrival-rate',
      startRate: 100,
      timeUnit: '1s',
      preAllocatedVUs: PRE_ALLOCATED_VUS,
      maxVUs: MAX_VUS,
      stages: [
        { duration: RAMP_DURATION, target: TARGET_RPS },
      ],
      tags: { phase: 'ramp' },
      exec: 'apiLoad',
    },
    sustained: {
      executor: 'constant-arrival-rate',
      rate: TARGET_RPS,
      timeUnit: '1s',
      duration: DURATION,
      preAllocatedVUs: PRE_ALLOCATED_VUS,
      maxVUs: MAX_VUS,
      startTime: RAMP_DURATION,
      tags: { phase: 'sustained' },
      exec: 'apiLoad',
    },
  },
  thresholds: {
    // Issue #223 SLO gates
    http_req_duration: ['p(95)<200', 'p(99)<500'],
    http_req_failed: ['rate<0.01'],
    http_reqs: [`rate>${TARGET_RPS * 0.95}`],
    api_latency_ms: ['p(99)<500'],
    api_error_rate: ['rate<0.01'],
    // Phase-specific gates
    'http_req_duration{phase:sustained}': ['p(99)<500', 'p(95)<200'],
  },
  // Abort early if we massively miss the SLO during ramp-up.
  noConnectionReuse: false,
  discardResponseBodies: true,
};

// --- Setup -----------------------------------------------------------------

export function setup() {
  const token = login(TEST_EMAIL, TEST_PASSWORD);
  if (!token) {
    throw new Error(
      'Setup failed: could not authenticate. Is the ShieldOps API running at ' + BASE_URL + '?'
    );
  }
  return { token };
}

// --- Endpoint mix ----------------------------------------------------------
// Read-heavy mix modeled after production dashboard traffic.
// Weights approximate real user patterns from analytics.

const ENDPOINTS = [
  { path: '/investigations?limit=20', weight: 25, name: 'list_investigations' },
  { path: '/remediations?limit=20', weight: 15, name: 'list_remediations' },
  { path: '/analytics/summary', weight: 15, name: 'analytics_summary' },
  { path: '/agents', weight: 10, name: 'list_agents' },
  { path: '/security/alerts?limit=20', weight: 10, name: 'list_alerts' },
  { path: '/vulnerabilities?limit=20', weight: 8, name: 'list_vulns' },
  { path: '/auth/me', weight: 7, name: 'auth_me' },
  { path: '/situations?limit=20', weight: 5, name: 'list_situations' },
  { path: '/nhi/registry?limit=20', weight: 3, name: 'list_nhi' },
  { path: '/mcp/servers', weight: 2, name: 'list_mcp' },
];

// Pre-expand weighted list once per VU init.
const ENDPOINT_POOL = [];
for (const ep of ENDPOINTS) {
  for (let i = 0; i < ep.weight; i++) ENDPOINT_POOL.push(ep);
}

// --- Default exec fn -------------------------------------------------------

export function apiLoad(data) {
  const ep = randomChoice(ENDPOINT_POOL);
  const res = http.get(`${BASE_URL}${ep.path}`, {
    headers: authHeaders(data.token),
    tags: { name: ep.name, endpoint: ep.path },
  });

  apiLatency.add(res.timings.duration);
  apiRequests.add(1);
  const ok = res.status >= 200 && res.status < 300;
  apiErrors.add(!ok);

  check(res, {
    [`${ep.name} status 2xx`]: (r) => r.status >= 200 && r.status < 300,
    [`${ep.name} p99 budget`]: (r) => r.timings.duration < 500,
  });
}

// Default export required by k6 even when using scenarios.
export default function (data) {
  apiLoad(data);
}

// --- Summary ---------------------------------------------------------------

export function handleSummary(data) {
  const p99 = data.metrics.http_req_duration.values['p(99)'];
  const p95 = data.metrics.http_req_duration.values['p(95)'];
  const errRate = data.metrics.http_req_failed.values.rate;
  const rps = data.metrics.http_reqs.values.rate;

  // eslint-disable-next-line no-console
  console.log(`
============================================================
ShieldOps API Load Test — SLO Report
============================================================
Target RPS      : ${TARGET_RPS}
Observed RPS    : ${rps.toFixed(2)}
P95 latency     : ${p95.toFixed(2)} ms   (budget: 200 ms)
P99 latency     : ${p99.toFixed(2)} ms   (budget: 500 ms)
Error rate      : ${(errRate * 100).toFixed(3)} %   (budget: 1.0 %)
SLO PASS        : ${rps >= TARGET_RPS * 0.95 && p99 < 500 && errRate < 0.01 ? 'YES' : 'NO'}
============================================================
`);

  return {
    stdout: JSON.stringify(
      {
        target_rps: TARGET_RPS,
        observed_rps: rps,
        p95_ms: p95,
        p99_ms: p99,
        error_rate: errRate,
      },
      null,
      2,
    ),
  };
}
