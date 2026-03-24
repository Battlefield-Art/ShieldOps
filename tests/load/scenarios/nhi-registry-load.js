/**
 * NHI (Non-Human Identity) Registry load test -- exercises identity
 * listing, shadow AI detection, metrics, and scan endpoints under
 * sustained throughput.
 *
 * Usage:
 *   k6 run tests/load/scenarios/nhi-registry-load.js
 *   k6 run tests/load/scenarios/nhi-registry-load.js -e API_URL=http://staging:8000/api/v1
 */

import { group, sleep } from 'k6';
import { Trend, Counter } from 'k6/metrics';
import { BASE_URL, THRESHOLDS, TEST_EMAIL, TEST_PASSWORD } from '../config.js';
import { login, authGet, authPost, randomInt, randomChoice } from '../helpers.js';

// Custom metrics
const listLatency = new Trend('nhi_list_latency');
const scanLatency = new Trend('nhi_scan_latency');
const scanCount = new Counter('nhi_scans_triggered');

export const options = {
  scenarios: {
    sustained_reads: {
      executor: 'constant-arrival-rate',
      rate: 500,
      timeUnit: '1s',
      duration: '2m',
      preAllocatedVUs: 30,
      maxVUs: 150,
    },
  },
  thresholds: {
    http_req_duration: ['p(95)<200', 'p(99)<400'],
    nhi_list_latency: ['p(95)<150', 'p(99)<300'],
    nhi_scan_latency: ['p(95)<500', 'p(99)<1000'],
    http_req_failed: ['rate<0.01'],
  },
};

const IDENTITY_TYPES = ['service_account', 'api_key', 'bot', 'ci_pipeline', 'iac_runner'];
const ENVIRONMENTS = ['production', 'staging', 'development'];
const RISK_LEVELS = ['low', 'medium', 'high', 'critical'];
const PROVIDERS = ['aws', 'gcp', 'azure', 'kubernetes'];

// --- Setup -----------------------------------------------------------------

export function setup() {
  const token = login(TEST_EMAIL, TEST_PASSWORD);
  if (!token) {
    throw new Error('Setup failed: could not authenticate.');
  }
  return { token };
}

// --- VU iteration ----------------------------------------------------------

export default function (data) {
  const token = data.token;

  // 1. List identities with various filters
  group('nhi_list', () => {
    const filterType = randomChoice(IDENTITY_TYPES);
    const env = randomChoice(ENVIRONMENTS);
    const offset = randomInt(0, 5) * 20;

    const res = authGet(
      `/nhi/identities?limit=20&offset=${offset}&type=${filterType}&environment=${env}`,
      token,
      200,
      'nhi_list_identities',
    );
    listLatency.add(res.timings.duration);
  });

  // 2. Shadow AI detection
  group('nhi_shadow_ai', () => {
    authGet('/nhi/shadow-ai', token, 200, 'nhi_shadow_ai');

    if (randomInt(0, 10) < 3) {
      authGet(
        `/nhi/shadow-ai?provider=${randomChoice(PROVIDERS)}&risk=${randomChoice(RISK_LEVELS)}`,
        token,
        200,
        'nhi_shadow_ai_filtered',
      );
    }
  });

  // 3. NHI metrics
  group('nhi_metrics', () => {
    authGet('/nhi/metrics', token, 200, 'nhi_metrics');

    if (randomInt(0, 10) < 2) {
      authGet('/nhi/metrics/trends?period=7d', token, 200, 'nhi_metrics_trends');
    }
  });

  // 4. Trigger scan (~10% of iterations to avoid overwhelming workers)
  if (randomInt(0, 10) < 1) {
    group('nhi_scan', () => {
      const payload = {
        scan_type: randomChoice(['full', 'incremental', 'shadow_only']),
        providers: [randomChoice(PROVIDERS)],
        environment: randomChoice(ENVIRONMENTS),
      };

      const res = authPost('/nhi/scan', payload, token, 202, 'nhi_trigger_scan');
      scanLatency.add(res.timings.duration);
      scanCount.add(1);
    });
  }

  sleep(0.01);
}
