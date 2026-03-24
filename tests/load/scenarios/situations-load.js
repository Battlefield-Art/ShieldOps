/**
 * Situations load test -- exercises the correlated situations (incident
 * grouping) endpoints including listing, detail views, metrics, and
 * action execution under sustained traffic.
 *
 * Usage:
 *   k6 run tests/load/scenarios/situations-load.js
 *   k6 run tests/load/scenarios/situations-load.js -e API_URL=http://staging:8000/api/v1
 */

import { group, sleep } from 'k6';
import { Trend, Counter } from 'k6/metrics';
import { BASE_URL, THRESHOLDS, THRESHOLDS_RELAXED, TEST_EMAIL, TEST_PASSWORD } from '../config.js';
import { login, authGet, authPost, randomInt, randomChoice } from '../helpers.js';

// Custom metrics
const listLatency = new Trend('situations_list_latency');
const detailLatency = new Trend('situations_detail_latency');
const actionLatency = new Trend('situations_action_latency');
const actionsExecuted = new Counter('situations_actions_executed');

export const options = {
  scenarios: {
    sustained_reads: {
      executor: 'constant-arrival-rate',
      rate: 200,
      timeUnit: '1s',
      duration: '2m',
      preAllocatedVUs: 15,
      maxVUs: 80,
    },
  },
  thresholds: {
    http_req_duration: ['p(95)<300', 'p(99)<600'],
    situations_list_latency: ['p(95)<200', 'p(99)<400'],
    situations_detail_latency: ['p(95)<150', 'p(99)<300'],
    situations_action_latency: ['p(95)<500', 'p(99)<1000'],
    http_req_failed: ['rate<0.01'],
  },
};

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const STATUSES = ['active', 'investigating', 'mitigated', 'resolved'];
const CATEGORIES = ['infrastructure', 'security', 'performance', 'availability', 'capacity'];
const ACTION_TYPES = ['acknowledge', 'escalate', 'suppress', 'remediate', 'notify'];
const SITUATION_IDS = [
  'sit-2024-001', 'sit-2024-002', 'sit-2024-003',
  'sit-2024-004', 'sit-2024-005', 'sit-2024-006',
];
const ACTION_IDS = ['act-001', 'act-002', 'act-003', 'act-004'];

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

  // 1. List situations with filters
  group('situations_list', () => {
    const severity = randomChoice(SEVERITIES);
    const status = randomChoice(STATUSES);
    const offset = randomInt(0, 5) * 10;

    const res = authGet(
      `/situations?limit=10&offset=${offset}&severity=${severity}&status=${status}`,
      token,
      200,
      'situations_list',
    );
    listLatency.add(res.timings.duration);

    // Filter by category occasionally
    if (randomInt(0, 10) < 3) {
      const category = randomChoice(CATEGORIES);
      authGet(
        `/situations?category=${category}&limit=10`,
        token,
        200,
        'situations_list_by_category',
      );
    }
  });

  // 2. Situation detail
  group('situations_detail', () => {
    const situationId = randomChoice(SITUATION_IDS);
    const res = authGet(
      `/situations/${situationId}`,
      token,
      200,
      'situations_detail',
    );
    detailLatency.add(res.timings.duration);

    // Fetch related alerts for the situation
    if (randomInt(0, 10) < 4) {
      authGet(
        `/situations/${situationId}/alerts`,
        token,
        200,
        'situations_alerts',
      );
    }

    // Fetch timeline
    if (randomInt(0, 10) < 3) {
      authGet(
        `/situations/${situationId}/timeline`,
        token,
        200,
        'situations_timeline',
      );
    }
  });

  // 3. Metrics dashboard data
  group('situations_metrics', () => {
    authGet('/situations/metrics', token, 200, 'situations_metrics');

    if (randomInt(0, 10) < 2) {
      authGet('/situations/metrics/trends?period=24h', token, 200, 'situations_metrics_trends');
    }
  });

  // 4. Execute action (~5% of iterations to avoid side-effect overload)
  if (randomInt(0, 20) < 1) {
    group('situations_actions', () => {
      const situationId = randomChoice(SITUATION_IDS);
      const actionId = randomChoice(ACTION_IDS);
      const payload = {
        action_type: randomChoice(ACTION_TYPES),
        reason: 'k6 load test -- automated action execution',
        parameters: {
          notify_channel: randomChoice(['slack', 'pagerduty', 'email']),
          priority: randomChoice(['p1', 'p2', 'p3']),
        },
      };

      const res = authPost(
        `/situations/${situationId}/actions/${actionId}/execute`,
        payload,
        token,
        202,
        'situations_execute_action',
      );
      actionLatency.add(res.timings.duration);
      actionsExecuted.add(1);
    });
  }

  sleep(0.01);
}
