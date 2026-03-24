/**
 * Agent Firewall load test -- exercises the AI agent firewall endpoints
 * under sustained and burst traffic patterns.
 *
 * Tests evaluate tool call authorization, anomaly detection, and firewall
 * policy enforcement under high throughput.
 *
 * Usage:
 *   k6 run tests/load/scenarios/agent-firewall-load.js
 *   k6 run tests/load/scenarios/agent-firewall-load.js -e API_URL=http://staging:8000/api/v1
 */

import http from 'k6/http';
import { check, group, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';
import { BASE_URL, TEST_EMAIL, TEST_PASSWORD } from '../config.js';
import { login, authHeaders, authGet, authPost, randomInt, randomChoice } from '../helpers.js';

// Custom metrics
const blockRate = new Rate('firewall_block_rate');
const evaluateLatency = new Trend('firewall_evaluate_latency');

export const options = {
  scenarios: {
    // Sustained load: evaluate tool calls
    evaluate_calls: {
      executor: 'constant-arrival-rate',
      rate: 1000,
      timeUnit: '1s',
      duration: '2m',
      preAllocatedVUs: 50,
      maxVUs: 200,
    },
    // Burst: simulate agent anomaly storm
    anomaly_burst: {
      executor: 'ramping-arrival-rate',
      startRate: 100,
      timeUnit: '1s',
      stages: [
        { duration: '30s', target: 2000 },
        { duration: '30s', target: 100 },
      ],
      preAllocatedVUs: 100,
      maxVUs: 500,
      startTime: '2m',
    },
  },
  thresholds: {
    http_req_duration: ['p(95)<100', 'p(99)<200'],
    firewall_evaluate_latency: ['p(95)<50', 'p(99)<100'],
    firewall_block_rate: ['rate<0.5'],
  },
};

const AGENT_IDS = ['agent-001', 'agent-002', 'agent-003', 'agent-004', 'agent-005'];
const TOOL_NAMES = ['query_database', 'send_email', 'read_file', 'api_call', 'execute_command'];
const RISK_LEVELS = ['low', 'medium', 'high', 'critical'];

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
  const headers = authHeaders(token);

  group('firewall_evaluate', () => {
    const agentId = randomChoice(AGENT_IDS);
    const toolName = randomChoice(TOOL_NAMES);

    const payload = {
      agent_id: agentId,
      tool_name: toolName,
      args_summary: `${toolName} with standard params`,
      data_volume_bytes: randomInt(100, 10000),
      risk_level: randomChoice(RISK_LEVELS),
    };

    const res = authPost(
      `/agent-firewall/agents/${agentId}/evaluate`,
      payload,
      token,
      200,
      'firewall_evaluate',
    );

    evaluateLatency.add(res.timings.duration);

    try {
      const body = JSON.parse(res.body);
      check(res, {
        'has decision': () => body.decision !== undefined,
        'decision is valid': () => ['allow', 'block', 'review'].includes(body.decision),
      });
      blockRate.add(body.decision === 'block');
    } catch (_) {
      blockRate.add(false);
    }
  });

  group('firewall_status', () => {
    // Check firewall status and rules (read-heavy)
    authGet('/agent-firewall/status', token, 200, 'firewall_status');

    if (randomInt(0, 10) < 3) {
      authGet('/agent-firewall/rules', token, 200, 'firewall_rules');
    }

    if (randomInt(0, 10) < 2) {
      const agentId = randomChoice(AGENT_IDS);
      authGet(
        `/agent-firewall/agents/${agentId}/history?limit=20`,
        token,
        200,
        'firewall_agent_history',
      );
    }
  });

  sleep(0.01);
}
