/**
 * MCP Security load test -- exercises Model Context Protocol security
 * endpoints including server listing, god-key detection, zero-trust
 * verification, and security scanning.
 *
 * Usage:
 *   k6 run tests/load/scenarios/mcp-security-load.js
 *   k6 run tests/load/scenarios/mcp-security-load.js -e API_URL=http://staging:8000/api/v1
 */

import { group, sleep } from 'k6';
import { Trend, Counter } from 'k6/metrics';
import { BASE_URL, THRESHOLDS, TEST_EMAIL, TEST_PASSWORD } from '../config.js';
import { login, authGet, authPost, randomInt, randomChoice } from '../helpers.js';

// Custom metrics
const godKeyLatency = new Trend('mcp_godkey_detect_latency');
const scanLatency = new Trend('mcp_scan_latency');
const scanCount = new Counter('mcp_scans_triggered');

export const options = {
  scenarios: {
    sustained_reads: {
      executor: 'constant-arrival-rate',
      rate: 300,
      timeUnit: '1s',
      duration: '2m',
      preAllocatedVUs: 20,
      maxVUs: 100,
    },
  },
  thresholds: {
    http_req_duration: ['p(95)<200', 'p(99)<400'],
    mcp_godkey_detect_latency: ['p(95)<100', 'p(99)<250'],
    mcp_scan_latency: ['p(95)<500', 'p(99)<1000'],
    http_req_failed: ['rate<0.01'],
  },
};

const SERVER_STATUSES = ['active', 'inactive', 'quarantined'];
const SCAN_SCOPES = ['full', 'servers_only', 'keys_only', 'permissions'];
const TRUST_LEVELS = ['verified', 'unverified', 'revoked'];
const SERVER_IDS = ['mcp-srv-001', 'mcp-srv-002', 'mcp-srv-003', 'mcp-srv-004', 'mcp-srv-005'];

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

  // 1. List MCP servers with filters
  group('mcp_servers', () => {
    const status = randomChoice(SERVER_STATUSES);
    authGet(
      `/mcp-security/servers?status=${status}&limit=20`,
      token,
      200,
      'mcp_list_servers',
    );

    if (randomInt(0, 10) < 3) {
      const serverId = randomChoice(SERVER_IDS);
      authGet(
        `/mcp-security/servers/${serverId}`,
        token,
        200,
        'mcp_server_detail',
      );
    }
  });

  // 2. God-key detection
  group('mcp_god_keys', () => {
    const res = authGet('/mcp-security/god-keys', token, 200, 'mcp_god_keys');
    godKeyLatency.add(res.timings.duration);

    if (randomInt(0, 10) < 2) {
      authGet(
        '/mcp-security/god-keys/history?period=30d',
        token,
        200,
        'mcp_god_keys_history',
      );
    }
  });

  // 3. Zero-trust status
  group('mcp_zero_trust', () => {
    authGet('/mcp-security/zero-trust', token, 200, 'mcp_zero_trust');

    if (randomInt(0, 10) < 3) {
      const trust = randomChoice(TRUST_LEVELS);
      authGet(
        `/mcp-security/zero-trust?trust_level=${trust}`,
        token,
        200,
        'mcp_zero_trust_filtered',
      );
    }
  });

  // 4. Trigger scan (~10% of iterations)
  if (randomInt(0, 10) < 1) {
    group('mcp_scan', () => {
      const payload = {
        scope: randomChoice(SCAN_SCOPES),
        server_ids: [randomChoice(SERVER_IDS)],
        deep_inspection: randomInt(0, 2) === 0,
      };

      const res = authPost('/mcp-security/scan', payload, token, 202, 'mcp_trigger_scan');
      scanLatency.add(res.timings.duration);
      scanCount.add(1);
    });
  }

  sleep(0.01);
}
