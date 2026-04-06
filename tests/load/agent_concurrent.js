/**
 * Agent Concurrent Execution Test — 100 concurrent agent runs.
 *
 * Target SLOs (issue #223):
 *   - 100 concurrent agent runs
 *   - P99 agent completion < 30s
 *   - error rate < 2% (agents may retry / escalate)
 *
 * This test exercises the full LangGraph execution pipeline: POST /agents/{type}/run
 * returns 202 + run_id, then we poll /agents/runs/{run_id} until terminal state.
 *
 * Usage:
 *   k6 run tests/load/agent_concurrent.js
 *   k6 run tests/load/agent_concurrent.js -e CONCURRENCY=200 -e DURATION=15m
 */

import http from 'k6/http';
import { check, sleep, fail } from 'k6';
import { Trend, Rate, Counter } from 'k6/metrics';
import { BASE_URL, TEST_EMAIL, TEST_PASSWORD } from './config.js';
import { login, authHeaders, randomChoice } from './helpers.js';

// --- Tunables --------------------------------------------------------------

const CONCURRENCY = parseInt(__ENV.CONCURRENCY || '100', 10);
const DURATION = __ENV.DURATION || '10m';
const POLL_INTERVAL_SEC = parseFloat(__ENV.POLL_INTERVAL_SEC || '1.0');
const AGENT_TIMEOUT_SEC = parseInt(__ENV.AGENT_TIMEOUT_SEC || '60', 10);

// --- Custom metrics --------------------------------------------------------

const agentRunDuration = new Trend('agent_run_duration_ms', true);
const agentSuccessRate = new Rate('agent_success_rate');
const agentTimeouts = new Counter('agent_timeouts_total');
const agentStarts = new Counter('agent_starts_total');

// --- Options ---------------------------------------------------------------

export const options = {
  scenarios: {
    concurrent_agents: {
      executor: 'constant-vus',
      vus: CONCURRENCY,
      duration: DURATION,
    },
  },
  thresholds: {
    // Issue #223 gates
    agent_run_duration_ms: ['p(95)<20000', 'p(99)<30000'],
    agent_success_rate: ['rate>0.98'],
    agent_timeouts_total: ['count<10'],
    http_req_failed: ['rate<0.02'],
  },
};

// --- Setup -----------------------------------------------------------------

export function setup() {
  const token = login(TEST_EMAIL, TEST_PASSWORD);
  if (!token) {
    fail('Setup failed: could not authenticate.');
  }
  return { token };
}

// --- Agent catalog ---------------------------------------------------------
// Launch agents from GTM strategy (see MEMORY.md).

const AGENT_TYPES = [
  {
    type: 'investigation',
    input: { alert_id: 'alert-load-test', severity: 'high', source: 'load-test' },
  },
  {
    type: 'remediation',
    input: { finding_id: 'finding-load-test', auto_approve: false },
  },
  {
    type: 'soc_analyst',
    input: { event: 'suspicious_login', user: 'loadtest@example.com' },
  },
  {
    type: 'threat_hunter',
    input: { hypothesis: 'lateral movement via SSH', scope: 'prod' },
  },
  {
    type: 'incident_response',
    input: { incident_id: 'inc-load-test', severity: 'medium' },
  },
  {
    type: 'vulnerability_manager',
    input: { scope: 'prod-cluster', cve_filter: 'high' },
  },
  {
    type: 'compliance_auditor',
    input: { framework: 'SOC2', scope: 'production' },
  },
  {
    type: 'identity_graph',
    input: { principal: 'user:loadtest', depth: 2 },
  },
];

// --- VU function -----------------------------------------------------------

export default function (data) {
  const headers = authHeaders(data.token);
  const agent = randomChoice(AGENT_TYPES);

  // 1. Kick off agent run.
  const startTs = Date.now();
  const startRes = http.post(
    `${BASE_URL}/agents/${agent.type}/run`,
    JSON.stringify({ input: agent.input, mode: 'audit' }),
    { headers, tags: { name: 'agent_start', agent_type: agent.type } },
  );
  agentStarts.add(1);

  const accepted = check(startRes, {
    'agent start accepted': (r) => r.status === 200 || r.status === 202,
    'agent start returns run_id': (r) => {
      try {
        return !!r.json('run_id');
      } catch (_) {
        return false;
      }
    },
  });

  if (!accepted) {
    agentSuccessRate.add(false);
    sleep(POLL_INTERVAL_SEC);
    return;
  }

  const runId = startRes.json('run_id');

  // 2. Poll for completion.
  const deadline = startTs + AGENT_TIMEOUT_SEC * 1000;
  let terminal = false;
  let succeeded = false;

  while (Date.now() < deadline) {
    sleep(POLL_INTERVAL_SEC);
    const pollRes = http.get(`${BASE_URL}/agents/runs/${runId}`, {
      headers,
      tags: { name: 'agent_poll', agent_type: agent.type },
    });
    if (pollRes.status !== 200) continue;

    let status;
    try {
      status = pollRes.json('status');
    } catch (_) {
      continue;
    }

    if (status === 'completed' || status === 'succeeded') {
      terminal = true;
      succeeded = true;
      break;
    }
    if (status === 'failed' || status === 'error' || status === 'cancelled') {
      terminal = true;
      succeeded = false;
      break;
    }
  }

  const elapsed = Date.now() - startTs;

  if (!terminal) {
    agentTimeouts.add(1);
    agentSuccessRate.add(false);
  } else {
    agentRunDuration.add(elapsed);
    agentSuccessRate.add(succeeded);
  }

  check(null, {
    'agent completed within 30s': () => terminal && elapsed < 30000,
  });
}

// --- Summary ---------------------------------------------------------------

export function handleSummary(data) {
  const p99 = data.metrics.agent_run_duration_ms?.values?.['p(99)'] ?? 0;
  const p95 = data.metrics.agent_run_duration_ms?.values?.['p(95)'] ?? 0;
  const successRate = data.metrics.agent_success_rate?.values?.rate ?? 0;
  const timeouts = data.metrics.agent_timeouts_total?.values?.count ?? 0;
  const starts = data.metrics.agent_starts_total?.values?.count ?? 0;

  // eslint-disable-next-line no-console
  console.log(`
============================================================
ShieldOps Agent Concurrent Test — SLO Report
============================================================
Concurrency     : ${CONCURRENCY}
Total runs      : ${starts}
P95 duration    : ${(p95 / 1000).toFixed(2)} s   (budget: 20 s)
P99 duration    : ${(p99 / 1000).toFixed(2)} s   (budget: 30 s)
Success rate    : ${(successRate * 100).toFixed(2)} %   (budget: >=98 %)
Timeouts        : ${timeouts}
SLO PASS        : ${p99 < 30000 && successRate >= 0.98 ? 'YES' : 'NO'}
============================================================
`);

  return {
    stdout: JSON.stringify(
      {
        concurrency: CONCURRENCY,
        total_runs: starts,
        p95_ms: p95,
        p99_ms: p99,
        success_rate: successRate,
        timeouts: timeouts,
      },
      null,
      2,
    ),
  };
}
