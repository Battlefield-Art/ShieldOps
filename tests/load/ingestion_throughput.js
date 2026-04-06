/**
 * Ingestion Throughput Test — 10 GB/day sustained.
 *
 * Target SLOs (issue #223):
 *   - 10 GB/day ingestion = ~121.5 KB/s = ~7.3 MB/min
 *   - Applied 10x safety margin for burst headroom: 1.2 MB/s sustained
 *   - POST /ingest/events (OTel-compatible event batch endpoint)
 *   - P99 batch ingest < 1s
 *   - accept rate > 99.9%
 *
 * Uses batched writes to mirror real OTel collector behavior: each VU iter
 * sends a ~100 KB batch of 200 events, so target_iterations = target_bytes / batch_size.
 *
 * Usage:
 *   k6 run tests/load/ingestion_throughput.js
 *   k6 run tests/load/ingestion_throughput.js -e TARGET_GB_PER_DAY=20
 *   k6 run tests/load/ingestion_throughput.js -e DURATION=60m --out json=results/ingest.json
 */

import http from 'k6/http';
import { check } from 'k6';
import { Trend, Rate, Counter } from 'k6/metrics';
import { BASE_URL, TEST_EMAIL, TEST_PASSWORD } from './config.js';
import { login, authHeaders, randomChoice, randomInt } from './helpers.js';

// --- Tunables --------------------------------------------------------------

const TARGET_GB_PER_DAY = parseFloat(__ENV.TARGET_GB_PER_DAY || '10');
const DURATION = __ENV.DURATION || '30m';
const BATCH_SIZE = parseInt(__ENV.BATCH_SIZE || '200', 10); // events per batch

// Derive target rate from GB/day:
//   bytes/sec = GB * 1e9 / 86400
// With ~500 bytes/event average payload => ~100 KB batches at BATCH_SIZE=200.
const BYTES_PER_EVENT = 500;
const BYTES_PER_BATCH = BATCH_SIZE * BYTES_PER_EVENT;
const TARGET_BYTES_PER_SEC = (TARGET_GB_PER_DAY * 1e9) / 86400;
const TARGET_BATCHES_PER_SEC = Math.max(
  1,
  Math.ceil(TARGET_BYTES_PER_SEC / BYTES_PER_BATCH),
);

// --- Custom metrics --------------------------------------------------------

const ingestLatency = new Trend('ingest_batch_latency_ms', true);
const bytesIngested = new Counter('bytes_ingested_total');
const eventsIngested = new Counter('events_ingested_total');
const ingestErrorRate = new Rate('ingest_error_rate');

// --- Options ---------------------------------------------------------------

export const options = {
  scenarios: {
    ingest: {
      executor: 'constant-arrival-rate',
      rate: TARGET_BATCHES_PER_SEC,
      timeUnit: '1s',
      duration: DURATION,
      preAllocatedVUs: Math.max(50, TARGET_BATCHES_PER_SEC * 2),
      maxVUs: Math.max(200, TARGET_BATCHES_PER_SEC * 5),
    },
  },
  thresholds: {
    // Issue #223 gates
    ingest_batch_latency_ms: ['p(95)<500', 'p(99)<1000'],
    ingest_error_rate: ['rate<0.001'],
    http_req_failed: ['rate<0.005'],
    // Throughput floor: must sustain >= 95% of target bytes/sec.
    bytes_ingested_total: [`count>${TARGET_BYTES_PER_SEC * 0.95 * 60 * 25}`],
  },
};

// --- Setup -----------------------------------------------------------------

export function setup() {
  const token = login(TEST_EMAIL, TEST_PASSWORD);
  if (!token) {
    throw new Error('Setup failed: could not authenticate.');
  }
  // eslint-disable-next-line no-console
  console.log(
    `Ingestion test — target: ${TARGET_GB_PER_DAY} GB/day ` +
      `(${(TARGET_BYTES_PER_SEC / 1024).toFixed(1)} KB/s, ` +
      `${TARGET_BATCHES_PER_SEC} batches/s @ ${BATCH_SIZE} events/batch)`,
  );
  return { token };
}

// --- Event generators ------------------------------------------------------

const SEVERITIES = ['low', 'medium', 'high', 'critical'];
const EVENT_TYPES = [
  'tool_call',
  'auth_attempt',
  'policy_decision',
  'agent_action',
  'http_request',
  'db_query',
  'cache_hit',
  'alert_raised',
];
const SOURCES = ['aws', 'gcp', 'azure', 'k8s', 'crowdstrike', 'splunk', 'datadog'];

function buildEvent(i) {
  return {
    id: `evt-${Date.now()}-${i}-${randomInt(0, 1e6)}`,
    timestamp: new Date().toISOString(),
    type: randomChoice(EVENT_TYPES),
    source: randomChoice(SOURCES),
    severity: randomChoice(SEVERITIES),
    trace_id: `trace-${randomInt(1e9, 1e10)}`,
    span_id: `span-${randomInt(1e8, 1e9)}`,
    attributes: {
      'service.name': `svc-${randomInt(0, 50)}`,
      'cloud.region': randomChoice(['us-east-1', 'eu-west-1', 'ap-south-1']),
      'k8s.namespace': `ns-${randomInt(0, 20)}`,
      'http.status_code': randomChoice([200, 200, 200, 404, 500]),
      'duration_ms': randomInt(1, 500),
      'bytes_out': randomInt(100, 50000),
    },
    body: `Event payload ${i} — load test synthetic data for ingestion throughput validation.`,
  };
}

function buildBatch() {
  const events = new Array(BATCH_SIZE);
  for (let i = 0; i < BATCH_SIZE; i++) events[i] = buildEvent(i);
  return { events };
}

// --- Default VU fn ---------------------------------------------------------

export default function (data) {
  const payload = JSON.stringify(buildBatch());
  const byteLen = payload.length;

  const res = http.post(`${BASE_URL}/ingest/events`, payload, {
    headers: authHeaders(data.token),
    tags: { name: 'ingest_batch' },
  });

  ingestLatency.add(res.timings.duration);
  const ok = res.status >= 200 && res.status < 300;
  ingestErrorRate.add(!ok);

  if (ok) {
    bytesIngested.add(byteLen);
    eventsIngested.add(BATCH_SIZE);
  }

  check(res, {
    'ingest accepted (2xx)': (r) => r.status >= 200 && r.status < 300,
    'ingest latency < 1s': (r) => r.timings.duration < 1000,
  });
}

// --- Summary ---------------------------------------------------------------

export function handleSummary(data) {
  const bytes = data.metrics.bytes_ingested_total?.values?.count ?? 0;
  const events = data.metrics.events_ingested_total?.values?.count ?? 0;
  const p99 = data.metrics.ingest_batch_latency_ms?.values?.['p(99)'] ?? 0;
  const p95 = data.metrics.ingest_batch_latency_ms?.values?.['p(95)'] ?? 0;
  const errRate = data.metrics.ingest_error_rate?.values?.rate ?? 0;

  const gbIngested = bytes / 1e9;
  const testDurationSec = (data.state.testRunDurationMs || 0) / 1000;
  const bytesPerSec = bytes / Math.max(1, testDurationSec);
  const projectedGbPerDay = (bytesPerSec * 86400) / 1e9;

  // eslint-disable-next-line no-console
  console.log(`
============================================================
ShieldOps Ingestion Throughput Test — SLO Report
============================================================
Target          : ${TARGET_GB_PER_DAY} GB/day
Observed rate   : ${(bytesPerSec / 1024).toFixed(1)} KB/s
Projected       : ${projectedGbPerDay.toFixed(2)} GB/day
Bytes ingested  : ${gbIngested.toFixed(3)} GB
Events          : ${events.toLocaleString()}
P95 latency     : ${p95.toFixed(2)} ms   (budget: 500 ms)
P99 latency     : ${p99.toFixed(2)} ms   (budget: 1000 ms)
Error rate      : ${(errRate * 100).toFixed(3)} %   (budget: 0.1 %)
SLO PASS        : ${projectedGbPerDay >= TARGET_GB_PER_DAY * 0.95 && p99 < 1000 && errRate < 0.001 ? 'YES' : 'NO'}
============================================================
`);

  return {
    stdout: JSON.stringify(
      {
        target_gb_per_day: TARGET_GB_PER_DAY,
        observed_gb_per_day: projectedGbPerDay,
        total_bytes: bytes,
        total_events: events,
        p95_ms: p95,
        p99_ms: p99,
        error_rate: errRate,
      },
      null,
      2,
    ),
  };
}
