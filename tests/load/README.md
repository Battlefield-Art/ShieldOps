# ShieldOps Load Tests

k6-based load testing suite for the ShieldOps API. Each scenario is independently
runnable and targets a specific workload pattern.

## Prerequisites

Install k6 (the test runner -- no npm packages required):

```bash
# macOS
brew install k6

# Linux (Debian/Ubuntu)
sudo gpg -k
sudo gpg --no-default-keyring --keyring /usr/share/keyrings/k6-archive-keyring.gpg \
  --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D69
echo "deb [signed-by=/usr/share/keyrings/k6-archive-keyring.gpg] https://dl.k6.io/deb stable main" \
  | sudo tee /etc/apt/sources.list.d/k6.list
sudo apt-get update && sudo apt-get install k6

# Docker (no install needed)
docker run --rm -i grafana/k6 run - < tests/load/smoke-test.js
```

## Running Tests

Start the API server first:

```bash
make run-api
```

### Quick smoke test

```bash
k6 run tests/load/smoke-test.js
# or via Makefile
make load-test
```

### Issue #223 SLO tests

The three top-level scripts target the GA launch SLOs from issue #223.

```bash
# 1000 RPS sustained 30 min, P99 < 500ms
k6 run tests/load/api_load.js

# 100 concurrent agent runs, P99 < 30s
k6 run tests/load/agent_concurrent.js

# 10 GB/day ingestion throughput
k6 run tests/load/ingestion_throughput.js
```

Each script prints an SLO PASS/NO summary block after the run. Tune via env:

| Script                   | Key env vars                                    |
| ------------------------ | ----------------------------------------------- |
| `api_load.js`            | `TARGET_RPS` (1000), `DURATION` (30m)            |
| `agent_concurrent.js`    | `CONCURRENCY` (100), `DURATION` (10m), `AGENT_TIMEOUT_SEC` (60) |
| `ingestion_throughput.js`| `TARGET_GB_PER_DAY` (10), `BATCH_SIZE` (200)     |

### Full scenario suite

```bash
# API CRUD operations (investigations + remediations)
k6 run tests/load/scenarios/api-crud.js

# Authentication flow (login, refresh, verify)
k6 run tests/load/scenarios/auth-flow.js

# Dashboard read-heavy workload (analytics, security, vulnerabilities)
k6 run tests/load/scenarios/read-heavy.js

# WebSocket connection stress
k6 run tests/load/scenarios/websocket.js

# or via Makefile
make load-test-full
```

### Selecting a stage profile

Every scenario defaults to the `load` profile. Override via the `PROFILE` env var:

```bash
# Smoke (light, quick validation)
k6 run tests/load/scenarios/api-crud.js -e PROFILE=smoke

# Stress (push past capacity)
k6 run tests/load/scenarios/api-crud.js -e PROFILE=stress

# Spike (sudden burst)
k6 run tests/load/scenarios/api-crud.js -e PROFILE=spike
```

### Targeting a different environment

```bash
k6 run tests/load/smoke-test.js \
  -e API_URL=https://staging.shieldops.io/api/v1 \
  -e WS_URL=wss://staging.shieldops.io \
  -e TEST_EMAIL=loadtest@shieldops.io \
  -e TEST_PASSWORD=s3cureP@ss
```

## Environment Variables

| Variable        | Default                           | Description                        |
| --------------- | --------------------------------- | ---------------------------------- |
| `API_URL`       | `http://localhost:8000/api/v1`    | Base URL for REST endpoints        |
| `WS_URL`        | `ws://localhost:8000`             | Base URL for WebSocket endpoints   |
| `TEST_EMAIL`    | `admin@shieldops.io`             | Login email for test user          |
| `TEST_PASSWORD` | `admin123`                        | Login password for test user       |
| `PROFILE`       | `load`                            | Stage profile: smoke/load/stress/spike |

## Scenarios

| File                        | Purpose                                         | Key Endpoints                                   |
| --------------------------- | ----------------------------------------------- | ----------------------------------------------- |
| `smoke-test.js`             | Quick health validation                         | /health, /investigations, /remediations, /agents |
| `scenarios/api-crud.js`     | CRUD load on core resources                     | POST/GET /investigations, POST/GET /remediations |
| `scenarios/auth-flow.js`    | Authentication lifecycle under concurrency      | /auth/login, /auth/me, /auth/refresh            |
| `scenarios/read-heavy.js`   | Dashboard read pattern (most realistic)         | /analytics/*, /security/*, /vulnerabilities/*   |
| `scenarios/websocket.js`    | WebSocket connection capacity                   | /ws/events, /ws/vulnerabilities                 |

## Thresholds

Default thresholds (applied in `config.js`):

| Metric              | Condition         | Meaning                                     |
| ------------------- | ----------------- | ------------------------------------------- |
| `http_req_duration` | p(95) < 200ms     | 95th percentile response time under 200ms   |
| `http_req_duration` | p(99) < 500ms     | 99th percentile response time under 500ms   |
| `http_req_failed`   | rate < 1%          | Less than 1% of requests fail               |
| `http_reqs`         | rate > 100 req/s   | Sustained throughput above 100 requests/sec  |

Scenarios may add additional thresholds for specific endpoints (e.g., auth
latency, WebSocket connect rate).

## Stage Profiles

| Profile | Ramp-up | Sustained | Peak VUs | Total Duration |
| ------- | ------- | --------- | -------- | -------------- |
| smoke   | 30s     | 1m        | 5        | 2m             |
| load    | 2m      | 5m        | 50       | 9m             |
| stress  | 2m      | 10m       | 300      | 19m            |
| spike   | 1m      | 10s burst | 500      | ~2.5m          |

## Interpreting Results

k6 prints a summary table after each run. Key things to check:

1. **http_req_duration**: Look at p(95) and p(99). Values above thresholds
   indicate the API is struggling under the given load.

2. **http_req_failed**: Any value above 0% warrants investigation. Check
   which endpoints are failing by looking at tagged metrics.

3. **iterations**: Total completed VU iterations. A low count relative to
   VUs and duration suggests requests are timing out or blocking.

4. **checks**: Percentage of passed checks. Anything below 100% means some
   responses did not meet expected status codes or body shapes.

For detailed per-endpoint breakdowns, use the `--out json=results.json` flag
and analyze with k6 Cloud, Grafana, or a custom script.

## CI Integration

Add to your GitHub Actions workflow:

```yaml
- name: Run load tests (smoke)
  run: |
    k6 run tests/load/smoke-test.js \
      -e API_URL=${{ secrets.STAGING_API_URL }}
```

For full load tests in CI, use the `smoke` profile to keep run times short,
and reserve `load`/`stress` profiles for scheduled nightly runs.

A manual-trigger workflow is provided at `.github/workflows/load-test.yml`:

```bash
gh workflow run load-test.yml -f script=api_load.js -f target_rps=1000
```

## Baseline Numbers

Record the observed numbers from your first clean run so future runs have a
regression baseline. These will be filled in after the first validated run.

| Script                    | Target             | Observed | Date | Commit | Env      |
| ------------------------- | ------------------ | -------- | ---- | ------ | -------- |
| `api_load.js`             | 1000 RPS, P99<500ms| TBD      | TBD  | TBD    | staging  |
| `agent_concurrent.js`     | 100 conc, P99<30s  | TBD      | TBD  | TBD    | staging  |
| `ingestion_throughput.js` | 10 GB/day          | TBD      | TBD  | TBD    | staging  |

## Chaos Engineering (tests/chaos/)

Chaos scripts verify graceful degradation and recovery SLOs. All require
pre-configured cloud credentials (AWS CLI, kubectl, docker, redis-cli,
kafka-* CLI tools as applicable).

| Script                       | What it does                                  | SLO gate                            |
| ---------------------------- | ---------------------------------------------- | ----------------------------------- |
| `test_ecs_task_kill.sh`      | `aws ecs stop-task`, verify auto-restart       | Replacement RUNNING < 120s, health streak <= 3 |
| `test_rds_failover.sh`       | `aws rds reboot --force-failover`, verify reconnect | API reconnects < 30s after DB ready |
| `test_redis_eviction.sh`     | Fill Redis past `maxmemory`, check degradation | /health 2xx throughout, cached endpoints work |
| `test_kafka_broker_down.sh`  | Kill broker, verify durability + ISR recovery  | Zero msg loss, max 5s health streak, ISR recovered < 60s |

### Running chaos tests

```bash
# ECS task kill (AWS)
CLUSTER=shieldops-prod SERVICE=shieldops-api \
  HEALTH_URL=https://api.shieldops.io/health \
  ./tests/chaos/test_ecs_task_kill.sh

# RDS failover
DB_INSTANCE=shieldops-prod-db \
  HEALTH_URL=https://api.shieldops.io/health \
  ./tests/chaos/test_rds_failover.sh

# Redis eviction
REDIS_HOST=prod-redis.shieldops.io \
  HEALTH_URL=https://api.shieldops.io/health \
  CACHED_URL=https://api.shieldops.io/api/v1/analytics/summary \
  AUTH_TOKEN=$(gh secret get CHAOS_TEST_TOKEN) \
  ./tests/chaos/test_redis_eviction.sh

# Kafka broker kill (K8s)
BROKER_POD=kafka-0 NAMESPACE=shieldops \
  HEALTH_URL=https://api.shieldops.io/health \
  TOPIC=shieldops.events \
  BOOTSTRAP=kafka.shieldops.svc:9092 \
  ./tests/chaos/test_kafka_broker_down.sh
```

Each script exits 0 on SLO pass and non-zero with a `FAIL:` message on
breach. Pipe into a notification tool (Slack, PagerDuty) for scheduled
game-days.

### Chaos scheduling

Recommended cadence:
- ECS task kill — weekly, automated
- Redis eviction — monthly, game-day
- RDS failover — quarterly, game-day (maintenance window)
- Kafka broker down — quarterly, game-day
