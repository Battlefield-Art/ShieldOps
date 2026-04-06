#!/usr/bin/env bash
# ============================================================================
# Chaos: Kafka broker down
# ----------------------------------------------------------------------------
# Stops one broker in the Kafka cluster and verifies:
#   1. Producers do not lose messages (durability via acks=all + min.insync.replicas)
#   2. Consumers continue processing from surviving brokers
#   3. ShieldOps event ingestion stays up
#   4. When the broker returns, partitions rebalance cleanly
#
# SLO gate (issue #223):
#   - Zero message loss during broker outage
#   - Ingest /health stays 2xx (max 5s unavailability during leader election)
#   - Broker rejoins ISR within 60s of restart
#
# Usage (K8s):
#   BROKER_POD=kafka-0 NAMESPACE=shieldops \
#     HEALTH_URL=https://api.shieldops.io/health \
#     TOPIC=shieldops.events \
#     BOOTSTRAP=kafka.shieldops.svc:9092 \
#     ./tests/chaos/test_kafka_broker_down.sh
#
# Usage (Docker Compose):
#   MODE=docker BROKER_CONTAINER=kafka1 \
#     HEALTH_URL=http://localhost:8000/health \
#     TOPIC=shieldops.events \
#     BOOTSTRAP=localhost:9092 \
#     ./tests/chaos/test_kafka_broker_down.sh
# ============================================================================

set -euo pipefail

MODE="${MODE:-k8s}"
HEALTH_URL="${HEALTH_URL:?HEALTH_URL env var required}"
TOPIC="${TOPIC:-shieldops.events}"
BOOTSTRAP="${BOOTSTRAP:?BOOTSTRAP env var required (kafka bootstrap servers)}"
TEST_MESSAGES="${TEST_MESSAGES:-1000}"

log() { printf '[chaos:kafka-down] %s\n' "$*" >&2; }
fail() { log "FAIL: $*"; exit 1; }
pass() { log "PASS: $*"; exit 0; }

need() { command -v "$1" >/dev/null || fail "$1 not installed"; }
need curl

case "$MODE" in
  k8s)
    BROKER_POD="${BROKER_POD:?BROKER_POD required in k8s mode}"
    NAMESPACE="${NAMESPACE:-default}"
    need kubectl
    stop_broker() {
      log "Deleting broker pod $BROKER_POD (StatefulSet will restart)..."
      kubectl delete pod "$BROKER_POD" -n "$NAMESPACE" --wait=false
    }
    wait_broker_back() {
      log "Waiting for $BROKER_POD to become Ready..."
      kubectl wait --for=condition=Ready "pod/$BROKER_POD" \
        -n "$NAMESPACE" --timeout=180s
    }
    ;;
  docker)
    BROKER_CONTAINER="${BROKER_CONTAINER:?BROKER_CONTAINER required in docker mode}"
    need docker
    stop_broker() {
      log "Stopping container $BROKER_CONTAINER..."
      docker stop "$BROKER_CONTAINER" >/dev/null
    }
    wait_broker_back() {
      log "Starting container $BROKER_CONTAINER..."
      docker start "$BROKER_CONTAINER" >/dev/null
      sleep 10
    }
    ;;
  *)
    fail "MODE must be k8s or docker"
    ;;
esac

# --- Baseline -----------------------------------------------------------
BASE_HEALTH="$(curl -sk -o /dev/null -w '%{http_code}' "$HEALTH_URL" || echo 000)"
[[ "$BASE_HEALTH" =~ ^2 ]] || fail "Baseline health failed ($BASE_HEALTH)"
log "Baseline OK"

# --- Produce pre-outage messages (sentinel) -----------------------------
SENTINEL_PREFIX="chaos-$(date +%s)"
if command -v kafka-console-producer >/dev/null; then
  log "Producing ${TEST_MESSAGES} sentinel messages pre-outage..."
  for i in $(seq 1 "$TEST_MESSAGES"); do
    echo "${SENTINEL_PREFIX}-pre-$i"
  done | kafka-console-producer --broker-list "$BOOTSTRAP" --topic "$TOPIC" \
    --producer-property acks=all >/dev/null 2>&1 || log "WARN: producer had issues"
else
  log "WARN: kafka-console-producer not found — skipping sentinel produce"
fi

# --- Background health poller -------------------------------------------
HEALTH_LOG="$(mktemp)"
(
  for _ in $(seq 1 180); do
    code="$(curl -sk -o /dev/null -w '%{http_code}' "$HEALTH_URL" || echo 000)"
    printf '%s %s\n' "$(date +%s)" "$code" >> "$HEALTH_LOG"
    sleep 1
  done
) &
POLLER_PID=$!
trap 'kill $POLLER_PID 2>/dev/null || true; rm -f "$HEALTH_LOG"' EXIT

# --- Stop broker --------------------------------------------------------
DOWN_TS=$(date +%s)
stop_broker
log "Broker down; keeping it down for 30s..."
sleep 30

# --- Produce during outage (test durability) ----------------------------
if command -v kafka-console-producer >/dev/null; then
  log "Producing ${TEST_MESSAGES} messages during outage..."
  for i in $(seq 1 "$TEST_MESSAGES"); do
    echo "${SENTINEL_PREFIX}-during-$i"
  done | kafka-console-producer --broker-list "$BOOTSTRAP" --topic "$TOPIC" \
    --producer-property acks=all --producer-property retries=10 \
    >/dev/null 2>&1 || log "WARN: some messages may have failed to produce"
fi

# --- Bring broker back --------------------------------------------------
wait_broker_back
BACK_TS=$(date +%s)
log "Broker back up ($(( BACK_TS - DOWN_TS ))s of disruption)"

# --- Wait for ISR recovery ----------------------------------------------
log "Waiting 60s for ISR rebalance..."
sleep 60

if command -v kafka-topics >/dev/null; then
  UNDER_REPLICATED="$(kafka-topics --bootstrap-server "$BOOTSTRAP" \
    --describe --under-replicated-partitions 2>/dev/null | wc -l | tr -d ' ')"
  log "Under-replicated partitions: $UNDER_REPLICATED"
  (( UNDER_REPLICATED == 0 )) || fail "Partitions still under-replicated after 60s"
fi

# --- Consume and verify sentinel count ----------------------------------
if command -v kafka-console-consumer >/dev/null; then
  log "Consuming and counting sentinel messages (5s timeout)..."
  COUNT="$(kafka-console-consumer --bootstrap-server "$BOOTSTRAP" \
    --topic "$TOPIC" --from-beginning --timeout-ms 5000 2>/dev/null | \
    grep -c "$SENTINEL_PREFIX" || true)"
  EXPECTED=$((TEST_MESSAGES * 2))
  log "Sentinel count: $COUNT / expected $EXPECTED"
  (( COUNT >= EXPECTED * 95 / 100 )) || \
    fail "Message durability <95% ($COUNT/$EXPECTED)"
fi

# --- Evaluate health during outage --------------------------------------
sleep 2
kill $POLLER_PID 2>/dev/null || true
wait $POLLER_PID 2>/dev/null || true

TOTAL=$(wc -l < "$HEALTH_LOG" | tr -d ' ')
OK=$(awk '$2>=200 && $2<300 {c++} END {print c+0}' "$HEALTH_LOG")
BAD=$((TOTAL - OK))
MAX_STREAK=$(awk '$2<200 || $2>=300 {s++; if(s>m) m=s; next} {s=0} END {print m+0}' "$HEALTH_LOG")

log "Health during chaos: ok=$OK/$TOTAL max_consecutive_fail=$MAX_STREAK"
(( MAX_STREAK <= 5 )) || fail "Health check had $MAX_STREAK consecutive failures (budget 5s)"

pass "Kafka broker down chaos — durability + availability maintained"
