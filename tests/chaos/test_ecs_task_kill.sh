#!/usr/bin/env bash
# ============================================================================
# Chaos: ECS task kill
# ----------------------------------------------------------------------------
# Stops a random task in the target ECS service and verifies that ECS
# reschedules a replacement within the recovery budget AND that the API
# remains responsive throughout the disruption.
#
# SLO gate (issue #223):
#   - Replacement task RUNNING within 120s
#   - /health endpoint 2xx throughout disruption (allow <=3 consecutive fails)
#
# Usage:
#   CLUSTER=shieldops-prod SERVICE=shieldops-api \
#     HEALTH_URL=https://api.shieldops.io/health \
#     ./tests/chaos/test_ecs_task_kill.sh
#
# Environment:
#   CLUSTER         ECS cluster name (required)
#   SERVICE         ECS service name (required)
#   HEALTH_URL      Health endpoint to poll (required)
#   AWS_REGION      AWS region (default: us-east-1)
#   RECOVERY_BUDGET Seconds to wait for replacement (default: 120)
# ============================================================================

set -euo pipefail

CLUSTER="${CLUSTER:?CLUSTER env var required}"
SERVICE="${SERVICE:?SERVICE env var required}"
HEALTH_URL="${HEALTH_URL:?HEALTH_URL env var required}"
AWS_REGION="${AWS_REGION:-us-east-1}"
RECOVERY_BUDGET="${RECOVERY_BUDGET:-120}"

log() { printf '[chaos:ecs-kill] %s\n' "$*" >&2; }
fail() { log "FAIL: $*"; exit 1; }
pass() { log "PASS: $*"; exit 0; }

log "Cluster=$CLUSTER Service=$SERVICE Region=$AWS_REGION"

# --- Baseline -----------------------------------------------------------
log "Fetching baseline task count..."
BASELINE_JSON="$(aws ecs describe-services \
  --cluster "$CLUSTER" --services "$SERVICE" --region "$AWS_REGION")"
BASELINE_RUNNING="$(echo "$BASELINE_JSON" | jq -r '.services[0].runningCount')"
DESIRED="$(echo "$BASELINE_JSON" | jq -r '.services[0].desiredCount')"
log "Baseline: running=$BASELINE_RUNNING desired=$DESIRED"

if [[ "$BASELINE_RUNNING" -lt 1 ]]; then
  fail "No running tasks in $SERVICE — cannot run chaos"
fi

# --- Pick victim --------------------------------------------------------
TASK_ARN="$(aws ecs list-tasks \
  --cluster "$CLUSTER" --service-name "$SERVICE" \
  --desired-status RUNNING --region "$AWS_REGION" \
  --query 'taskArns[0]' --output text)"

[[ -z "$TASK_ARN" || "$TASK_ARN" == "None" ]] && fail "No task ARN found"
log "Victim task: $TASK_ARN"

# --- Start background health poller ------------------------------------
HEALTH_LOG="$(mktemp)"
(
  end=$((SECONDS + RECOVERY_BUDGET + 30))
  while (( SECONDS < end )); do
    code="$(curl -sk -o /dev/null -w '%{http_code}' "$HEALTH_URL" || echo 000)"
    printf '%s %s\n' "$(date +%s)" "$code" >> "$HEALTH_LOG"
    sleep 1
  done
) &
POLLER_PID=$!
trap 'kill $POLLER_PID 2>/dev/null || true; rm -f "$HEALTH_LOG"' EXIT

# --- Kill task ----------------------------------------------------------
KILL_TS=$(date +%s)
log "Stopping task (reason: chaos test #223)..."
aws ecs stop-task \
  --cluster "$CLUSTER" --task "$TASK_ARN" \
  --reason "chaos-test-issue-223" --region "$AWS_REGION" >/dev/null

# --- Wait for replacement ----------------------------------------------
log "Waiting up to ${RECOVERY_BUDGET}s for replacement..."
DEADLINE=$((KILL_TS + RECOVERY_BUDGET))
RECOVERED=0
while (( $(date +%s) < DEADLINE )); do
  RUNNING="$(aws ecs describe-services \
    --cluster "$CLUSTER" --services "$SERVICE" --region "$AWS_REGION" \
    --query 'services[0].runningCount' --output text)"
  if [[ "$RUNNING" -ge "$DESIRED" ]]; then
    RECOVERY_TIME=$(( $(date +%s) - KILL_TS ))
    log "Recovered in ${RECOVERY_TIME}s (running=$RUNNING desired=$DESIRED)"
    RECOVERED=1
    break
  fi
  sleep 3
done

# --- Stop poller + evaluate health -------------------------------------
sleep 2
kill $POLLER_PID 2>/dev/null || true
wait $POLLER_PID 2>/dev/null || true

TOTAL=$(wc -l < "$HEALTH_LOG" | tr -d ' ')
OK=$(awk '$2>=200 && $2<300 {c++} END {print c+0}' "$HEALTH_LOG")
BAD=$((TOTAL - OK))
MAX_STREAK=$(awk '$2<200 || $2>=300 {s++; if(s>m) m=s; next} {s=0} END {print m+0}' "$HEALTH_LOG")

log "Health polls: total=$TOTAL ok=$OK bad=$BAD max_consecutive_fail=$MAX_STREAK"

(( RECOVERED == 1 )) || fail "No replacement task within ${RECOVERY_BUDGET}s"
(( MAX_STREAK <= 3 )) || fail "Health check had $MAX_STREAK consecutive failures (budget 3)"

pass "ECS task kill chaos test — replacement in ${RECOVERY_TIME}s, max streak ${MAX_STREAK} fails"
