#!/usr/bin/env bash
# ============================================================================
# Chaos: RDS failover
# ----------------------------------------------------------------------------
# Triggers a failover on a Multi-AZ RDS instance (or Aurora cluster) and
# verifies the ShieldOps API reconnects to the new primary within the
# recovery budget.
#
# SLO gate (issue #223):
#   - API /health reachable again within 30s of failover completion
#   - DB connection pool recovers without manual restart
#
# Usage:
#   DB_INSTANCE=shieldops-prod-db \
#     HEALTH_URL=https://api.shieldops.io/health \
#     ./tests/chaos/test_rds_failover.sh
#
#   # Aurora cluster:
#   DB_CLUSTER=shieldops-prod-aurora \
#     HEALTH_URL=https://api.shieldops.io/health \
#     ./tests/chaos/test_rds_failover.sh
# ============================================================================

set -euo pipefail

HEALTH_URL="${HEALTH_URL:?HEALTH_URL env var required}"
AWS_REGION="${AWS_REGION:-us-east-1}"
RECOVERY_BUDGET="${RECOVERY_BUDGET:-30}"
DB_INSTANCE="${DB_INSTANCE:-}"
DB_CLUSTER="${DB_CLUSTER:-}"

log() { printf '[chaos:rds-failover] %s\n' "$*" >&2; }
fail() { log "FAIL: $*"; exit 1; }
pass() { log "PASS: $*"; exit 0; }

[[ -z "$DB_INSTANCE" && -z "$DB_CLUSTER" ]] && \
  fail "Must set DB_INSTANCE (RDS) or DB_CLUSTER (Aurora)"

# --- Baseline health ----------------------------------------------------
log "Baseline health check..."
BASE_CODE="$(curl -sk -o /dev/null -w '%{http_code}' "$HEALTH_URL" || echo 000)"
[[ "$BASE_CODE" =~ ^2 ]] || fail "Baseline health check failed ($BASE_CODE)"

# --- Trigger failover ---------------------------------------------------
FAILOVER_TS=$(date +%s)
if [[ -n "$DB_CLUSTER" ]]; then
  log "Failing over Aurora cluster: $DB_CLUSTER"
  aws rds failover-db-cluster \
    --db-cluster-identifier "$DB_CLUSTER" \
    --region "$AWS_REGION" >/dev/null
else
  log "Rebooting RDS instance with failover: $DB_INSTANCE"
  aws rds reboot-db-instance \
    --db-instance-identifier "$DB_INSTANCE" \
    --force-failover \
    --region "$AWS_REGION" >/dev/null
fi

# --- Wait for DB to return -----------------------------------------------
log "Waiting for DB to finish failover..."
if [[ -n "$DB_CLUSTER" ]]; then
  aws rds wait db-cluster-available \
    --db-cluster-identifier "$DB_CLUSTER" \
    --region "$AWS_REGION"
else
  aws rds wait db-instance-available \
    --db-instance-identifier "$DB_INSTANCE" \
    --region "$AWS_REGION"
fi
DB_READY_TS=$(date +%s)
log "DB ready ($(( DB_READY_TS - FAILOVER_TS ))s after trigger)"

# --- Poll health until reconnect ----------------------------------------
log "Polling health for reconnect (budget ${RECOVERY_BUDGET}s)..."
DEADLINE=$((DB_READY_TS + RECOVERY_BUDGET))
RECOVERED=0
while (( $(date +%s) < DEADLINE )); do
  CODE="$(curl -sk -o /dev/null -w '%{http_code}' "$HEALTH_URL" || echo 000)"
  if [[ "$CODE" =~ ^2 ]]; then
    RECONNECT_TIME=$(( $(date +%s) - DB_READY_TS ))
    log "API reconnected in ${RECONNECT_TIME}s (code=$CODE)"
    RECOVERED=1
    break
  fi
  sleep 1
done

(( RECOVERED == 1 )) || fail "API did not reconnect within ${RECOVERY_BUDGET}s"

# --- Verify DB queries work ---------------------------------------------
READY_CODE="$(curl -sk -o /dev/null -w '%{http_code}' "${HEALTH_URL%/health}/health/ready" || echo 000)"
if [[ "$READY_CODE" =~ ^2 ]]; then
  log "Readiness probe OK (code=$READY_CODE)"
else
  log "WARN: readiness probe returned $READY_CODE (may not expose /health/ready)"
fi

pass "RDS failover chaos — reconnect in ${RECONNECT_TIME}s (budget ${RECOVERY_BUDGET}s)"
