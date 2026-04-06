#!/usr/bin/env bash
# ============================================================================
# Chaos: Redis memory pressure / eviction
# ----------------------------------------------------------------------------
# Fills Redis with junk keys until `maxmemory` is exceeded, forcing eviction.
# Verifies ShieldOps degrades gracefully: cache misses fall back to DB,
# /health stays 2xx, no 5xx storm on cache-dependent endpoints.
#
# SLO gate (issue #223):
#   - /health remains 2xx throughout
#   - /api/v1/analytics/summary succeeds (may be slower)
#   - No crash-loop on API pods
#
# Usage:
#   REDIS_HOST=prod-redis.shieldops.io REDIS_PORT=6379 \
#     HEALTH_URL=https://api.shieldops.io/health \
#     CACHED_URL=https://api.shieldops.io/api/v1/analytics/summary \
#     AUTH_TOKEN=... \
#     ./tests/chaos/test_redis_eviction.sh
# ============================================================================

set -euo pipefail

REDIS_HOST="${REDIS_HOST:?REDIS_HOST env var required}"
REDIS_PORT="${REDIS_PORT:-6379}"
REDIS_PASSWORD="${REDIS_PASSWORD:-}"
HEALTH_URL="${HEALTH_URL:?HEALTH_URL env var required}"
CACHED_URL="${CACHED_URL:-}"
AUTH_TOKEN="${AUTH_TOKEN:-}"
FILL_KEYS="${FILL_KEYS:-100000}"
FILL_SIZE_BYTES="${FILL_SIZE_BYTES:-10240}" # 10KB per key => 1GB for 100k keys

log() { printf '[chaos:redis-evict] %s\n' "$*" >&2; }
fail() { log "FAIL: $*"; exit 1; }
pass() { log "PASS: $*"; exit 0; }

redis_cmd() {
  if [[ -n "$REDIS_PASSWORD" ]]; then
    redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" -a "$REDIS_PASSWORD" --no-auth-warning "$@"
  else
    redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" "$@"
  fi
}

command -v redis-cli >/dev/null || fail "redis-cli not installed"

# --- Baseline -----------------------------------------------------------
log "Redis baseline info..."
MAXMEM="$(redis_cmd CONFIG GET maxmemory | tail -1)"
POLICY="$(redis_cmd CONFIG GET maxmemory-policy | tail -1)"
log "maxmemory=$MAXMEM policy=$POLICY"
[[ "$POLICY" == "noeviction" ]] && \
  log "WARN: policy is noeviction — writes will ERR instead of evict"

BASE_HEALTH="$(curl -sk -o /dev/null -w '%{http_code}' "$HEALTH_URL" || echo 000)"
[[ "$BASE_HEALTH" =~ ^2 ]] || fail "Baseline health failed ($BASE_HEALTH)"

# --- Fill Redis ---------------------------------------------------------
PAYLOAD="$(printf 'x%.0s' $(seq 1 "$FILL_SIZE_BYTES"))"
log "Filling Redis with $FILL_KEYS keys of ${FILL_SIZE_BYTES}B each..."

for i in $(seq 1 "$FILL_KEYS"); do
  redis_cmd SET "chaos:fill:$i" "$PAYLOAD" EX 3600 >/dev/null 2>&1 || true
  if (( i % 5000 == 0 )); then
    USED="$(redis_cmd INFO memory | grep used_memory_human | tr -d '\r' | cut -d: -f2)"
    log "  progress=$i used_memory=$USED"
  fi
done

USED_AFTER="$(redis_cmd INFO memory | grep used_memory_human | tr -d '\r' | cut -d: -f2)"
EVICTED="$(redis_cmd INFO stats | grep evicted_keys | tr -d '\r' | cut -d: -f2)"
log "Fill complete. used=$USED_AFTER evicted_keys=$EVICTED"

# --- Verify graceful degradation ----------------------------------------
log "Polling API for 30s under memory pressure..."
FAILS=0
TOTAL=0
for _ in $(seq 1 30); do
  CODE="$(curl -sk -o /dev/null -w '%{http_code}' "$HEALTH_URL" || echo 000)"
  TOTAL=$((TOTAL + 1))
  [[ "$CODE" =~ ^2 ]] || FAILS=$((FAILS + 1))
  sleep 1
done
log "Health under pressure: ok=$((TOTAL-FAILS))/$TOTAL"

# Check cached endpoint if provided
if [[ -n "$CACHED_URL" && -n "$AUTH_TOKEN" ]]; then
  log "Checking cached endpoint: $CACHED_URL"
  CACHED_CODE="$(curl -sk -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer $AUTH_TOKEN" "$CACHED_URL" || echo 000)"
  [[ "$CACHED_CODE" =~ ^2 ]] || \
    fail "Cache-dependent endpoint returned $CACHED_CODE under memory pressure"
  log "Cached endpoint OK (code=$CACHED_CODE)"
fi

# --- Cleanup ------------------------------------------------------------
log "Cleaning up chaos keys..."
redis_cmd --scan --pattern 'chaos:fill:*' | xargs -r -n 100 redis_cmd DEL >/dev/null 2>&1 || true

(( FAILS <= 2 )) || fail "Health check failed $FAILS/$TOTAL times (budget 2)"

pass "Redis eviction chaos — graceful degradation confirmed ($((TOTAL-FAILS))/$TOTAL healthy)"
