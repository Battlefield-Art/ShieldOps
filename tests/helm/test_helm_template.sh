#!/usr/bin/env bash
# =============================================================================
# Helm chart validation test for ShieldOps (issue #230).
#
# Runs `helm template` against multiple value permutations and verifies the
# rendered output parses as valid YAML. Useful as a fast smoke test in CI
# before `helm lint` and full integration tests.
#
# Usage:
#   ./tests/helm/test_helm_template.sh
#
# Requirements:
#   - helm 3.12+
#   - python3 (for YAML validation; falls back to `yq` if installed)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CHART_DIR="$REPO_ROOT/infrastructure/helm/shieldops"
RELEASE_NAME="test-shieldops"
NAMESPACE="shieldops-test"

if ! command -v helm >/dev/null 2>&1; then
  echo "ERROR: helm not found in PATH" >&2
  exit 1
fi

# Build dependencies once (uses vendored .tgz files in charts/)
if [ -d "$CHART_DIR/charts" ]; then
  echo "==> Using vendored subcharts from $CHART_DIR/charts"
else
  echo "==> Building Helm dependencies"
  helm dependency build "$CHART_DIR"
fi

validate_yaml() {
  local output_file="$1"
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$output_file" <<'PY'
import sys, yaml
path = sys.argv[1]
with open(path) as f:
    docs = list(yaml.safe_load_all(f))
non_empty = [d for d in docs if d]
if not non_empty:
    print(f"ERROR: {path} rendered zero documents", file=sys.stderr)
    sys.exit(1)
for d in non_empty:
    if not isinstance(d, dict) or "kind" not in d or "apiVersion" not in d:
        print(f"ERROR: {path} has document missing kind/apiVersion: {d!r}", file=sys.stderr)
        sys.exit(1)
print(f"OK: {len(non_empty)} valid documents in {path}")
PY
  elif command -v yq >/dev/null 2>&1; then
    yq eval-all '.' "$output_file" >/dev/null
    echo "OK (yq): $output_file"
  else
    echo "WARN: neither python3 nor yq available; skipping YAML parse check"
  fi
}

run_case() {
  local name="$1"
  shift
  local out="/tmp/shieldops-helm-${name}.yaml"
  echo ""
  echo "=============================================================="
  echo "CASE: $name"
  echo "ARGS: $*"
  echo "=============================================================="
  helm template "$RELEASE_NAME" "$CHART_DIR" \
    --namespace "$NAMESPACE" \
    "$@" > "$out"
  validate_yaml "$out"
}

# -----------------------------------------------------------------------------
# Permutations
# -----------------------------------------------------------------------------

# 1. Defaults (embedded DB + embedded Redis, kafka off, airgap off)
run_case "defaults"

# 2. External PostgreSQL
run_case "external-db" \
  --set database.embedded=false \
  --set database.external.url="postgresql+asyncpg://u:p@pg/shieldops" \
  --set postgresql.enabled=false

# 3. External Redis
run_case "external-redis" \
  --set redisCompat.embedded=false \
  --set redisCompat.external.url="redis://redis.ext:6379/0" \
  --set redis.enabled=false

# 4. Kafka on
run_case "kafka-on" \
  --set kafka.enabled=true

# 5. Air-gapped mode
run_case "airgapped" \
  --set airGapped=true \
  --set llm.provider=bedrock \
  --set llm.region=us-gov-west-1

# 6. Ingress disabled
run_case "no-ingress" \
  --set ingress.enabled=false

# 7. Full external (production-like)
run_case "full-external" \
  --set database.embedded=false \
  --set database.external.url="postgresql+asyncpg://u:p@pg/shieldops" \
  --set postgresql.enabled=false \
  --set redisCompat.embedded=false \
  --set redisCompat.external.url="redis://redis.ext:6379/0" \
  --set redis.enabled=false \
  --set kafka.enabled=true \
  --set airGapped=false \
  --set ingestion.maxGbPerDay=100 \
  --set autoscaling.maxReplicas=25

# 8. Worker disabled
run_case "no-worker" \
  --set worker.enabled=false

# 9. Storage disabled (stateless, fully external)
run_case "no-storage" \
  --set storage.enabled=false \
  --set database.embedded=false \
  --set database.external.url="postgresql+asyncpg://u:p@pg/shieldops" \
  --set postgresql.enabled=false

echo ""
echo "=============================================================="
echo "All Helm template permutations rendered and validated OK."
echo "=============================================================="
