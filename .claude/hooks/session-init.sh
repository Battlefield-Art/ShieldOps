#!/bin/bash
# SessionStart hook — initializes environment and reports project status
# Output is added to Claude's context as system information
set -uo pipefail

INPUT=$(cat)
SOURCE=$(echo "$INPUT" | jq -r '.source // "startup"' 2>/dev/null || echo "startup")

# Only run on startup and resume (not clear/compact)
if [[ "$SOURCE" != "startup" && "$SOURCE" != "resume" ]]; then
  exit 0
fi

PROJECT_DIR="${CLAUDE_PROJECT_DIR:-$(pwd)}"
cd "$PROJECT_DIR" 2>/dev/null || exit 0

# Gather git status
BRANCH=$(git branch --show-current 2>/dev/null || echo "unknown")
DIRTY_COUNT=$(git status --porcelain 2>/dev/null | wc -l | tr -d ' ')
LAST_COMMIT=$(git log -1 --format="%h %s" 2>/dev/null || echo "none")

# Check for uncommitted changes
if [[ "$DIRTY_COUNT" -gt 0 ]]; then
  DIRTY_MSG="⚠ $DIRTY_COUNT uncommitted change(s)"
else
  DIRTY_MSG="Clean working tree"
fi

# Check if Python env is active
if [[ -n "${VIRTUAL_ENV:-}" ]]; then
  VENV_MSG="venv active"
else
  VENV_MSG="⚠ No virtual environment active"
fi

# Check key services (quick, non-blocking)
PG_STATUS="unknown"
REDIS_STATUS="unknown"
if command -v pg_isready &>/dev/null; then
  pg_isready -h localhost -p 5432 -t 1 &>/dev/null && PG_STATUS="up" || PG_STATUS="down"
fi
if command -v redis-cli &>/dev/null; then
  redis-cli -h localhost ping &>/dev/null && REDIS_STATUS="up" || REDIS_STATUS="down"
fi

# Output project context (added to Claude's context on session start)
cat << EOF
ShieldOps Session Context:
- Branch: $BRANCH | $DIRTY_MSG
- Last commit: $LAST_COMMIT
- Python: $VENV_MSG
- Services: PostgreSQL=$PG_STATUS, Redis=$REDIS_STATUS
- Hooks: validate-bash, protect-sensitive-files, audit-trail, lint-on-edit, gitops-guard
EOF

exit 0
