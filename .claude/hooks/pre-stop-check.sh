#!/bin/bash
# Stop hook — checks for uncommitted changes and test status before stopping
# Exit 0 with JSON to provide context (non-blocking advisory)
set -uo pipefail

INPUT=$(cat)

# Prevent infinite loop: if this is a nested stop hook, exit immediately
STOP_ACTIVE=$(echo "$INPUT" | jq -r '.stop_hook_active // false' 2>/dev/null || echo "false")
if [[ "$STOP_ACTIVE" == "true" ]]; then
  exit 0
fi

PROJECT_DIR="${CLAUDE_PROJECT_DIR:-$(pwd)}"
cd "$PROJECT_DIR" 2>/dev/null || exit 0

WARNINGS=""

# Check for uncommitted changes
DIRTY_COUNT=$(git status --porcelain 2>/dev/null | wc -l | tr -d ' ')
if [[ "$DIRTY_COUNT" -gt 0 ]]; then
  STAGED=$(git diff --cached --name-only 2>/dev/null | wc -l | tr -d ' ')
  UNSTAGED=$(git diff --name-only 2>/dev/null | wc -l | tr -d ' ')
  UNTRACKED=$(git ls-files --others --exclude-standard 2>/dev/null | wc -l | tr -d ' ')
  WARNINGS="${WARNINGS}Uncommitted changes: $STAGED staged, $UNSTAGED modified, $UNTRACKED untracked. "
fi

# Check for modified Python files that might need linting
MODIFIED_PY=$(git diff --name-only 2>/dev/null | grep '\.py$' | wc -l | tr -d ' ')
if [[ "$MODIFIED_PY" -gt 0 ]]; then
  # Quick lint check
  LINT_ISSUES=$(python3 -m ruff check src/ tests/ --no-fix --statistics 2>/dev/null | tail -1 || true)
  if [[ -n "$LINT_ISSUES" ]]; then
    WARNINGS="${WARNINGS}Lint issues remain: $LINT_ISSUES. "
  fi
fi

# Output valid hook JSON
if [[ -n "$WARNINGS" ]]; then
  jq -n --arg w "$WARNINGS" '{
    "decision": "approve",
    "reason": ("Pre-stop advisory: " + $w)
  }'
else
  echo '{"decision":"approve","reason":"Clean state"}'
fi

exit 0
