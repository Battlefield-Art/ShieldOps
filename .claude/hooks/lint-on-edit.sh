#!/bin/bash
# PostToolUse hook for Edit|Write — runs ruff on edited Python files
# Non-blocking: logs issues but never fails
set -uo pipefail

INPUT=$(cat)
FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty')

if [[ -z "$FILE_PATH" ]]; then
  exit 0
fi

# Only lint Python files
if [[ ! "$FILE_PATH" =~ \.py$ ]]; then
  exit 0
fi

# Skip if file doesn't exist (was deleted)
if [[ ! -f "$FILE_PATH" ]]; then
  exit 0
fi

# Run ruff check (non-blocking — report issues as context)
LINT_OUTPUT=$(python3 -m ruff check "$FILE_PATH" --no-fix --output-format=concise 2>/dev/null || true)

if [[ -n "$LINT_OUTPUT" ]]; then
  # Return lint issues as additional context for Claude
  ISSUE_COUNT=$(echo "$LINT_OUTPUT" | wc -l | tr -d ' ')
  echo "{\"systemMessage\":\"Lint: $ISSUE_COUNT issue(s) found in $(basename "$FILE_PATH"). Run ruff check --fix to auto-fix.\"}"
fi

exit 0
