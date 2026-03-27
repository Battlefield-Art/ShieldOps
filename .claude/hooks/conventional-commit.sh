#!/bin/bash
# PreToolUse hook for Bash — validates git commit messages follow conventional commits
# Only activates on git commit commands
set -euo pipefail

INPUT=$(cat)
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty')

if [[ -z "$COMMAND" ]]; then
  exit 0
fi

# Only check git commit commands
if ! echo "$COMMAND" | grep -qE 'git[[:space:]]+commit'; then
  exit 0
fi

# Extract commit message from -m flag
COMMIT_MSG=""
if echo "$COMMAND" | grep -qE '\-m[[:space:]]'; then
  # Handle both -m "msg" and -m 'msg' patterns
  COMMIT_MSG=$(echo "$COMMAND" | grep -oE '\-m[[:space:]]+[\"'"'"']([^\"'"'"']+)[\"'"'"']' | head -1 | sed 's/-m[[:space:]]*[\"'"'"']//;s/[\"'"'"']$//')
fi

# Handle heredoc commit messages (cat <<'EOF'...)
if echo "$COMMAND" | grep -qE 'cat[[:space:]]+<<'; then
  # Extract first line of heredoc as the commit subject
  COMMIT_MSG=$(echo "$COMMAND" | grep -A1 "cat <<" | tail -1 | sed 's/^[[:space:]]*//')
fi

if [[ -z "$COMMIT_MSG" ]]; then
  # Can't parse message — allow through (might be interactive or heredoc)
  exit 0
fi

# Validate conventional commit format: type(scope): description
# or type: description
VALID_TYPES="feat|fix|chore|docs|style|refactor|perf|test|build|ci|revert"
if ! echo "$COMMIT_MSG" | grep -qE "^($VALID_TYPES)(\(.+\))?:[[:space:]].+"; then
  echo "{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"additionalContext\":\"Commit message should follow conventional commits format: type(scope): description. Valid types: feat, fix, chore, docs, style, refactor, perf, test, build, ci, revert. Example: feat(agents): add new SOC brain agent\"}}"
fi

exit 0
