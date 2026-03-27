#!/bin/bash
# PostToolUse hook for Edit|Write — runs security checks on sensitive file edits
# Non-blocking: reports findings as context
set -uo pipefail

INPUT=$(cat)
FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty')

if [[ -z "$FILE_PATH" ]]; then
  exit 0
fi

# Only check Python files in security-sensitive directories
if [[ ! "$FILE_PATH" =~ \.py$ ]]; then
  exit 0
fi

if [[ ! -f "$FILE_PATH" ]]; then
  exit 0
fi

# Check if file is in security-sensitive paths
IS_SENSITIVE=false
if [[ "$FILE_PATH" =~ (security|auth|policy|connectors|api/middleware|sdk|crypto|credentials) ]]; then
  IS_SENSITIVE=true
fi

if [[ "$IS_SENSITIVE" != "true" ]]; then
  exit 0
fi

# Run bandit on the specific file (quick security scan)
BANDIT_OUTPUT=$(python3 -m bandit -ll "$FILE_PATH" -f json 2>/dev/null || true)

if [[ -n "$BANDIT_OUTPUT" ]]; then
  ISSUE_COUNT=$(echo "$BANDIT_OUTPUT" | jq '.results | length' 2>/dev/null || echo "0")
  if [[ "$ISSUE_COUNT" -gt 0 ]]; then
    SEVERITIES=$(echo "$BANDIT_OUTPUT" | jq -r '[.results[].issue_severity] | group_by(.) | map({(.[0]): length}) | add // {}' 2>/dev/null || echo "{}")
    echo "{\"systemMessage\":\"Security scan: $ISSUE_COUNT issue(s) in $(basename "$FILE_PATH"). Severities: $SEVERITIES. Run: bandit -ll $FILE_PATH for details.\"}"
  fi
fi

# Quick check for common security anti-patterns
if grep -qE '(eval\(|exec\(|pickle\.loads|yaml\.load\(.*Loader|subprocess\.call.*shell=True)' "$FILE_PATH" 2>/dev/null; then
  echo "{\"systemMessage\":\"Security warning: Potentially unsafe function detected in $(basename "$FILE_PATH"). Review eval/exec/pickle/yaml.load/subprocess.call usage.\"}"
fi

# Check for hardcoded secrets patterns
if grep -qiE '(password[[:space:]]*=[[:space:]]*[\"'"'"'][^\"'"'"']+|api_key[[:space:]]*=[[:space:]]*[\"'"'"'][A-Za-z0-9])' "$FILE_PATH" 2>/dev/null; then
  echo "{\"systemMessage\":\"Security warning: Possible hardcoded credential in $(basename "$FILE_PATH"). Use env vars or secret manager.\"}"
fi

exit 0
