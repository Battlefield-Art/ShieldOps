#!/bin/bash
# PostToolUse hook — logs all tool executions to audit trail
# Non-blocking: always exits 0
set -uo pipefail

INPUT=$(cat)
AUDIT_DIR="${CLAUDE_PROJECT_DIR:-.}/.claude/audit"
AUDIT_FILE="$AUDIT_DIR/tool-audit.jsonl"

# Ensure audit directory exists
mkdir -p "$AUDIT_DIR"

# Extract fields
TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // "unknown"')
SESSION_ID=$(echo "$INPUT" | jq -r '.session_id // "unknown"')
EVENT=$(echo "$INPUT" | jq -r '.hook_event_name // "unknown"')

# Build audit entry based on tool type
case "$TOOL_NAME" in
  Bash)
    DETAIL=$(echo "$INPUT" | jq -r '.tool_input.command // "N/A"' | head -c 500 | tr '\n' ' ')
    ;;
  Edit|Write)
    DETAIL=$(echo "$INPUT" | jq -r '.tool_input.file_path // "N/A"' | tr -d '\n')
    ;;
  Read)
    DETAIL=$(echo "$INPUT" | jq -r '.tool_input.file_path // "N/A"' | tr -d '\n')
    ;;
  Glob)
    DETAIL=$(echo "$INPUT" | jq -r '.tool_input.pattern // "N/A"' | tr -d '\n')
    ;;
  Grep)
    DETAIL=$(echo "$INPUT" | jq -r '.tool_input.pattern // "N/A"' | tr -d '\n')
    ;;
  Agent)
    DETAIL=$(echo "$INPUT" | jq -r '.tool_input.description // "N/A"' | head -c 200 | tr '\n' ' ')
    ;;
  *)
    DETAIL=$(echo "$INPUT" | jq -c '.tool_input // {}' | head -c 300 | tr '\n' ' ')
    ;;
esac

# Write audit entry (append, atomic-ish)
echo "{\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"session\":\"$SESSION_ID\",\"event\":\"$EVENT\",\"tool\":\"$TOOL_NAME\",\"detail\":$(echo "$DETAIL" | jq -Rs .)}" >> "$AUDIT_FILE"

# Rotate if > 10MB
if [[ -f "$AUDIT_FILE" ]] && [[ $(wc -c < "$AUDIT_FILE") -gt 10485760 ]]; then
  mv "$AUDIT_FILE" "${AUDIT_FILE}.$(date +%Y%m%d%H%M%S).bak"
fi

exit 0
