#!/bin/bash
# PreToolUse hook for Bash — blocks destructive and dangerous commands
# Exit 0 = allow, Exit 2 = block (stderr shown to Claude)
set -euo pipefail

INPUT=$(cat)
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty')

if [[ -z "$COMMAND" ]]; then
  exit 0
fi

# === BLOCK: Destructive filesystem operations ===
if [[ "$COMMAND" =~ (rm[[:space:]]+-rf[[:space:]]+/|rm[[:space:]]+-rf[[:space:]]+\.\.|rm[[:space:]]+-rf[[:space:]]+\*) ]]; then
  echo "BLOCKED: Destructive recursive delete outside project scope. Use targeted rm instead." >&2
  exit 2
fi

# === BLOCK: Database destruction ===
if echo "$COMMAND" | grep -qiE '(DROP[[:space:]]+TABLE|DROP[[:space:]]+DATABASE|TRUNCATE[[:space:]]+TABLE|DELETE[[:space:]]+FROM[[:space:]]+[^W])'; then
  echo "BLOCKED: Database destructive operation. Use migrations or targeted queries." >&2
  exit 2
fi

# === BLOCK: Force push to main/master ===
if echo "$COMMAND" | grep -qE 'git[[:space:]]+push[[:space:]]+.*--force.*\b(main|master)\b'; then
  echo "BLOCKED: Force push to main/master is prohibited. Use a feature branch." >&2
  exit 2
fi

if echo "$COMMAND" | grep -qE 'git[[:space:]]+push[[:space:]]+-f[[:space:]].*\b(main|master)\b'; then
  echo "BLOCKED: Force push to main/master is prohibited. Use a feature branch." >&2
  exit 2
fi

# === BLOCK: Git reset --hard without branch ===
if echo "$COMMAND" | grep -qE 'git[[:space:]]+reset[[:space:]]+--hard[[:space:]]+(origin|HEAD~)'; then
  echo "BLOCKED: git reset --hard can destroy uncommitted work. Consider git stash or git checkout." >&2
  exit 2
fi

# === BLOCK: Skip hooks ===
if echo "$COMMAND" | grep -qE '(--no-verify|--no-gpg-sign)'; then
  echo "BLOCKED: Skipping git hooks/signing is not allowed. Fix the underlying issue instead." >&2
  exit 2
fi

# === BLOCK: Credential exposure in commands ===
if echo "$COMMAND" | grep -qiE '(ANTHROPIC_API_KEY|OPENAI_API_KEY|STRIPE_SECRET|AWS_SECRET_ACCESS_KEY|DATABASE_URL.*password|PAGERDUTY_API_KEY)='; then
  echo "BLOCKED: Hardcoded credential detected in command. Use environment variables." >&2
  exit 2
fi

# === BLOCK: System-level destruction ===
if echo "$COMMAND" | grep -qE '(mkfs|dd[[:space:]]+if=|fdisk|chmod[[:space:]]+-R[[:space:]]+777|chown[[:space:]]+-R[[:space:]]+root)'; then
  echo "BLOCKED: System-level destructive operation not permitted." >&2
  exit 2
fi

# === BLOCK: Kill all processes ===
if echo "$COMMAND" | grep -qE '(killall|pkill[[:space:]]+-9|kill[[:space:]]+-9[[:space:]]+-1)'; then
  echo "BLOCKED: Mass process termination not permitted. Kill specific PIDs." >&2
  exit 2
fi

# === WARN: Infrastructure modifications (allow but add context) ===
if echo "$COMMAND" | grep -qE '(terraform[[:space:]]+destroy|terraform[[:space:]]+apply|kubectl[[:space:]]+delete|helm[[:space:]]+uninstall)'; then
  echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","additionalContext":"WARNING: This is an infrastructure-modifying command. Verify the target environment and ensure dry-run was performed first."}}'
  exit 0
fi

exit 0
