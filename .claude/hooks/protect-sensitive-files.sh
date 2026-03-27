#!/bin/bash
# PreToolUse hook for Edit|Write — protects sensitive files from modification
# Exit 0 = allow, Exit 2 = block (stderr shown to Claude)
set -euo pipefail

INPUT=$(cat)
FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty')

if [[ -z "$FILE_PATH" ]]; then
  exit 0
fi

# Normalize to basename for pattern matching
BASENAME=$(basename "$FILE_PATH")
DIRPATH=$(dirname "$FILE_PATH")

# === BLOCK: Environment files with secrets ===
if [[ "$BASENAME" == ".env" || "$BASENAME" == ".env.production" || "$BASENAME" == ".env.staging" ]]; then
  echo "BLOCKED: Cannot modify $BASENAME — contains secrets. Edit .env.example instead and document required vars." >&2
  exit 2
fi

# === BLOCK: Credential files ===
if [[ "$BASENAME" == "credentials.json" || "$BASENAME" == "service-account.json" || "$BASENAME" =~ \.pem$ || "$BASENAME" =~ \.key$ ]]; then
  echo "BLOCKED: Cannot modify credential/key file $BASENAME. Use secret manager or env vars." >&2
  exit 2
fi

# === WARN: OPA policy files (allow but add context) ===
if [[ "$FILE_PATH" =~ \.rego$ ]] || [[ "$DIRPATH" =~ playbooks/policies ]]; then
  echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","additionalContext":"CAUTION: Modifying OPA policy file. Changes affect agent authorization across ALL environments. Verify with /scan-security --scope policies after editing."}}'
  exit 0
fi

# === WARN: Kubernetes manifests ===
if [[ "$DIRPATH" =~ infrastructure/kubernetes ]]; then
  echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","additionalContext":"CAUTION: Modifying Kubernetes manifest. Run kubectl diff or /manage-gitops detect-drift after editing to verify impact."}}'
  exit 0
fi

# === WARN: Terraform configs ===
if [[ "$FILE_PATH" =~ \.tf$ ]] || [[ "$DIRPATH" =~ infrastructure/terraform ]]; then
  echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","additionalContext":"CAUTION: Modifying Terraform config. Run terraform plan (dry-run) before applying. Changes affect cloud infrastructure."}}'
  exit 0
fi

# === WARN: CI/CD workflows ===
if [[ "$DIRPATH" =~ \.github/workflows ]]; then
  echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","additionalContext":"CAUTION: Modifying CI/CD workflow. Changes affect build/deploy pipeline for all contributors."}}'
  exit 0
fi

# === WARN: Database migrations ===
if [[ "$DIRPATH" =~ alembic ]] || [[ "$DIRPATH" =~ migrations ]]; then
  echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","additionalContext":"CAUTION: Modifying database migration. Verify with alembic check and ensure migration is reversible."}}'
  exit 0
fi

# === WARN: Docker/Helm configs ===
if [[ "$BASENAME" == "Dockerfile" || "$BASENAME" == "docker-compose.yml" ]] || [[ "$DIRPATH" =~ infrastructure/helm ]]; then
  echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","additionalContext":"CAUTION: Modifying container/deployment config. Verify image builds and deployment manifests."}}'
  exit 0
fi

exit 0
