#!/bin/bash
# PreToolUse hook for Edit|Write — GitOps-aware validation for infrastructure files
# Enforces dry-run-first policy for K8s, Terraform, Helm, and policy changes
set -euo pipefail

INPUT=$(cat)
FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty')
TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // empty')

if [[ -z "$FILE_PATH" ]]; then
  exit 0
fi

# Track infrastructure changes for GitOps reconciliation
INFRA_CHANGE=false
CHANGE_TYPE=""

# === Kubernetes manifest changes ===
if [[ "$FILE_PATH" =~ infrastructure/kubernetes/.+\.ya?ml$ ]]; then
  INFRA_CHANGE=true
  CHANGE_TYPE="kubernetes"
fi

# === Terraform changes ===
if [[ "$FILE_PATH" =~ infrastructure/terraform/.+\.tf$ ]]; then
  INFRA_CHANGE=true
  CHANGE_TYPE="terraform"
fi

# === Helm chart changes ===
if [[ "$FILE_PATH" =~ infrastructure/helm/ ]]; then
  INFRA_CHANGE=true
  CHANGE_TYPE="helm"
fi

# === Kustomize changes ===
if [[ "$FILE_PATH" =~ kustomization\.ya?ml$ ]]; then
  INFRA_CHANGE=true
  CHANGE_TYPE="kustomize"
fi

# === OPA/Rego policy changes ===
if [[ "$FILE_PATH" =~ \.rego$ ]]; then
  INFRA_CHANGE=true
  CHANGE_TYPE="opa-policy"
fi

# === Docker changes ===
if [[ "$(basename "$FILE_PATH")" == "Dockerfile" ]] || [[ "$(basename "$FILE_PATH")" == "docker-compose.yml" ]]; then
  INFRA_CHANGE=true
  CHANGE_TYPE="docker"
fi

# === GitHub Actions workflow changes ===
if [[ "$FILE_PATH" =~ \.github/workflows/.+\.ya?ml$ ]]; then
  INFRA_CHANGE=true
  CHANGE_TYPE="ci-cd"
fi

# If infrastructure change detected, add GitOps context
if [[ "$INFRA_CHANGE" == "true" ]]; then
  # Log infrastructure change to audit
  AUDIT_DIR="${CLAUDE_PROJECT_DIR:-.}/.claude/audit"
  mkdir -p "$AUDIT_DIR"
  echo "{\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"type\":\"infra_change\",\"change_type\":\"$CHANGE_TYPE\",\"file\":\"$FILE_PATH\"}" >> "$AUDIT_DIR/gitops-changes.jsonl"

  # Provide GitOps-aware context
  case "$CHANGE_TYPE" in
    kubernetes)
      MSG="GitOps: K8s manifest changed. After editing, run: kubectl diff -f $FILE_PATH (or /manage-gitops detect-drift). Commit triggers gitops-sync workflow."
      ;;
    terraform)
      MSG="GitOps: Terraform config changed. After editing, run: terraform plan -target=<resource> (or /manage-gitops verify). CI validates automatically."
      ;;
    helm)
      MSG="GitOps: Helm chart changed. After editing, run: helm template . --debug to validate. Commit triggers gitops-sync workflow."
      ;;
    kustomize)
      MSG="GitOps: Kustomize config changed. After editing, run: kustomize build . to validate. CI runs kustomize build on push."
      ;;
    opa-policy)
      MSG="GitOps: OPA policy changed. After editing, run: /scan-security --scope policies to validate. Policy changes affect ALL agent authorization."
      ;;
    docker)
      MSG="GitOps: Container config changed. After editing, run: docker build --dry-run or docker compose config to validate."
      ;;
    ci-cd)
      MSG="GitOps: CI/CD workflow changed. Verify with: act --list (GitHub Actions local runner) or review in PR. Changes affect all contributors."
      ;;
    *)
      MSG="GitOps: Infrastructure file changed. Verify changes before merging."
      ;;
  esac

  echo "{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"additionalContext\":\"$MSG\"}}"
fi

exit 0
