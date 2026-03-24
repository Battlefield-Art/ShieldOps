###############################################################################
# ShieldOps AI Security Module — Outputs
###############################################################################

# ── Secret ARNs ──────────────────────────────────────────────────────────

output "crowdstrike_secret_arn" {
  description = "ARN of the CrowdStrike credentials secret"
  value       = var.crowdstrike_enabled ? aws_secretsmanager_secret.crowdstrike_credentials[0].arn : null
}

output "defender_secret_arn" {
  description = "ARN of the Microsoft Defender credentials secret"
  value       = var.defender_enabled ? aws_secretsmanager_secret.defender_credentials[0].arn : null
}

output "wiz_secret_arn" {
  description = "ARN of the Wiz credentials secret"
  value       = var.wiz_enabled ? aws_secretsmanager_secret.wiz_credentials[0].arn : null
}

# ── Kubernetes Resources ─────────────────────────────────────────────────

output "ai_security_configmap_name" {
  description = "Name of the AI Security ConfigMap"
  value       = kubernetes_config_map.ai_security.metadata[0].name
}

output "opa_policies_configmap_name" {
  description = "Name of the OPA AI policies ConfigMap"
  value       = kubernetes_config_map.opa_ai_policies.metadata[0].name
}

# ── IAM ──────────────────────────────────────────────────────────────────

output "secrets_access_policy_arn" {
  description = "ARN of the IAM policy granting Secrets Manager read access"
  value       = aws_iam_policy.ai_security_secrets_access.arn
}

output "secrets_access_policy_name" {
  description = "Name of the IAM policy granting Secrets Manager read access"
  value       = aws_iam_policy.ai_security_secrets_access.name
}
