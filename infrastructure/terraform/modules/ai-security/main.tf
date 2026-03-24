###############################################################################
# ShieldOps AI Security Control Plane — Terraform Module
# Provisions: OPA policies, firewall config, vendor credentials, MCP gateway
###############################################################################

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.25"
    }
  }
}

# ── Vendor Credential Secrets (AWS Secrets Manager) ───────────────────────

resource "aws_secretsmanager_secret" "crowdstrike_credentials" {
  count       = var.crowdstrike_enabled ? 1 : 0
  name        = "${var.prefix}/ai-security/crowdstrike"
  description = "CrowdStrike Falcon API credentials for ShieldOps SOC Brain"

  tags = merge(var.common_tags, {
    component = "ai-security"
    vendor    = "crowdstrike"
  })
}

resource "aws_secretsmanager_secret_version" "crowdstrike_credentials" {
  count     = var.crowdstrike_enabled ? 1 : 0
  secret_id = aws_secretsmanager_secret.crowdstrike_credentials[0].id

  secret_string = jsonencode({
    client_id     = var.crowdstrike_client_id
    client_secret = var.crowdstrike_client_secret
    base_url      = var.crowdstrike_base_url
  })
}

resource "aws_secretsmanager_secret" "defender_credentials" {
  count       = var.defender_enabled ? 1 : 0
  name        = "${var.prefix}/ai-security/defender"
  description = "Microsoft Defender credentials for ShieldOps SOC Brain"

  tags = merge(var.common_tags, {
    component = "ai-security"
    vendor    = "defender"
  })
}

resource "aws_secretsmanager_secret_version" "defender_credentials" {
  count     = var.defender_enabled ? 1 : 0
  secret_id = aws_secretsmanager_secret.defender_credentials[0].id

  secret_string = jsonencode({
    tenant_id     = var.defender_tenant_id
    client_id     = var.defender_client_id
    client_secret = var.defender_client_secret
  })
}

resource "aws_secretsmanager_secret" "wiz_credentials" {
  count       = var.wiz_enabled ? 1 : 0
  name        = "${var.prefix}/ai-security/wiz"
  description = "Wiz API credentials for ShieldOps SOC Brain"

  tags = merge(var.common_tags, {
    component = "ai-security"
    vendor    = "wiz"
  })
}

resource "aws_secretsmanager_secret_version" "wiz_credentials" {
  count     = var.wiz_enabled ? 1 : 0
  secret_id = aws_secretsmanager_secret.wiz_credentials[0].id

  secret_string = jsonencode({
    client_id     = var.wiz_client_id
    client_secret = var.wiz_client_secret
    api_url       = var.wiz_api_url
  })
}

# ── Kubernetes ConfigMap: AI Security Runtime Settings ────────────────────

resource "kubernetes_config_map" "ai_security" {
  metadata {
    name      = "shieldops-ai-security"
    namespace = var.namespace

    labels = merge(var.common_tags, {
      component = "ai-security"
    })
  }

  data = {
    "firewall-mode"        = var.firewall_mode
    "auto-trip-threshold"  = tostring(var.firewall_auto_trip_threshold)
    "nhi-scan-schedule"    = var.nhi_scan_schedule
    "mcp-gateway-mode"     = var.mcp_gateway_mode
    "mcp-zero-trust-level" = var.mcp_zero_trust_level
    "soc-auto-execute"     = tostring(var.soc_auto_execute_threshold)
    "soc-approval-timeout" = tostring(var.soc_approval_timeout_minutes)
  }
}

# ── OPA Policy ConfigMap (deploy .rego files to OPA sidecar) ─────────────

resource "kubernetes_config_map" "opa_ai_policies" {
  metadata {
    name      = "shieldops-opa-ai-policies"
    namespace = var.namespace

    labels = merge(var.common_tags, {
      component = "opa"
    })
  }

  data = {
    "ai_agent_governance.rego" = file("${path.module}/policies/ai_agent_governance.rego")
    "mcp_zero_trust.rego"      = file("${path.module}/policies/mcp_zero_trust.rego")
    "nhi_least_privilege.rego"  = file("${path.module}/policies/nhi_least_privilege.rego")
  }
}

# ── IAM Policy: ShieldOps Secrets Manager Access ─────────────────────────

resource "aws_iam_policy" "ai_security_secrets_access" {
  name        = "${var.prefix}-ai-security-secrets"
  description = "Allow ShieldOps to read AI Security vendor credentials"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadAISecuritySecrets"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = ["arn:aws:secretsmanager:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:secret:${var.prefix}/ai-security/*"]
      },
      {
        Sid      = "ListAISecuritySecrets"
        Effect   = "Allow"
        Action   = ["secretsmanager:ListSecrets"]
        Resource = ["*"]
        Condition = {
          StringEquals = {
            "secretsmanager:ResourceTag/component" = "ai-security"
          }
        }
      }
    ]
  })

  tags = var.common_tags
}

# ── Data sources ──────────────────────────────────────────────────────────

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}
