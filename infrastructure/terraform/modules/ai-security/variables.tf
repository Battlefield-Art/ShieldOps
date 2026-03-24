###############################################################################
# ShieldOps AI Security Module — Input Variables
###############################################################################

# ── General ───────────────────────────────────────────────────────────────

variable "prefix" {
  description = "Resource name prefix (e.g. 'shieldops-prod')"
  type        = string
  default     = "shieldops"
}

variable "namespace" {
  description = "Kubernetes namespace for AI Security resources"
  type        = string
  default     = "shieldops"
}

variable "common_tags" {
  description = "Tags applied to all resources"
  type        = map(string)
  default = {
    managed_by = "terraform"
    project    = "shieldops"
  }
}

# ── CrowdStrike ──────────────────────────────────────────────────────────

variable "crowdstrike_enabled" {
  description = "Enable CrowdStrike Falcon integration"
  type        = bool
  default     = false
}

variable "crowdstrike_client_id" {
  description = "CrowdStrike API client ID"
  type        = string
  default     = ""
  sensitive   = true
}

variable "crowdstrike_client_secret" {
  description = "CrowdStrike API client secret"
  type        = string
  default     = ""
  sensitive   = true
}

variable "crowdstrike_base_url" {
  description = "CrowdStrike API base URL"
  type        = string
  default     = "https://api.crowdstrike.com"

  validation {
    condition     = can(regex("^https://", var.crowdstrike_base_url))
    error_message = "CrowdStrike base URL must use HTTPS."
  }
}

# ── Microsoft Defender ───────────────────────────────────────────────────

variable "defender_enabled" {
  description = "Enable Microsoft Defender integration"
  type        = bool
  default     = false
}

variable "defender_tenant_id" {
  description = "Azure AD tenant ID for Defender"
  type        = string
  default     = ""
  sensitive   = true
}

variable "defender_client_id" {
  description = "Defender app registration client ID"
  type        = string
  default     = ""
  sensitive   = true
}

variable "defender_client_secret" {
  description = "Defender app registration client secret"
  type        = string
  default     = ""
  sensitive   = true
}

# ── Wiz ──────────────────────────────────────────────────────────────────

variable "wiz_enabled" {
  description = "Enable Wiz cloud security integration"
  type        = bool
  default     = false
}

variable "wiz_client_id" {
  description = "Wiz service account client ID"
  type        = string
  default     = ""
  sensitive   = true
}

variable "wiz_client_secret" {
  description = "Wiz service account client secret"
  type        = string
  default     = ""
  sensitive   = true
}

variable "wiz_api_url" {
  description = "Wiz API endpoint URL"
  type        = string
  default     = "https://api.us1.app.wiz.io/graphql"

  validation {
    condition     = can(regex("^https://", var.wiz_api_url))
    error_message = "Wiz API URL must use HTTPS."
  }
}

# ── Agent Firewall ───────────────────────────────────────────────────────

variable "firewall_mode" {
  description = "Agent firewall operating mode"
  type        = string
  default     = "enforce"

  validation {
    condition     = contains(["enforce", "monitor", "disabled"], var.firewall_mode)
    error_message = "firewall_mode must be one of: enforce, monitor, disabled."
  }
}

variable "firewall_auto_trip_threshold" {
  description = "Number of blocked actions before circuit breaker trips"
  type        = number
  default     = 5

  validation {
    condition     = var.firewall_auto_trip_threshold >= 1 && var.firewall_auto_trip_threshold <= 100
    error_message = "Threshold must be between 1 and 100."
  }
}

# ── NHI (Non-Human Identity) ────────────────────────────────────────────

variable "nhi_scan_schedule" {
  description = "Cron schedule for NHI credential scanning"
  type        = string
  default     = "0 */6 * * *"
}

# ── MCP Gateway ──────────────────────────────────────────────────────────

variable "mcp_gateway_mode" {
  description = "MCP gateway operating mode"
  type        = string
  default     = "proxy"

  validation {
    condition     = contains(["proxy", "passthrough", "strict"], var.mcp_gateway_mode)
    error_message = "mcp_gateway_mode must be one of: proxy, passthrough, strict."
  }
}

variable "mcp_zero_trust_level" {
  description = "Zero-trust enforcement level for MCP tool calls"
  type        = string
  default     = "standard"

  validation {
    condition     = contains(["relaxed", "standard", "strict", "paranoid"], var.mcp_zero_trust_level)
    error_message = "mcp_zero_trust_level must be one of: relaxed, standard, strict, paranoid."
  }
}

# ── SOC Brain ────────────────────────────────────────────────────────────

variable "soc_auto_execute_threshold" {
  description = "Confidence threshold above which SOC auto-executes (0.0-1.0)"
  type        = number
  default     = 0.85

  validation {
    condition     = var.soc_auto_execute_threshold >= 0.5 && var.soc_auto_execute_threshold <= 1.0
    error_message = "Auto-execute threshold must be between 0.5 and 1.0."
  }
}

variable "soc_approval_timeout_minutes" {
  description = "Minutes to wait for human approval before escalating"
  type        = number
  default     = 15

  validation {
    condition     = var.soc_approval_timeout_minutes >= 1 && var.soc_approval_timeout_minutes <= 1440
    error_message = "Approval timeout must be between 1 and 1440 minutes."
  }
}
