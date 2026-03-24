# NHI (Non-Human Identity) Least Privilege Policy
# Enforces credential TTL, permission limits, ownership requirements,
# staleness detection, and over-privilege flagging for all NHIs.

package shieldops.nhi_least_privilege

import rego.v1

default compliant := false

# NHI is compliant when all least-privilege checks pass
compliant if {
    credential_ttl_valid
    permissions_within_limits
    has_owner
    not stale_credential
}

# ── Credential TTL ────────────────────────────────────────────────

# Temporary credentials must expire within 1 hour
credential_ttl_valid if {
    input.credential_type == "temp_credential"
    input.ttl_seconds <= 3600
}

# API keys must be rotated within 90 days
credential_ttl_valid if {
    input.credential_type == "api_key"
    input.rotation_days <= 90
}

# OAuth tokens validated by issuer
credential_ttl_valid if {
    input.credential_type == "oauth_token"
    input.token_valid == true
}

# ── Permission limits ─────────────────────────────────────────────

permissions_within_limits if {
    count(input.permissions) <= input.max_permissions_for_type
}

# ── Ownership requirement ─────────────────────────────────────────

has_owner if {
    input.owner != ""
    input.owner != null
}

# ── Staleness detection ───────────────────────────────────────────

# Credentials unused for 90+ days are stale and should be revoked
stale_credential if {
    input.days_since_last_use > 90
}

# ── Over-privilege detection ──────────────────────────────────────

# AI agents should have at most 5 permissions
over_privileged if {
    input.nhi_type == "ai_agent"
    count(input.permissions) > 5
}

# Service accounts must not have admin access
over_privileged if {
    input.nhi_type == "service_account"
    input.has_admin_access == true
}

# Pipeline identities should not have write access to production
over_privileged if {
    input.nhi_type == "pipeline"
    input.has_production_write == true
    not input.approved_for_production
}

# ── Rotation requirements ─────────────────────────────────────────

requires_rotation if {
    input.credential_age_days > 30
    input.credential_type != "temp_credential"
}

# Urgent rotation for high-risk NHIs
urgent_rotation if {
    input.risk_score > 0.8
    input.credential_age_days > 7
}

# ── Violation reasons (for audit trail) ───────────────────────────

violation_reasons contains "credential_ttl_invalid" if {
    not credential_ttl_valid
}

violation_reasons contains "permissions_exceeded" if {
    not permissions_within_limits
}

violation_reasons contains "no_owner" if {
    not has_owner
}

violation_reasons contains "stale_credential" if {
    stale_credential
}

violation_reasons contains "over_privileged" if {
    over_privileged
}
