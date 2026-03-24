# MCP Zero Trust Policy
# Enforces authentication, encrypted transport, agent authorization,
# rate limits, and detects god-key risks for MCP server interactions.

package shieldops.mcp_zero_trust

import rego.v1

default allow_mcp_request := false

# Allow MCP requests that pass all zero-trust checks
allow_mcp_request if {
    auth_valid
    transport_encrypted
    agent_authorized
    rate_within_limits
    not god_key_risk
}

# ── Authentication ─────────────────────────────────────────────────

auth_valid if {
    input.auth_type == "oauth2"
}

auth_valid if {
    input.auth_type == "mtls"
}

auth_valid if {
    input.auth_type == "jwt"
}

# ── Transport encryption ──────────────────────────────────────────

transport_encrypted if {
    input.transport == "https"
}

transport_encrypted if {
    input.transport == "wss"
}

transport_encrypted if {
    input.tls_enabled == true
}

# ── Agent authorization ───────────────────────────────────────────

agent_authorized if {
    some agent in input.allowed_agents
    input.agent_id == agent
}

# ── Rate limiting ─────────────────────────────────────────────────

rate_within_limits if {
    input.requests_in_window <= input.rate_limit
}

# ── God-key detection ─────────────────────────────────────────────
# Flag overly broad credentials with access to many downstream resources

god_key_risk if {
    input.downstream_resource_count > 20
    input.credential_scope == "full_access"
}

# ── Scope reduction ───────────────────────────────────────────────
# Recommend reducing scope when admin access spans many resources

requires_scope_reduction if {
    input.downstream_resource_count > 10
    input.permission_level == "admin"
}

# ── Tool-level authorization ──────────────────────────────────────

tool_allowed if {
    some tool in input.allowed_tools
    input.requested_tool == tool
}

# ── Deny reasons (for audit trail) ────────────────────────────────

deny_reasons contains "auth_invalid" if {
    not auth_valid
}

deny_reasons contains "transport_not_encrypted" if {
    not transport_encrypted
}

deny_reasons contains "agent_not_authorized" if {
    not agent_authorized
}

deny_reasons contains "rate_limit_exceeded" if {
    not rate_within_limits
}

deny_reasons contains "god_key_detected" if {
    god_key_risk
}
