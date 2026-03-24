# AI Agent Behavioral Governance Policy
# Enforces rate limits, tool authorization, operating hours, data volume,
# circuit breaker, and risk-based approval thresholds for all AI agent actions.

package shieldops.ai_agent_governance

import rego.v1

default allow_tool_call := false

# Allow tool calls that pass all safety checks
allow_tool_call if {
    not rate_limit_exceeded
    tool_is_authorized
    within_operating_hours
    data_volume_within_limits
    not circuit_breaker_open
}

# Rate limiting: max 100 calls per minute per agent
rate_limit_exceeded if {
    input.calls_in_window > 100
}

# Tool authorization: agent can only use tools in its allowed set
tool_is_authorized if {
    some tool in input.allowed_tools
    input.tool_name == tool
}

# Operating hours: restrict to business hours unless override granted
within_operating_hours if {
    input.current_hour >= 6
    input.current_hour <= 22
}

within_operating_hours if {
    input.allow_off_hours == true
}

# Data volume: max 10 MB per call
data_volume_within_limits if {
    input.data_bytes <= 10485760
}

# Circuit breaker: block if agent circuit breaker is open
circuit_breaker_open if {
    input.circuit_breaker_state == "open"
}

# ── Risk score evaluation ──────────────────────────────────────────

# High risk: requires escalation, no autonomous execution
high_risk if {
    input.risk_score > 0.85
}

# Medium risk: requires human approval before execution
requires_approval if {
    input.risk_score > 0.5
    input.risk_score <= 0.85
}

# Low risk: fully autonomous execution allowed
auto_allowed if {
    input.risk_score <= 0.5
}

# ── Blast-radius limits ───────────────────────────────────────────

# Block actions that affect too many resources at once
blast_radius_exceeded if {
    input.affected_resource_count > input.max_blast_radius
}

# Production environment requires stricter limits
production_restricted if {
    input.environment == "production"
    input.risk_score > 0.5
    not input.has_approval
}

# ── Deny reasons (for audit trail) ────────────────────────────────

deny_reasons contains "rate_limit_exceeded" if {
    rate_limit_exceeded
}

deny_reasons contains "tool_not_authorized" if {
    not tool_is_authorized
}

deny_reasons contains "outside_operating_hours" if {
    not within_operating_hours
}

deny_reasons contains "data_volume_exceeded" if {
    not data_volume_within_limits
}

deny_reasons contains "circuit_breaker_open" if {
    circuit_breaker_open
}

deny_reasons contains "blast_radius_exceeded" if {
    blast_radius_exceeded
}
