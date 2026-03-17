# SOC 2 Type II compliance policy
# Enforces: security, availability, processing integrity, confidentiality, privacy

package shieldops.soc2

import rego.v1

# All agent actions must be logged
deny contains msg if {
    input.action.type == "agent_execution"
    not input.audit.enabled
    msg := "All agent actions must have audit logging enabled (CC6.1)"
}

# Change management requires approval
deny contains msg if {
    input.action.type in {"deploy", "config_change", "remediation"}
    input.action.risk_level in {"high", "critical"}
    not input.approval.granted
    msg := "High-risk changes require approval (CC8.1)"
}

# Logical access controls
deny contains msg if {
    input.action.type in {"access_grant", "role_change"}
    not input.approval.granted
    msg := "Access changes require documented approval (CC6.2)"
}

# System monitoring required
deny contains msg if {
    input.action.type == "disable_monitoring"
    msg := "Monitoring cannot be disabled — availability controls required (A1.2)"
}
