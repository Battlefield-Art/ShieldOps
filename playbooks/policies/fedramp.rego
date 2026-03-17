# FedRAMP compliance policy (NIST 800-53)
# Enforces: FIPS encryption, MFA, boundary protection, continuous monitoring

package shieldops.fedramp

import rego.v1

# FIPS 140-2 encryption required
deny contains msg if {
    input.action.involves_federal_data == true
    not input.transport.fips_compliant
    msg := "Federal data requires FIPS 140-2 compliant encryption (SC-13)"
}

# Multi-factor authentication for privileged access
deny contains msg if {
    input.user.role in {"admin"}
    not input.user.mfa_verified
    msg := "Privileged access requires multi-factor authentication (IA-2)"
}

# Boundary protection — deny access from unauthorized networks
deny contains msg if {
    input.action.involves_federal_data == true
    not input.network.authorized_boundary
    msg := "Access must originate from authorized network boundary (SC-7)"
}

# Continuous monitoring required
deny contains msg if {
    input.action.type == "disable_monitoring"
    input.environment == "production"
    msg := "Continuous monitoring cannot be disabled in production (CA-7)"
}
