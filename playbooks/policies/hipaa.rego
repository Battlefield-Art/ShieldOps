# HIPAA compliance policy
# Enforces: PHI access controls, minimum necessary, audit requirements

package shieldops.hipaa

import rego.v1

default allow := false

# PHI access requires authenticated user with healthcare role
allow if {
    input.user.role == "admin"
    input.action.type != "delete_phi"
}

allow if {
    input.user.role == "operator"
    input.action.type == "read_phi"
    input.action.minimum_necessary == true
}

# Deny PHI access without audit trail
deny contains msg if {
    input.action.involves_phi == true
    not input.audit.enabled
    msg := "PHI access requires audit logging enabled"
}

# Deny PHI transmission without encryption
deny contains msg if {
    input.action.involves_phi == true
    not input.transport.encrypted
    msg := "PHI must be transmitted over encrypted channels"
}

# Deny PHI access without valid BAA
deny contains msg if {
    input.action.involves_phi == true
    not input.organization.baa_signed
    msg := "PHI access requires a signed Business Associate Agreement"
}
