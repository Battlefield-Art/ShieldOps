# PCI-DSS compliance policy
# Enforces: cardholder data protection, access control, network segmentation

package shieldops.pci_dss

import rego.v1

default allow := false

# Only authorized roles can access cardholder data
allow if {
    input.user.role in {"admin", "operator"}
    input.action.type in {"read_transaction", "process_payment"}
    input.environment != "development"
}

# Deny storing full PAN
deny contains msg if {
    input.action.type == "store_data"
    input.data.contains_full_pan == true
    msg := "Full PAN must not be stored - mask or truncate"
}

# Require MFA for cardholder data environment access
deny contains msg if {
    input.action.involves_cardholder_data == true
    not input.user.mfa_verified
    msg := "MFA required for cardholder data environment"
}

# Require network segmentation for CDE
deny contains msg if {
    input.action.involves_cardholder_data == true
    not input.network.segmented
    msg := "Cardholder data environment must be network-segmented (Req 1.3)"
}
