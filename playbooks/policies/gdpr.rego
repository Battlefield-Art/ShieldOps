# GDPR/PII compliance policy
# Enforces: data minimization, right to erasure, purpose limitation, consent

package shieldops.gdpr

import rego.v1

# Right to erasure
deny contains msg if {
    input.action.type == "data_retention"
    input.data.erasure_requested == true
    msg := "Data subject erasure request must be honored (Art. 17)"
}

# Data minimization
deny contains msg if {
    input.action.type == "collect_data"
    not input.data.purpose_specified
    msg := "Personal data collection requires specified purpose (Art. 5)"
}

# Cross-border transfer restrictions
deny contains msg if {
    input.action.type == "transfer_data"
    input.data.contains_pii == true
    not input.transfer.adequacy_decision
    not input.transfer.standard_clauses
    msg := "PII transfer outside EEA requires adequacy decision or SCCs (Art. 46)"
}

# Consent requirement for processing
deny contains msg if {
    input.action.type == "process_personal_data"
    not input.data.consent_obtained
    not input.data.legal_basis_specified
    msg := "Processing personal data requires consent or legal basis (Art. 6)"
}
