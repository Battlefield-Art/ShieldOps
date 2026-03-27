# policy/ — OPA Policy Engine

Open Policy Agent integration for all agent actions.

## Architecture
- `opa/client.py` — OPA client for policy evaluation
- `approval/workflow.py` — Human approval workflow
- `rollback/` — Rollback mechanisms

## Policy Files (Rego)
- `hipaa.rego` — HIPAA compliance
- `pci_dss.rego` — PCI DSS compliance
- `soc2.rego` — SOC 2 compliance
- `gdpr.rego` — GDPR compliance
- `fedramp.rego` — FedRAMP controls

## Confidence Thresholds
- `> 0.85` — Autonomous action (no approval needed)
- `0.5 - 0.85` — Human approval required
- `< 0.5` — Escalate to senior analyst

## Non-Negotiable Rules
- All agent actions MUST pass OPA policy before execution
- No agent can delete databases, drop tables, or modify IAM root
- Blast-radius limits enforced per environment (dev/staging/prod)
