# SOC 2 Trust Service Criteria → ShieldOps Controls

This document maps each Trust Service Criteria (TSC) point to one or more
ShieldOps controls (technical, procedural, or both). Use this as the
auditor's primary navigation aid into our control environment.

## Scope criteria

ShieldOps is in scope for the following Trust Service Categories:
- **Security** (mandatory)
- **Availability**
- **Confidentiality**

We are **not** claiming Privacy or Processing Integrity in this engagement
(planned for Type II in 2027).

---

## CC1 — Control environment

| Criterion | ShieldOps controls |
|---|---|
| CC1.1 — Demonstrates commitment to integrity and ethical values | Code of Conduct (HR handbook); annual ethics training; whistleblower channel |
| CC1.2 — Board exercises oversight | Quarterly security review at board meetings; signed minutes |
| CC1.3 — Establishes structures, reporting lines, authorities | Org chart; RACI matrix in `docs/team/responsibilities.md` |
| CC1.4 — Demonstrates commitment to competence | Job descriptions with required skills; annual performance reviews; training budget |
| CC1.5 — Holds individuals accountable | Performance reviews; security incident retros; documented disciplinary policy |

## CC2 — Communication and information

| Criterion | ShieldOps controls |
|---|---|
| CC2.1 — Obtains and uses relevant information | Threat-intel feeds (CISA, vendor advisories); incident DB; metric dashboards |
| CC2.2 — Internal communication of objectives and responsibilities | All-hands meetings; published security policies in `docs/compliance/soc2/policies/`; Slack channels |
| CC2.3 — External communication | Status page (status.shieldops.io); customer email notifications; vulnerability disclosure policy |

## CC3 — Risk assessment

| Criterion | ShieldOps controls |
|---|---|
| CC3.1 — Specifies suitable objectives | Security Objectives in `docs/compliance/soc2/risk-assessment.md` |
| CC3.2 — Identifies and analyzes risk | Risk register; quarterly risk review; threat model |
| CC3.3 — Assesses fraud risk | Separation of duties (no single person can deploy + approve + audit); 4-eye principle on prod changes |
| CC3.4 — Identifies and assesses change | Change management policy; CAB (informal for now) |

## CC4 — Monitoring activities

| Criterion | ShieldOps controls |
|---|---|
| CC4.1 — Selects, develops, performs evaluations | Internal audits quarterly; SOC 2 annual; pentest annual; bug bounty / VDP |
| CC4.2 — Communicates deficiencies | Findings tracker (Linear); CTO escalation for Critical; quarterly board update |

## CC5 — Control activities

| Criterion | ShieldOps controls |
|---|---|
| CC5.1 — Selects and develops control activities | Control library (this document); design reviews |
| CC5.2 — Selects and develops technology controls | OPA policy gates; agent firewall; tenant isolation; encryption at rest + transit |
| CC5.3 — Deploys through policies and procedures | Policies in this directory; automated enforcement via CI gates |

## CC6 — Logical and physical access

| Criterion | ShieldOps controls |
|---|---|
| CC6.1 — Logical access security | JWT auth; RBAC (admin/operator/viewer); MFA enforced; SSO via OIDC; API keys hashed at rest |
| CC6.2 — Authorization and modification | New user approval workflow; quarterly access reviews; immediate offboarding |
| CC6.3 — Removal of access | Offboarding checklist; SCIM auto-deprovision; immediate revocation on termination |
| CC6.4 — Restricts physical access | Cloud-only — no physical facilities (AWS data center physical security inherited) |
| CC6.5 — Protection at end of life | Encrypted-at-rest data; AWS-managed disk shredding; documented destruction |
| CC6.6 — Logical access protection of system boundaries | VPC + security groups; WAF; private subnets for DB/cache; no direct DB access from internet |
| CC6.7 — Information transmitted | TLS 1.3 only; HSTS preload; no plaintext fallback |
| CC6.8 — Prevents unauthorized data access | Tenant isolation tests (`tests/unit/api/test_tenant_isolation.py`); SQL injection prevention; SSRF protection |

## CC7 — System operations

| Criterion | ShieldOps controls |
|---|---|
| CC7.1 — Identifies and manages new vulnerabilities | Dependabot; weekly vulnerability scans; vulnerability_manager agent |
| CC7.2 — Monitors system components for anomalies | CloudWatch alarms; Prometheus metrics; agent observability traces; behavioral analytics |
| CC7.3 — Evaluates security events | SOC analyst agent; situations queue; runbook for triage |
| CC7.4 — Responds to security incidents | Incident response policy + procedure; PagerDuty integration; incident_response agent |
| CC7.5 — Recovers from incidents | DR plan; backup-and-restore procedure; tested quarterly |

## CC8 — Change management

| Criterion | ShieldOps controls |
|---|---|
| CC8.1 — Authorizes, develops, tests, approves, releases changes | PR review (1+ approver); CI gates (lint, type, test, security); staging deploy; production approval; deployment_approval procedure |

## CC9 — Risk mitigation

| Criterion | ShieldOps controls |
|---|---|
| CC9.1 — Identifies, selects, develops risk mitigation | Risk register with mitigation owners |
| CC9.2 — Manages business partner risks | Vendor management policy; vendor risk reviews; sub-processor list |

---

## A1 — Availability

| Criterion | ShieldOps controls |
|---|---|
| A1.1 — Capacity demand | Auto-scaling on ECS; RDS read replicas; ClickHouse cluster |
| A1.2 — Environmental protections | Cloud-only (AWS Multi-AZ); BCP/DR plan |
| A1.3 — Tests recovery procedures | Quarterly DR drill; weekly backup restore test |

---

## C1 — Confidentiality

| Criterion | ShieldOps controls |
|---|---|
| C1.1 — Identifies and maintains confidential information | Data classification policy; tagging; tenant isolation |
| C1.2 — Disposes of confidential information | Customer Data deletion within 30 days of termination; backup deletion within 90 days |

---

## Coverage matrix

| TSC criterion count | Covered | Coverage % |
|---|---|---|
| Common Criteria (CC1–CC9) | 33/33 | 100% |
| Availability (A1) | 3/3 | 100% |
| Confidentiality (C1) | 2/2 | 100% |
| **Total** | **38/38** | **100%** |

## Evidence references

For each control, evidence is collected automatically by
`scripts/audit/collect_evidence.py` and stored in
`s3://shieldops-audit-evidence/{audit_window}/`. The script generates a
markdown index mapping each control to its supporting evidence files.

## Gaps and remediation

| Gap | Owner | Target date |
|---|---|---|
| Privacy criterion (P1–P8) | Compliance | Type II 2027 |
| Processing Integrity (PI1) | Compliance | Type II 2027 |
| Formal Change Advisory Board | CTO | 2026-Q3 |
| ISO 27001 certification | Compliance | 2027 |
