# SOC 2 Type I Audit Preparation

ShieldOps' artifact bundle for the upcoming SOC 2 Type I audit. This
directory holds policies, procedures, evidence collection scripts, and
control mapping. Designed for handoff to a third-party auditor (e.g.
Drata-managed, Vanta-managed, or direct firm engagement).

## Audit window

| Field | Value |
|---|---|
| Audit window | 2026-04-01 → 2026-09-30 (6 months) |
| Type | Type I (design of controls at a point in time) |
| Trust Service Criteria | Security, Availability, Confidentiality |
| Auditor | _placeholder_ — to be selected |
| Target report date | 2026-11-15 |

Type II (operating effectiveness over a period) is planned for 2027 once
the controls have a 6+ month operating history.

## Directory layout

```
docs/compliance/soc2/
├── README.md                     ← you are here
├── control-mapping.md            ← TSC → ShieldOps controls
├── risk-assessment.md            ← asset inventory + threat model
├── policies/                     ← what we promise to do
│   ├── access-control.md
│   ├── acceptable-use.md
│   ├── business-continuity.md
│   ├── change-management.md
│   ├── data-classification.md
│   ├── encryption.md
│   ├── incident-response.md
│   └── vendor-management.md
└── procedures/                   ← how we actually do it
    ├── access-review.md
    ├── backup-and-restore.md
    ├── code-review.md
    ├── deployment-approval.md
    ├── employee-offboarding.md
    ├── employee-onboarding.md
    ├── incident-escalation.md
    └── secrets-rotation.md
```

Evidence is collected by `scripts/audit/collect_evidence.py` (run nightly
in CI; output stored in `s3://shieldops-audit-evidence/`).

## Pre-audit checklist

### 30 days before fieldwork

- [ ] All policies + procedures published, version-controlled, and approved
- [ ] All employees have completed annual security awareness training
- [ ] Most-recent quarterly access review documented
- [ ] Most-recent quarterly secrets rotation documented
- [ ] Backup restore drill performed and documented in last 90 days
- [ ] DR tabletop exercise performed and documented in last 12 months
- [ ] Pentest report from last 12 months on file
- [ ] Vendor risk reviews complete for all sub-processors
- [ ] Vulnerability scans clean for last 30 days
- [ ] Auditor access to staging + read-only production granted

### 7 days before fieldwork

- [ ] Evidence collection script runs cleanly
- [ ] Audit-window evidence package prepared (PRs, deploys, incidents,
      access reviews, backups, scans) — see `scripts/audit/collect_evidence.py`
- [ ] Auditor contact info distributed to engineering leadership
- [ ] Auditor questionnaire (CAIQ-Lite) completed
- [ ] Conference room reserved if onsite

### Day of kickoff

- [ ] Welcome meeting with auditor (1 hour)
- [ ] Walkthrough of architecture + controls (1 hour)
- [ ] Provide auditor with read-only credentials
- [ ] Slack channel for auditor Q&A established

## Roles and responsibilities

| Role | Person | Responsibility |
|---|---|---|
| Audit Sponsor | CTO | Final sign-off on policies, scope decisions |
| Audit Lead | Head of Security | Day-to-day auditor liaison |
| Engineering Lead | VP Engineering | Technical evidence (deploys, code review, infra) |
| People Ops Lead | HR | HR evidence (onboarding/offboarding, training) |
| Legal | Outside counsel | DPA, vendor agreements |
| External Advisor | TBD | Pre-audit gap analysis |

## Contact

- **Audit lead:** security@shieldops.io
- **Compliance questions:** compliance@shieldops.io

## References

- [Trust Service Criteria (AICPA, 2017)](https://www.aicpa.org/content/dam/aicpa/interestareas/frc/assuranceadvisoryservices/downloadabledocuments/trust-services-criteria.pdf)
- [Vendor Security Policies](../../security/)
- [Privacy Policy](../../legal/privacy-policy.md)
- [DPA Template](../../legal/dpa-template.md)
- [Vulnerability Disclosure Policy](../../security/vulnerability-disclosure-policy.md)
