# Compliance Auditor Agent

Automated compliance scanning agent that continuously validates infrastructure and application configurations against SOC2, PCI-DSS, HIPAA, and GDPR frameworks. Collects evidence, identifies gaps, and generates audit-ready reports.

## Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│    Scan      │────▶│    Map       │────▶│   Collect    │────▶│    Report    │
│  Resources   │     │  Controls    │     │  Evidence    │     │   & Remediate│
└──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
       │                    │                    │                    │
       ▼                    ▼                    ▼                    ▼
  Cloud Config         Framework Map        Auto Evidence       Audit Reports
  IAM Policies         Control Matrix       Screenshots         Gap Analysis
  Network Rules        Gap Detection        Config Snapshots    Fix Playbooks
```

## Workflow

1. **Scan** -- Inventories cloud resources (IAM policies, network configs, encryption settings, logging configurations) across AWS, GCP, and Azure. Checks Kubernetes RBAC, pod security standards, and network policies.
2. **Map** -- Maps discovered configurations against compliance control frameworks. Maintains a control matrix covering SOC2 Trust Services Criteria, PCI-DSS v4.0 requirements, HIPAA Security Rule, and GDPR Article 32 technical measures.
3. **Collect** -- Automatically gathers audit evidence: configuration snapshots, access logs, encryption verification, data flow diagrams, and policy documents. Timestamps and hashes all evidence for integrity.
4. **Report** -- Generates framework-specific audit reports with pass/fail per control, evidence references, gap analysis, and prioritized remediation playbooks. Tracks compliance posture over time with trend dashboards.

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `COMPLIANCE_FRAMEWORKS` | Frameworks to audit against | `soc2,pci` |
| `COMPLIANCE_SCAN_SCHEDULE` | Cron schedule for scans | `0 2 * * *` |
| `COMPLIANCE_EVIDENCE_BUCKET` | S3/GCS bucket for evidence | Required |
| `COMPLIANCE_ALERT_ON_CRITICAL` | Alert on critical control failures | `true` |
| `COMPLIANCE_REPORT_FORMAT` | Output format (pdf, json, html) | `pdf` |

## Usage

```bash
# Trigger via CLI
shieldops run-agent compliance_auditor --frameworks soc2,hipaa --scope production

# Trigger via API
curl -X POST /api/v1/agents/compliance_auditor/run \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"frameworks": ["soc2", "pci_dss"], "scope": "all", "collect_evidence": true}'
```

Returns a compliance report with overall posture score, per-control results, evidence inventory, and remediation priorities.
