# Audit Compliance Skill

Run compliance audits, generate evidence packages, and manage regulatory frameworks across the platform.

## Usage
`/audit-compliance <action> [--framework <name>] [--scope <environment>] [--format <pdf|json|csv>]`

Actions: `audit`, `evidence`, `report`, `gap-analysis`, `drift`, `status`

Frameworks: `soc2`, `pci_dss`, `hipaa`, `gdpr`, `fedramp`, `nist_csf`, `iso27001`, `eu_ai_act`, `nist_ai_rmf`, `iso42001`

## Agents Used
- `compliance_auditor` — Framework-specific compliance auditing
- `compliance_reporter` — Evidence packaging and audit report generation
- `compliance_scanner` — Continuous compliance scanning and drift detection
- `ai_compliance` — AI-specific compliance (EU AI Act, NIST AI RMF, ISO 42001)
- `access_review` — Access certification and recertification workflows
- `config_validator` — Configuration baseline compliance checking

## Process

### Audit
1. **Select framework**: Choose compliance framework(s) to audit against
2. **Scope environment**: Define audit scope (production, staging, specific services)
3. **Run auditor**: Execute `ComplianceAuditorRunner.audit()` against controls
4. **Collect evidence**: Gather automated evidence for each control
5. **Generate findings**: Produce gap analysis with remediation recommendations

```python
from shieldops.agents.compliance_auditor.runner import ComplianceAuditorRunner

runner = ComplianceAuditorRunner()
result = await runner.audit(
    frameworks=["soc2", "pci_dss"],
    scope="production",
    evidence_collection=True,
)
```

### Evidence Package
1. **Map controls**: Link controls to evidence sources
2. **Collect artifacts**: Screenshots, configs, logs, test results
3. **Verify integrity**: Cryptographic evidence chain validation
4. **Package**: Bundle into auditor-ready evidence package

```python
from shieldops.agents.compliance_reporter.runner import ComplianceReporterRunner

runner = ComplianceReporterRunner()
result = await runner.generate_evidence_package(
    framework="soc2",
    audit_period="2025-Q4",
    format="pdf",
)
```

### Gap Analysis
1. **Assess current state**: Scan all controls for current compliance status
2. **Identify gaps**: Flag missing controls, stale evidence, policy violations
3. **Prioritize**: Rank gaps by risk and audit timeline
4. **Remediation plan**: Generate actionable remediation steps

### AI Compliance
1. **EU AI Act**: Article 6/9/10/13/14 assessment for AI systems
2. **NIST AI RMF**: GOVERN/MAP/MEASURE/MANAGE function evaluation
3. **ISO 42001**: AI management system requirements check
4. **Model cards**: Generate transparency documentation

```python
from shieldops.agents.ai_compliance.runner import AIComplianceRunner

runner = AIComplianceRunner()
result = await runner.assess(
    framework="eu_ai_act",
    ai_system="shieldops_agents",
    risk_category="high",
)
```

## Key Files
- `src/shieldops/agents/compliance_auditor/` — Compliance auditor agent
- `src/shieldops/agents/compliance_reporter/` — Report generation agent
- `src/shieldops/agents/compliance_scanner/` — Continuous scanning agent
- `src/shieldops/agents/ai_compliance/` — AI compliance agent
- `src/shieldops/agents/access_review/` — Access review agent
- `src/shieldops/agents/config_validator/` — Config validation agent
- `src/shieldops/compliance/` — 116 compliance engines
- `src/shieldops/audit/` — 30 audit engines
- `src/shieldops/policy/` — OPA policies (hipaa.rego, pci_dss.rego, soc2.rego, gdpr.rego, fedramp.rego)
- `src/shieldops/compliance/compliance_evidence_packager.py` — Evidence packaging
- `src/shieldops/compliance/cross_framework_control_mapper.py` — Framework mapping

## Conventions
- Evidence must have cryptographic integrity verification (hash chain)
- Compliance scans run continuously; drift alerts within 15 minutes
- Access reviews must complete within 30 days of initiation
- AI compliance assessments required before deploying new agent types
- All audit findings require remediation owner and target date
