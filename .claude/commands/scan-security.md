# Security Scan Skill

Run security audits on ShieldOps codebase, agents, infrastructure, and compliance posture.

## Usage
`/scan-security [--scope <area>] [--severity <level>]`

## Scopes
- `code` — Static analysis (ruff, bandit, safety)
- `deps` — Dependency vulnerability scan
- `policies` — OPA policy completeness check
- `agents` — Agent blast-radius and permission audit
- `compliance` — Compliance gap analysis (SOC 2, PCI-DSS, HIPAA, GDPR, FedRAMP)
- `audit` — Configuration audit trail review
- `isolation` — Tenant resource isolation checks
- `licenses` — Dependency license compliance
- `access` — Access certification review
- `contracts` — API contract drift and breaking changes
- `vulns` — Vulnerability lifecycle and exploit risk
- `secrets` — Hardcoded credential and secrets sprawl detection
- `infra` — Infrastructure-as-code security scan (checkov, tfsec)
- `containers` — Container image vulnerability scanning
- `cloud` — Cloud posture management (CIS benchmarks)
- `network` — Network flow analysis and exfiltration detection
- `certs` — Certificate expiry monitoring
- `all` — Full security audit (all scopes)

## Agents Used
- `code_security_scanner` — Shift-left SAST/SCA/IaC scanning
- `vulnerability_manager` — Vulnerability lifecycle tracking
- `secrets_scanner` — Secret exposure tracking and credential leak analysis
- `container_security` — Container image and runtime scanning
- `cloud_posture` — Cloud misconfiguration and CIS benchmark scoring
- `compliance_scanner` — Continuous compliance scanning and drift detection
- `exposure_management` — Unified attack surface monitoring
- `api_security` — API endpoint threat detection

## Process

### Code Security
1. **Static analysis**: Run bandit for Python security issues
2. **Secret detection**: Scan for hardcoded credentials
3. **Dependency audit**: Check all dependencies against CVE databases
4. **License compliance**: Verify dependency licenses

```bash
# Quick code scan
python3 -m ruff check src/ tests/ --select S  # security rules
bandit -c pyproject.toml -ll -r src/
```

### Agent Security Audit
1. **Blast radius**: Verify per-environment limits enforced
2. **OPA policies**: Confirm all agent actions have policy rules
3. **Permissions**: Audit tool call permissions per agent type
4. **Decision audit**: Review agent decision trails

```python
from shieldops.agents.agent_governance.runner import AgentGovernanceRunner

runner = AgentGovernanceRunner()
result = await runner.assess(
    agent_type="remediation",
    environment="production",
    check_capabilities=True,
    check_escalation=True,
)
```

### Infrastructure Security
1. **IaC scan**: Scan Terraform/K8s configs (checkov, tfsec)
2. **Container scan**: Image vulnerability scanning
3. **Cloud posture**: CIS benchmark assessment
4. **Network**: Flow analysis and segmentation audit

### Compliance Scan
1. **Framework assessment**: Check controls against SOC 2, PCI-DSS, HIPAA, GDPR, FedRAMP
2. **Evidence freshness**: Verify evidence is current
3. **Policy drift**: Detect compliance policy drift
4. **Access review**: Check expired/uncertified access grants

## Key Files
- `src/shieldops/agents/code_security_scanner/` — Code scanning agent
- `src/shieldops/agents/vulnerability_manager/` — Vuln lifecycle agent
- `src/shieldops/agents/secrets_scanner/` — Secrets scanning agent
- `src/shieldops/agents/container_security/` — Container security agent
- `src/shieldops/agents/cloud_posture/` — Cloud posture agent
- `src/shieldops/agents/compliance_scanner/` — Compliance scanning agent
- `src/shieldops/agents/api_security/` — API security agent
- `src/shieldops/security/` — 518 security engines
- `src/shieldops/compliance/` — 116 compliance engines
- `src/shieldops/audit/` — 30 audit engines
- `src/shieldops/policy/` — OPA policies (hipaa.rego, pci_dss.rego, soc2.rego, gdpr.rego, fedramp.rego)
- `infrastructure/terraform/` — Terraform configs to scan
- `infrastructure/kubernetes/` — K8s manifests to scan

## Conventions
- Critical findings require remediation within 24 hours
- All scan results logged to immutable audit trail
- Secret scanning runs on every commit via pre-commit hooks
- Container images must pass scan before deployment
- OPA policy coverage must be 100% for production agents
- Compliance scans run continuously; drift alerts within 15 minutes
