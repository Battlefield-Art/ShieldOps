# Manage Vulns Skill

Manage vulnerability lifecycle — scanning, prioritization, remediation tracking, supply chain, and secrets detection.

## Usage
`/manage-vulns <action> [--scope <environment>] [--severity <critical|high|medium|low>] [--type <code|deps|infra|secrets|supply-chain>]`

Actions: `scan`, `prioritize`, `track`, `secrets`, `supply-chain`, `code`, `status`

## Agents Used
- `vulnerability_manager` — Vulnerability lifecycle management and tracking
- `vulnerability_intelligence` — Scanless vulnerability assessment from telemetry
- `code_security_scanner` — Shift-left IaC, code, SCA, and AI config scanning
- `supply_chain_security` — SBOM dependency scanning and CI/CD pipeline security
- `supply_chain_scanner` — Software supply chain integrity verification
- `secrets_scanner` — Secret exposure tracking and credential leak analysis
- `file_integrity_monitor` — AI-enhanced FIM for system, AI model, and K8s files
- `exposure_management` — Unified attack surface including AI endpoints and MCP

## Process

### Scan (Vulnerability Scanning)
1. **Code scan**: Run SAST/DAST on application code
2. **Dependency scan**: Check all dependencies against CVE databases
3. **IaC scan**: Scan Terraform, K8s manifests for misconfigurations
4. **Container scan**: Image vulnerability scanning
5. **AI config scan**: Check AI agent and model configurations

```python
from shieldops.agents.code_security_scanner.runner import CodeSecurityScannerRunner

runner = CodeSecurityScannerRunner()
result = await runner.scan(
    targets=["src/", "infrastructure/terraform/", "infrastructure/kubernetes/"],
    scan_types=["sast", "sca", "iac", "ai_config"],
)
```

### Prioritize (Vulnerability Intelligence)
1. **Assess exploitability**: Check for known exploits in the wild
2. **Map attack surface**: Determine which vulns are reachable
3. **Score risk**: Combine CVSS, EPSS, asset criticality, exposure
4. **Rank**: Produce prioritized remediation list

```python
from shieldops.agents.vulnerability_intelligence.runner import VulnerabilityIntelligenceRunner

runner = VulnerabilityIntelligenceRunner()
result = await runner.prioritize(
    findings=scan_results,
    include_epss=True,
    include_exploit_db=True,
)
```

### Secrets (Secret Scanning)
1. **Scan repos**: Check source code for hardcoded credentials
2. **Scan configs**: Check config files, environment variables, K8s secrets
3. **Detect leaks**: Monitor for credential leaks in logs, outputs
4. **Remediate**: Rotate compromised credentials, update references

```python
from shieldops.agents.secrets_scanner.runner import SecretsScannerRunner

runner = SecretsScannerRunner()
result = await runner.scan(
    targets=["src/", "infrastructure/", ".env*", "docker-compose.yml"],
    check_git_history=True,
    auto_rotate=False,
)
```

### Supply Chain
1. **Generate SBOM**: Create software bill of materials
2. **Verify integrity**: Check dependency signatures and provenance
3. **CI/CD audit**: Scan pipeline configs for injection vectors
4. **Monitor**: Continuous monitoring for new supply chain threats

### Track (Lifecycle Management)
1. **Intake**: Ingest findings from all scanners
2. **Deduplicate**: Merge duplicate findings across tools
3. **Assign**: Route to appropriate team for remediation
4. **Track SLA**: Monitor remediation SLA compliance (critical: 24h, high: 7d, medium: 30d)

## Key Files
- `src/shieldops/agents/vulnerability_manager/` — Vuln lifecycle agent
- `src/shieldops/agents/vulnerability_intelligence/` — Vuln intel agent
- `src/shieldops/agents/code_security_scanner/` — Code scanning agent
- `src/shieldops/agents/supply_chain_security/` — Supply chain agent
- `src/shieldops/agents/supply_chain_scanner/` — Supply chain scanner agent
- `src/shieldops/agents/secrets_scanner/` — Secrets scanning agent
- `src/shieldops/agents/file_integrity_monitor/` — FIM agent
- `src/shieldops/agents/exposure_management/` — Attack surface agent
- `src/shieldops/security/vulnerability_exploit_predictor.py` — Exploit prediction
- `src/shieldops/security/sbom_dependency_scanner.py` — SBOM scanning
- `src/shieldops/security/secret_exposure_tracker.py` — Secret exposure tracking

## Conventions
- Critical vulnerabilities require remediation within 24 hours
- All dependencies must have SBOM entries; new deps trigger automatic scan
- Secret scanning runs on every commit via pre-commit hook
- Supply chain integrity checks required for all third-party dependencies
- Vulnerability SLAs: critical 24h, high 7d, medium 30d, low 90d
- Never suppress vulnerability findings without documented exception
