# Manage Cloud Skill

Manage cloud security posture — CSPM, container security, CNAPP, zero trust, and multi-cloud risk ranking.

## Usage
`/manage-cloud <action> [--provider <aws|gcp|azure|k8s>] [--scope <account|project|subscription>] [--benchmark <cis|nist>]`

Actions: `posture`, `containers`, `cnapp`, `zero-trust`, `risk-rank`, `network`, `status`

## Agents Used
- `cloud_posture` — Cloud misconfiguration detection and CIS benchmark scoring
- `cnapp_analyzer` — Unified CSPM + CWPP + CIEM + code security
- `container_security` — Container image scanning and K8s admission control
- `zero_trust_network` — ZTNA for humans, AI agents, NHIs, and MCP clients
- `unified_cloud_security` — Cross-cloud unified security posture
- `cloud_risk_ranker` — Multi-cloud risk ranking by attacker TTPs
- `network_segmentation` — Network segmentation policy enforcement
- `zero_trust` — Zero trust architecture enforcement

## Process

### Posture (Cloud Security Posture Management)
1. **Connect clouds**: Use AWS/GCP/Azure connectors to scan accounts
2. **Benchmark**: Run CIS benchmark scoring across all resources
3. **Detect misconfigs**: Identify security misconfigurations
4. **Prioritize**: Rank findings by exploitability and blast radius
5. **Remediate**: Generate remediation steps or auto-fix

```python
from shieldops.agents.cloud_posture.runner import CloudPostureRunner

runner = CloudPostureRunner(connectors={"aws": aws, "gcp": gcp, "azure": azure})
result = await runner.assess(
    providers=["aws", "gcp"],
    benchmark="cis_v2",
    auto_remediate=False,
)
```

### Containers (Container Security)
1. **Scan images**: Vulnerability scanning of container images
2. **Runtime protection**: Monitor running containers for anomalies
3. **Admission control**: K8s admission webhook for policy enforcement
4. **SBOM**: Generate software bill of materials for containers

```python
from shieldops.agents.container_security.runner import ContainerSecurityRunner

runner = ContainerSecurityRunner(connectors={"kubernetes": k8s})
result = await runner.scan(
    namespace="production",
    include_runtime=True,
    generate_sbom=True,
)
```

### CNAPP (Cloud-Native Application Protection)
1. **Unified view**: Aggregate CSPM + CWPP + CIEM findings
2. **Attack path analysis**: Map potential attack paths across cloud resources
3. **Identity entitlements**: Analyze cloud IAM for overprivilege
4. **Code security**: Scan IaC templates for misconfigurations

```python
from shieldops.agents.cnapp_analyzer.runner import CNAPPAnalyzerRunner

runner = CNAPPAnalyzerRunner()
result = await runner.analyze(
    providers=["aws", "gcp", "azure"],
    include_attack_paths=True,
    include_iam_analysis=True,
)
```

### Zero Trust
1. **Policy definition**: Define ZTNA policies for all entity types
2. **Microsegmentation**: Enforce least-privilege network access
3. **Continuous verification**: Verify identity and posture on every request
4. **AI agent access**: Apply zero trust to AI agent API calls and MCP connections

### Risk Rank
1. **Aggregate risks**: Collect findings across all cloud providers
2. **Map to TTPs**: Correlate with known attacker techniques
3. **Score**: Risk-rank by exploitability, impact, and active threats
4. **Report**: Generate executive risk dashboard

## Key Files
- `src/shieldops/agents/cloud_posture/` — CSPM agent
- `src/shieldops/agents/cnapp_analyzer/` — CNAPP agent
- `src/shieldops/agents/container_security/` — Container security agent
- `src/shieldops/agents/zero_trust_network/` — ZTNA agent
- `src/shieldops/agents/unified_cloud_security/` — Unified cloud agent
- `src/shieldops/agents/cloud_risk_ranker/` — Risk ranking agent
- `src/shieldops/agents/network_segmentation/` — Network segmentation agent
- `src/shieldops/connectors/aws/` — AWS connector (boto3)
- `src/shieldops/connectors/gcp/` — GCP connector
- `src/shieldops/connectors/azure/` — Azure connector
- `src/shieldops/connectors/kubernetes/` — Kubernetes connector
- `src/shieldops/security/cloud_misconfiguration_tracker.py` — Misconfig tracking
- `src/shieldops/security/cis_benchmark_scorer.py` — CIS scoring
- `src/shieldops/security/container_vulnerability_scanner.py` — Container scanning

## Conventions
- CSPM scans run continuously; critical misconfigs alert within 5 minutes
- Container images must pass vulnerability scan before deployment
- Zero trust policies default to deny; explicit allow rules required
- Multi-cloud findings normalized to OCSF schema
- Auto-remediation requires OPA policy approval and confidence >0.85
- CIS benchmarks tracked over time for compliance trending
