# Protect Data Skill

Manage data protection — DLP, data classification, sensitive data monitoring, pipeline security, and data resilience.

## Usage
`/protect-data <action> [--scope <environment>] [--classification <level>] [--policy <name>]`

Actions: `classify`, `dlp`, `monitor`, `pipeline`, `resilience`, `vault`, `status`

Classification levels: `public`, `internal`, `confidential`, `restricted`, `top_secret`

## Agents Used
- `data_loss_prevention` — Cross-surface DLP including AI pipelines and MCP tools
- `data_classification` — Automated data classification and labeling
- `sensitive_data_monitor` — Continuous monitoring of sensitive data access and movement
- `data_pipeline_security` — RAG pipeline protection and model provenance tracking
- `data_resilience` — Immutable data protection and observability for AI models
- `data_threat_hunting` — LLM-powered threat hunting in data stores
- `air_gap_vault` — Air-gapped vault for backups, AI models, and configs
- `data_intelligence` — Data intelligence and analytics

## Process

### Classify (Data Classification)
1. **Discover data stores**: Scan databases, object storage, file systems, AI pipelines
2. **Classify content**: Apply classification labels (PII, PHI, PCI, financial, IP)
3. **Label**: Attach classification metadata to data assets
4. **Policy**: Enforce handling policies per classification level

```python
from shieldops.agents.data_classification.runner import DataClassificationRunner

runner = DataClassificationRunner()
result = await runner.classify(
    targets=["s3://data-lake", "postgresql://main-db", "redis://cache"],
    detect_pii=True,
    detect_phi=True,
    detect_pci=True,
)
```

### DLP (Data Loss Prevention)
1. **Monitor channels**: Watch email, API, file transfer, AI tool calls, MCP
2. **Detect exfiltration**: Identify unauthorized data movement
3. **Block/alert**: Enforce DLP policies (block, quarantine, alert)
4. **Report**: Generate DLP incident reports

```python
from shieldops.agents.data_loss_prevention.runner import DataLossPreventionRunner

runner = DataLossPreventionRunner()
result = await runner.scan(
    channels=["api", "email", "file_transfer", "ai_pipeline", "mcp"],
    policies=["pii_no_export", "pci_restricted", "ip_protection"],
)
```

### Pipeline (AI Pipeline Security)
1. **Audit RAG pipelines**: Check for data poisoning, prompt injection in retrieval
2. **Track provenance**: Verify training data lineage and model provenance
3. **Monitor inference**: Watch for sensitive data in model inputs/outputs
4. **Secure embeddings**: Protect vector databases from extraction attacks

```python
from shieldops.agents.data_pipeline_security.runner import DataPipelineSecurityRunner

runner = DataPipelineSecurityRunner()
result = await runner.audit(
    pipeline_type="rag",
    components=["retriever", "vector_db", "llm", "output"],
    check_poisoning=True,
    check_leakage=True,
)
```

### Resilience (Data Protection)
1. **Backup verification**: Validate backup integrity and recoverability
2. **Immutability**: Ensure immutable backups for critical data
3. **Air-gap vault**: Manage air-gapped backup copies
4. **Recovery testing**: Run automated recovery drills

### Vault (Air-Gap Vault)
1. **Store**: Place critical assets in air-gapped storage
2. **Verify**: Continuous integrity verification
3. **Recover**: Tested recovery procedures with clean room validation

## Key Files
- `src/shieldops/agents/data_loss_prevention/` — DLP agent
- `src/shieldops/agents/data_classification/` — Classification agent
- `src/shieldops/agents/sensitive_data_monitor/` — Sensitive data agent
- `src/shieldops/agents/data_pipeline_security/` — Pipeline security agent
- `src/shieldops/agents/data_resilience/` — Data resilience agent
- `src/shieldops/agents/data_threat_hunting/` — Data threat hunting agent
- `src/shieldops/agents/air_gap_vault/` — Air-gap vault agent
- `src/shieldops/agents/data_intelligence/` — Data intelligence agent
- `src/shieldops/security/rag_pipeline_security.py` — RAG security engine
- `src/shieldops/security/model_provenance_tracker.py` — Model provenance
- `src/shieldops/compliance/pii_detector.py` — PII detection (SSN, CC, email, phone, AWS key, PHI)

## Conventions
- PII detection mandatory for all data egress paths
- Classification labels must propagate through data transformations
- DLP policies enforced at system boundaries (API, file transfer, MCP)
- AI pipeline audits required before deploying new RAG pipelines
- Backup integrity verified daily; recovery drills monthly
- Air-gap vault stores require multi-party authorization for access
