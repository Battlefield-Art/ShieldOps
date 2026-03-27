# Run Agent Skill

Test-run a ShieldOps agent workflow locally with mock data.

## Usage
`/run-agent <agent-type> [--environment <env>] [--mock]`

**Core agents:** `investigation`, `remediation`, `security`, `learning`, `supervisor`, `cost`, `prediction`, `calibration`

**SOC & Incident Response:** `soc_analyst`, `soc_brain`, `ai_soc_assistant`, `soc_transformation`, `autonomous_soc`, `incident_response`, `incident_commander`, `incident_triage`, `ai_triage_accelerator`, `alert_correlation`, `anomaly_detector`, `situation_manager`, `situation_composer`

**Threat Intelligence & Hunting:** `threat_hunter`, `threat_intel`, `threat_intelligence_platform`, `managed_threat_hunting`, `data_threat_hunting`, `threat_modeling`, `threat_response`, `threat_automation`, `attack_campaign`, `attack_surface`

**Security Operations:** `xdr`, `autonomous_xdr`, `agentic_mdr`, `breakout_defender`, `soar_orchestration`, `soar_workflow`, `intelligent_soar`, `detection_engineering`, `deception`, `security_convergence`, `security_automation`, `adaptive_security`, `security_posture`, `security_testing`, `autonomous_defense`

**AI & Agent Security:** `agent_firewall`, `agent_governance`, `multi_agent_security`, `prompt_shield`, `model_security`, `ai_runtime_defense`, `ai_red_team`, `ai_blue_team`, `ai_compliance`, `digital_twin_security`, `ml_governance`, `agent_memory_store`, `reflection_engine`

**Identity & Access:** `nhi_registry`, `identity_graph`, `identity_protection`, `oauth_analyzer`, `service_account_tracker`, `credential_lifecycle`, `access_review`, `lateral_movement`, `itdr`

**Cloud & Infrastructure:** `cloud_posture`, `cnapp_analyzer`, `container_security`, `zero_trust_network`, `unified_cloud_security`, `cloud_risk_ranker`, `network_segmentation`, `zero_trust`, `iot_ot_security`

**Data Protection:** `data_loss_prevention`, `data_classification`, `sensitive_data_monitor`, `data_pipeline_security`, `data_resilience`, `data_intelligence`, `endpoint_dlp`, `air_gap_vault`

**Vulnerability & Code Security:** `vulnerability_manager`, `vulnerability_intelligence`, `code_security_scanner`, `supply_chain_security`, `supply_chain_scanner`, `secrets_scanner`, `file_integrity_monitor`, `exposure_management`, `api_security`

**Compliance & Governance:** `compliance_auditor`, `compliance_reporter`, `compliance_scanner`, `ai_compliance`, `config_validator`, `policy_engine`

**Forensics & Recovery:** `forensics`, `ransomware_forensics`, `cyber_recovery`, `disaster_recovery`, `backup_validator`, `backup_security_posture`

**Observability & OTel:** `observability_intelligence`, `otel_pipeline`, `otel_collector_manager`, `otel_deployer`, `otel_semantic`, `otel_tail_sampling`, `otel_metrics_pipeline`, `otel_logs_pipeline`, `telemetry_optimizer`, `log_analyzer`, `log_intelligence`, `performance_profiler`

**Operations & Automation:** `auto_remediation`, `runbook_automation`, `workflow_engine`, `automation_orchestrator`, `chaos_engineering`, `capacity_planner`, `sla_monitor`, `chatops`, `enterprise_integration`, `platform_intelligence`, `intelligent_automation`

**FinOps & Cost:** `cost`, `cost_anomaly`, `finops_intelligence`

**Risk & Scoring:** `risk_scoring`, `auto_learning`, `shadow_ai_discovery`

**GitOps & Changes:** `gitops`, `change_risk_analyzer`

**Connectors & Normalization:** `cross_vendor_correlator`, `vendor_normalizer`, `it_asset_intelligence`

**Specialized:** `dns_security`, `certificate_manager`, `malware_analyzer`, `insider_threat`, `security_app_builder`, `trust_relationship_mapper`

**Knowledge & Learning:** `knowledge`, `ai_runtime_guardian`

## Process

1. **Check agent runner exists**: Look in `src/shieldops/agents/{type}/runner.py`
2. **Create a test script** that:
   - Instantiates the runner with mock dependencies (no real DB/cloud needed)
   - Uses mock connectors, mock policy engine, mock repository
   - Provides realistic test input (alert context, remediation action, etc.)
   - Runs the agent workflow end-to-end
   - Prints results in structured format
3. **Run and validate**:
   - Execute the script with `python3 -m pytest` or direct invocation
   - Verify the agent graph executes all nodes
   - Check reasoning chain is populated
   - Validate output model is well-formed

## Agent Test Inputs

### Investigation
```python
alert_context = {"alert_id": "test-001", "alert_name": "High CPU", "severity": "warning", "environment": "staging", "resource_id": "web-server-1"}
```

### Remediation
```python
action = {"action_type": "restart_instance", "target_resource": "web-1", "environment": "staging", "risk_level": "low"}
```

### Security
```python
scan_config = {"scan_type": "full", "environment": "production", "targets": ["web-1"]}
```

### Learning
```python
learn_params = {"learning_type": "full", "period": "7d"}
```

### SOC Analyst
```python
alert_context = {"alert_id": "soc-001", "alert_name": "Suspicious Login", "severity": "high", "source": "SIEM", "environment": "production", "mitre_tactic": "Initial Access"}
```

### Threat Hunter
```python
hunt_params = {"hypothesis": "Lateral movement via RDP", "mitre_technique": "T1021.001", "hunt_type": "campaign", "scope": "production", "timeframe": "7d"}
```

### Forensics
```python
forensic_request = {"incident_id": "INC-042", "evidence_type": "memory_dump", "target_host": "web-server-3", "chain_of_custody": True, "priority": "high"}
```

### Deception
```python
deception_config = {"deployment_type": "honeypot", "target_network": "dmz", "emulate_service": "ssh", "alert_on_interaction": True, "profile_attacker": True}
```

### OTel Pipeline
```python
pipeline_config = {"cluster_name": "prod-us-east-1", "namespace": "default", "exporter_targets": ["otlp", "splunk_hec"]}
```

### Risk Scoring
```python
observations = [
    {"entity": "host-1", "entity_type": "host", "detection_name": "brute_force_login", "source": "siem", "raw_score": 0.7, "timestamp": 1710000000},
    {"entity": "host-1", "entity_type": "host", "detection_name": "lateral_movement_rdp", "source": "ndr", "raw_score": 0.8, "timestamp": 1710000300},
]
risk_config = {"observations": observations, "time_window_hours": 24, "autonomous_threshold": 0.85}
```

### Auto Learning
```python
learning_config = {"max_iterations": 10, "budget_seconds": 300, "budget_api_calls": 50}
```

### Security Automation
```python
alerts = [
    {"entity": "web-server-1", "composite_score": 0.88, "risk_level": "critical", "tactics_seen": ["initial_access", "execution", "persistence"]},
]
security_auto_config = {"alerts": alerts, "dry_run": True}
```

### GitOps
```python
gitops_config = {"repo_url": "https://github.com/org/infra-manifests", "branch": "main", "namespace": "production", "dry_run": True}
```

### Telemetry Optimizer
```python
optimizer_config = {"target_namespace": "production", "budget_seconds": 300}
```

### Threat Intel
```python
threat_intel_config = {"sources": ["osint", "commercial", "internal"], "distribution_channels": ["siem", "firewall"]}
```

### Incident Commander
```python
incident_config = {"alert_id": "INC-2847", "service": "payment-service", "environment": "production", "severity": "sev1", "description": "Payment service crash with OOMKilled pods"}
```

### Compliance Auditor
```python
compliance_config = {"frameworks": ["soc2", "pci_dss"], "scope": "production"}
```

### AI Runtime Defense
```python
runtime_config = {"agent_type": "remediation", "monitor_tool_calls": True, "detect_jailbreak": True, "environment": "production"}
```

### SOC Brain
```python
soc_brain_config = {"mode": "autonomous", "shift": "day", "alert_sources": ["splunk", "crowdstrike", "elastic"]}
```

### Identity Graph
```python
identity_config = {"scope": "all_providers", "providers": ["okta", "entra_id", "aws_iam"], "map_relationships": True}
```

### Agent Firewall
```python
firewall_config = {"agent_type": "remediation", "mode": "enforce", "blocked_actions": ["delete_database", "modify_iam_root"]}
```

### NHI Registry
```python
nhi_config = {"scope": "all_environments", "include_dormant": True, "risk_scoring": True}
```

### MCP Security
```python
mcp_config = {"discover_servers": True, "check_god_keys": True, "check_oauth": True}
```

### Cloud Posture
```python
cloud_config = {"providers": ["aws", "gcp"], "benchmark": "cis_v2", "auto_remediate": False}
```

### Container Security
```python
container_config = {"namespace": "production", "include_runtime": True, "generate_sbom": True}
```

### Data Loss Prevention
```python
dlp_config = {"channels": ["api", "email", "ai_pipeline", "mcp"], "policies": ["pii_no_export", "pci_restricted"]}
```

### Vulnerability Intelligence
```python
vuln_config = {"scan_types": ["sast", "sca", "iac"], "include_epss": True, "include_exploit_db": True}
```

### Ransomware Forensics
```python
ransomware_config = {"incident_id": "INC-RANSOM-001", "affected_hosts": ["file-server-1", "dc-01"], "first_detected": "2026-03-26T08:00:00Z"}
```

### Chaos Engineering
```python
chaos_config = {"fault_type": "pod_kill", "target_namespace": "staging", "blast_radius": "single_pod", "slo_guard": True, "auto_rollback": True, "duration": "5m"}
```

### Cost Anomaly
```python
cost_config = {"providers": ["aws", "gcp"], "sensitivity": "medium", "lookback": "7d"}
```

### SOAR Workflow
```python
soar_config = {"playbook": "phishing_response", "trigger_event": {"alert_id": "PHI-001", "type": "phishing", "severity": "high"}, "mode": "hybrid"}
```

### Autonomous XDR
```python
xdr_config = {"sources": ["edr", "siem", "cloud", "network", "identity"], "time_window": "1h", "detection_mode": "ml_and_rules"}
```

### Prompt Shield
```python
prompt_config = {"prompt": "test user input", "context": "agent_type=investigation", "detection_layers": ["regex", "semantic", "behavioral", "llm"]}
```

### AI Compliance
```python
ai_compliance_config = {"framework": "eu_ai_act", "ai_system": "shieldops_agents", "risk_category": "high"}
```

### Breakout Defender
```python
breakout_config = {"target_host": "compromised-host-1", "containment_actions": ["network_isolate", "process_kill", "credential_revoke"], "preserve_evidence": True}
```

### Disaster Recovery
```python
dr_config = {"scenario": "region_failure", "target_region": "us-east-1", "dr_region": "us-west-2", "measure_rto_rpo": True}
```

### SLA Monitor
```python
sla_config = {"services": ["api-server", "payment-service"], "slo_targets": {"availability": 0.999, "latency_p99_ms": 500}}
```

### Capacity Planner
```python
capacity_config = {"target_service": "api-server", "forecast_days": 90, "include_bottlenecks": True}
```

## Tips
- Set `ANTHROPIC_API_KEY` if you want real LLM calls (otherwise agents use mock/fallback)
- Use `--mock` flag to force mock mode for all external dependencies
- For domain-specific workflows, use dedicated skills: `/hunt-threats`, `/respond-incident`, `/manage-soc`, `/audit-compliance`, `/manage-identity`, `/secure-agents`, `/manage-cloud`, `/protect-data`, `/manage-vulns`, `/run-redteam`, `/orchestrate-soar`, `/run-xdr`, `/manage-costs`, `/run-forensics`, `/manage-mcp`
