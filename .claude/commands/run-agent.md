# Run Agent Skill

Test-run a ShieldOps agent workflow locally with mock data.

## Usage
`/run-agent <agent-type> [--environment <env>] [--mock]`

Agent types: `investigation`, `remediation`, `security`, `cost`, `learning`, `supervisor`, `soc_analyst`, `threat_hunter`, `forensics`, `deception`, `incident_response`, `attack_surface`, `ml_governance`, `finops_intelligence`, `zero_trust`, `threat_automation`, `soar_orchestration`, `itdr`, `auto_remediation`, `observability_intelligence`, `xdr`, `intelligent_automation`, `platform_intelligence`, `security_convergence`, `autonomous_defense`, `otel_pipeline`, `risk_scoring`, `auto_learning`, `security_automation`, `gitops`, `telemetry_optimizer`, `threat_intel`, `incident_commander`, `compliance_auditor`, `otel_collector_manager`, `adaptive_security`, `otel_deployer`, `security_posture`, `otel_semantic`, `soar_workflow`, `otel_tail_sampling`, `detection_engineering`, `otel_metrics_pipeline`, `security_testing`, `otel_logs_pipeline`, `threat_modeling`

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

## Tips
- Set `ANTHROPIC_API_KEY` if you want real LLM calls (otherwise agents use mock/fallback)
- Use `--mock` flag to force mock mode for all external dependencies
