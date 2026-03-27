# Manage SOC Skill

Operate and manage Security Operations Center workflows — alert triage, analyst assist, SOC transformation, and autonomous operations.

## Usage
`/manage-soc <action> [--mode <autonomous|assisted>] [--shift <day|night|weekend>]`

Actions: `analyze`, `correlate`, `transform`, `automate`, `assist`, `status`

## Agents Used
- `soc_analyst` — Alert investigation and response recommendations
- `soc_brain` — Central SOC intelligence and decision orchestration
- `ai_soc_assistant` — Open AI SOC assistant with Claude (cross-vendor)
- `soc_transformation` — Agent-driven SIEM migration and SOC modernization
- `autonomous_soc` — Open AI-native SOC with existing SIEM integration
- `alert_correlation` — Multi-source alert correlation and deduplication
- `anomaly_detector` — Behavioral anomaly detection across telemetry
- `situation_manager` — Outcome-centric event queue management

## Process

### Analyze (SOC Analyst Assist)
1. **Ingest alert**: Pull alert context from SIEM connector (Splunk/Elastic)
2. **Enrich**: Add asset context, threat intel, historical patterns
3. **Analyze**: Run `SOCAnalystRunner` for investigation recommendations
4. **Recommend**: Provide analyst with prioritized actions and playbook suggestions

```python
from shieldops.agents.soc_analyst.runner import SOCAnalystRunner

runner = SOCAnalystRunner(connectors={"splunk": splunk, "elastic": elastic})
result = await runner.analyze(
    alert_id="soc-001",
    alert_name="Suspicious Login",
    severity="high",
    source="SIEM",
    environment="production",
    mitre_tactic="Initial Access",
)
```

### Correlate (Alert Correlation)
1. **Collect alerts**: Aggregate from all sources (SIEM, EDR, cloud, network)
2. **Deduplicate**: Remove noise and duplicate alerts
3. **Correlate**: Map related alerts to attack chains
4. **Compose situation**: Build narrative via `SituationComposer`

```python
from shieldops.agents.alert_correlation.runner import AlertCorrelationRunner

runner = AlertCorrelationRunner()
result = await runner.correlate(
    alerts=alert_batch,
    time_window="1h",
    correlation_rules=["kill_chain", "entity", "temporal"],
)
```

### Transform (SOC Modernization)
1. **Assess current state**: Evaluate existing SOC tooling, processes, staffing
2. **Plan migration**: Generate SIEM migration plan (Splunk → ShieldOps, QRadar → ShieldOps)
3. **Automate**: Identify manual processes for agent automation
4. **Measure**: Track MTTD, MTTR, analyst productivity metrics

### Automate (Autonomous SOC)
1. **Configure automation rules**: Define auto-response thresholds
2. **Deploy autonomous agents**: Enable 24/7 autonomous monitoring
3. **Set guardrails**: OPA policies for autonomous actions
4. **Monitor effectiveness**: Track false positive rate, response time

## Key Files
- `src/shieldops/agents/soc_analyst/` — SOC analyst agent
- `src/shieldops/agents/soc_brain/` — SOC intelligence agent
- `src/shieldops/agents/ai_soc_assistant/` — AI assistant agent
- `src/shieldops/agents/soc_transformation/` — SOC modernization agent
- `src/shieldops/agents/autonomous_soc/` — Autonomous SOC agent
- `src/shieldops/agents/alert_correlation/` — Alert correlation agent
- `src/shieldops/agents/anomaly_detector/` — Anomaly detection agent
- `src/shieldops/agents/situation_manager/` — Situation management agent
- `src/shieldops/security/automated_incident_classifier.py` — Incident classification
- `src/shieldops/observability/alert_correlation_cascade_engine.py` — Cascade correlation
- `src/shieldops/observability/alert_dedup_intelligence.py` — Deduplication
- `src/shieldops/analytics/alert_lifecycle_intelligence.py` — Alert lifecycle

## Conventions
- Autonomous actions require confidence >0.85, otherwise escalate to analyst
- All alert dispositions must be logged for SOC metrics (MTTD, MTTR)
- Correlation windows default to 1 hour unless specified
- SOC transformations must include rollback plan and parallel-run period
- Use OCSF schema for vendor-neutral alert normalization
