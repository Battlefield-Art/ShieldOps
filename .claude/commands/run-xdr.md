# Run XDR Skill

Execute extended detection and response workflows — cross-source XDR, managed detection, breakout defense, and autonomous response.

## Usage
`/run-xdr <action> [--scope <environment>] [--sources <list>] [--mode <detect|respond|hunt>]`

Actions: `detect`, `respond`, `mdr`, `breakout`, `correlate`, `status`

## Agents Used
- `xdr` — Cross-source extended detection and response
- `autonomous_xdr` — Vendor-neutral XDR across any sensor
- `agentic_mdr` — Vendor-neutral managed detection and response with closed-loop learning
- `breakout_defender` — Sub-5-minute containment for active breaches
- `cross_vendor_correlator` — OCSF normalization across 8+ vendors
- `vendor_normalizer` — Vendor telemetry mapping and normalization

## Process

### Detect (Cross-Source Detection)
1. **Ingest telemetry**: Collect from EDR, SIEM, cloud, network, identity sources
2. **Normalize**: Convert to OCSF schema via `VendorNormalizer`
3. **Correlate**: Map related events across sources
4. **Detect**: Apply ML + rule-based detection across unified data
5. **Score**: Risk-score detections by entity, technique, and blast radius

```python
from shieldops.agents.autonomous_xdr.runner import AutonomousXDRRunner

runner = AutonomousXDRRunner(connectors={
    "crowdstrike": cs, "splunk": splunk, "elastic": elastic,
    "aws": aws, "azure": azure,
})
result = await runner.detect(
    sources=["edr", "siem", "cloud", "network", "identity"],
    time_window="1h",
    detection_mode="ml_and_rules",
)
```

### Respond (Automated Response)
1. **Assess threat**: Evaluate detection severity and confidence
2. **Select response**: Choose containment strategy based on threat type
3. **Execute**: Run automated response (isolate, block, kill, quarantine)
4. **Verify**: Confirm threat neutralization
5. **Report**: Generate response timeline

```python
result = await runner.respond(
    detection_id="XDR-4921",
    response_type="contain",
    auto_approve=False,  # Require human approval for production
)
```

### MDR (Managed Detection and Response)
1. **24/7 monitoring**: Autonomous monitoring with Claude-powered analysis
2. **Threat hunting**: Proactive hunting across all data sources
3. **Incident management**: Full incident lifecycle management
4. **Closed-loop learning**: Feed outcomes back into detection improvement

```python
from shieldops.agents.agentic_mdr.runner import AgenticMDRRunner

runner = AgenticMDRRunner()
result = await runner.monitor(
    scope="production",
    hunting_enabled=True,
    learning_enabled=True,
)
```

### Breakout (Active Breach Containment)
1. **Detect breakout**: Identify active lateral movement
2. **Contain immediately**: Sub-5-minute automated containment
3. **Isolate**: Network-level and host-level isolation
4. **Preserve evidence**: Snapshot state before containment actions

```python
from shieldops.agents.breakout_defender.runner import BreakoutDefenderRunner

runner = BreakoutDefenderRunner()
result = await runner.contain(
    target_host="compromised-host-1",
    containment_actions=["network_isolate", "process_kill", "credential_revoke"],
    preserve_evidence=True,
)
```

## Key Files
- `src/shieldops/agents/xdr/` — XDR agent
- `src/shieldops/agents/autonomous_xdr/` — Autonomous XDR agent
- `src/shieldops/agents/agentic_mdr/` — Managed detection agent
- `src/shieldops/agents/breakout_defender/` — Breakout containment agent
- `src/shieldops/agents/cross_vendor_correlator/` — Vendor correlation agent
- `src/shieldops/agents/vendor_normalizer/` — Vendor normalization agent
- `src/shieldops/connectors/crowdstrike/` — CrowdStrike Falcon connector
- `src/shieldops/connectors/defender/` — Microsoft Defender connector
- `src/shieldops/connectors/wiz/` — Wiz connector
- `src/shieldops/security/cross_domain_threat_fusion.py` — Threat fusion
- `src/shieldops/security/runtime_threat_analyzer.py` — Runtime analysis

## Conventions
- XDR detections normalized to OCSF schema before correlation
- Breakout containment must execute within 5 minutes of detection
- Autonomous response requires confidence >0.85 in production
- All response actions logged to immutable audit trail
- MDR closed-loop learning updates detection models weekly
- Vendor-neutral: must work with any combination of EDR/SIEM/cloud sensors
