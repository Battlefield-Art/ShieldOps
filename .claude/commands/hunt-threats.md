# Hunt Threats Skill

Run proactive threat hunting workflows across enterprise infrastructure using ShieldOps threat agents.

## Usage
`/hunt-threats <action> [--scope <environment>] [--technique <mitre-id>] [--timeframe <duration>]`

Actions: `hunt`, `intel`, `campaign`, `ioc-sweep`, `status`

## Agents Used
- `threat_hunter` — Hypothesis-driven threat hunting with MITRE ATT&CK mapping
- `threat_intel` — Multi-source threat intelligence aggregation and distribution
- `threat_intelligence_platform` — Full TIP with digital risk protection
- `managed_threat_hunting` — Autonomous 24/7 hunting without human dependency
- `data_threat_hunting` — LLM threat hunting in backups, production, and AI pipelines
- `threat_modeling` — STRIDE analysis and attack path modeling
- `threat_response` — Automated threat response and containment
- `attack_campaign` — Attack campaign orchestration and adversarial scenario generation

## Process

### Hunt (Hypothesis-Driven)
1. **Define hypothesis**: Specify MITRE technique, threat actor, or behavioral pattern
2. **Scope environment**: Select target infrastructure (cloud, on-prem, hybrid)
3. **Run hunter agent**: Execute `ThreatHunterRunner.hunt()` with hypothesis params
4. **Analyze findings**: Review discovered IOCs, TTPs, anomalies
5. **Escalate or close**: Route confirmed threats to incident response

```python
from shieldops.agents.threat_hunter.runner import ThreatHunterRunner

runner = ThreatHunterRunner(connectors={"splunk": splunk, "elastic": elastic})
result = await runner.hunt(
    hypothesis="Lateral movement via RDP from compromised workstation",
    mitre_technique="T1021.001",
    scope="production",
    timeframe="7d",
)
```

### Intel (Threat Intelligence)
1. **Aggregate sources**: Pull from OSINT, commercial, internal feeds
2. **Normalize IOCs**: Convert to STIX/TAXII format
3. **Enrich context**: Add MITRE ATT&CK mapping, risk scoring
4. **Distribute**: Push to SIEM, firewall, EDR via connectors

```python
from shieldops.agents.threat_intel.runner import ThreatIntelRunner

runner = ThreatIntelRunner()
result = await runner.collect(
    sources=["osint", "commercial", "internal"],
    distribution_channels=["siem", "firewall", "edr"],
)
```

### Campaign (Attack Campaign Analysis)
1. **Ingest indicators**: Collect related IOCs and TTPs
2. **Correlate activity**: Map to kill chain stages
3. **Reconstruct narrative**: Build attack timeline
4. **Generate report**: Produce campaign intelligence report

```python
from shieldops.agents.attack_campaign.runner import AttackCampaignRunner

runner = AttackCampaignRunner()
result = await runner.analyze(
    campaign_name="APT-suspected-lateral",
    indicators=["ip:10.0.0.55", "hash:abc123", "domain:evil.example.com"],
    timeframe="30d",
)
```

## Key Files
- `src/shieldops/agents/threat_hunter/` — Hypothesis-driven hunting agent
- `src/shieldops/agents/threat_intel/` — Threat intelligence agent
- `src/shieldops/agents/threat_intelligence_platform/` — Full TIP agent
- `src/shieldops/agents/managed_threat_hunting/` — Autonomous hunting agent
- `src/shieldops/agents/data_threat_hunting/` — Data-layer hunting agent
- `src/shieldops/agents/threat_modeling/` — STRIDE threat modeling agent
- `src/shieldops/agents/attack_campaign/` — Campaign analysis agent
- `src/shieldops/security/threat_prediction_engine.py` — Threat prediction
- `src/shieldops/security/adversary_emulation_engine.py` — Adversary emulation
- `src/shieldops/security/cross_domain_threat_fusion.py` — Cross-domain fusion
- `src/shieldops/security/attack_narrative_engine.py` — Attack narratives
- `src/shieldops/security/mitre_risk_mapper_engine.py` — MITRE ATT&CK mapping

## Conventions
- All hunts MUST log hypothesis, scope, findings, and outcome to audit trail
- Use MITRE ATT&CK technique IDs for all TTP references
- Threat intel IOCs must be normalized to STIX format before distribution
- Hunting timeframes default to 7d if not specified
- Autonomous hunting requires confidence >0.85 for automated containment
