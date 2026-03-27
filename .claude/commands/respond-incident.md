# Respond Incident Skill

Manage incident response lifecycle — from triage through containment, eradication, recovery, and post-incident review.

## Usage
`/respond-incident <action> [--incident <id>] [--severity <sev1-4>] [--playbook <name>]`

Actions: `triage`, `contain`, `eradicate`, `recover`, `review`, `command`, `forensics`, `status`

## Agents Used
- `incident_response` — Full incident lifecycle (intake → contain → eradicate → recover)
- `incident_commander` — Sev1/Sev2 command and coordination
- `incident_triage` — Automated classification and routing
- `ai_triage_accelerator` — 10x faster Claude-powered triage
- `forensics` — Digital forensics with chain of custody
- `ransomware_forensics` — Ransomware-specific investigation and recovery
- `cyber_recovery` — Agent-driven disaster recovery with clean room validation
- `disaster_recovery` — DR testing and failover readiness
- `situation_composer` — Alert narrative composition and kill chain reconstruction

## Process

### Triage
1. **Classify**: Run `AITriageAcceleratorRunner.triage()` for rapid classification
2. **Score severity**: Auto-assign sev1-4 based on blast radius, data sensitivity, business impact
3. **Route**: Assign to appropriate response team or escalate to incident commander
4. **Enrich**: Pull context from SIEM, asset inventory, threat intel

```python
from shieldops.agents.ai_triage_accelerator.runner import AITriageAcceleratorRunner

runner = AITriageAcceleratorRunner()
result = await runner.triage(
    alert_id="ALT-29471",
    source="crowdstrike",
    severity="high",
    description="Suspicious PowerShell execution on finance-server-3",
)
```

### Command (Incident Commander)
1. **Activate**: Spin up incident commander for sev1/sev2
2. **Coordinate**: Assign roles (IC, comms, ops, security)
3. **Track**: Maintain timeline, actions, decisions
4. **Communicate**: Push status to Slack, PagerDuty, StatusPage

```python
from shieldops.agents.incident_commander.runner import IncidentCommanderRunner

runner = IncidentCommanderRunner()
result = await runner.command(
    incident_id="INC-2847",
    service="payment-service",
    environment="production",
    severity="sev1",
    description="Payment service crash with OOMKilled pods",
)
```

### Forensics
1. **Collect evidence**: Memory dumps, disk images, logs, network captures
2. **Chain of custody**: Maintain cryptographic evidence integrity
3. **Analyze**: Timeline reconstruction, artifact analysis, IOC extraction
4. **Report**: Generate forensic report with findings and recommendations

```python
from shieldops.agents.forensics.runner import ForensicsRunner

runner = ForensicsRunner()
result = await runner.investigate(
    incident_id="INC-042",
    evidence_type="memory_dump",
    target_host="web-server-3",
    chain_of_custody=True,
)
```

### Recovery
1. **Validate clean state**: Run `CyberRecoveryRunner` clean room validation
2. **Restore services**: Orchestrate service restoration per priority
3. **Verify integrity**: Confirm data integrity and service health
4. **Monitor**: Enhanced monitoring for recurrence detection

## Key Files
- `src/shieldops/agents/incident_response/` — Full lifecycle agent
- `src/shieldops/agents/incident_commander/` — Command coordination agent
- `src/shieldops/agents/incident_triage/` — Classification agent
- `src/shieldops/agents/ai_triage_accelerator/` — Fast triage agent
- `src/shieldops/agents/forensics/` — Digital forensics agent
- `src/shieldops/agents/ransomware_forensics/` — Ransomware forensics agent
- `src/shieldops/agents/cyber_recovery/` — Cyber recovery agent
- `src/shieldops/agents/disaster_recovery/` — DR agent
- `src/shieldops/agents/situation_composer/` — Narrative composition agent
- `src/shieldops/incidents/` — Incident engines (triage, escalation, postmortem, cost attribution)
- `src/shieldops/operations/autonomous_incident_commander.py` — Autonomous IC engine

## Conventions
- Sev1 incidents MUST activate incident commander within 5 minutes
- All forensic evidence requires chain of custody tracking
- Containment actions require OPA policy approval for production environments
- Post-incident reviews mandatory for sev1/sev2 within 48 hours
- Recovery must include integrity verification before declaring resolved
