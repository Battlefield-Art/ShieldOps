# Run Forensics Skill

Execute digital forensics and recovery workflows — evidence collection, ransomware investigation, cyber recovery, and disaster recovery.

## Usage
`/run-forensics <action> [--incident <id>] [--target <host>] [--evidence <type>]`

Actions: `investigate`, `ransomware`, `recover`, `dr-test`, `evidence`, `timeline`, `status`

Evidence types: `memory_dump`, `disk_image`, `logs`, `network_capture`, `registry`, `browser_artifacts`

## Agents Used
- `forensics` — Digital forensics with chain of custody
- `ransomware_forensics` — Ransomware-specific investigation and recovery
- `cyber_recovery` — Agent-driven disaster recovery with clean room validation
- `disaster_recovery` — DR testing and failover readiness assessment
- `backup_validator` — Backup integrity validation and recovery testing
- `backup_security_posture` — Backup security posture assessment
- `log_analyzer` — AI-powered log anomaly detection and pattern analysis

## Process

### Investigate (Digital Forensics)
1. **Preserve evidence**: Capture memory, disk, logs with chain of custody
2. **Collect**: Gather artifacts from target systems
3. **Analyze**: Timeline reconstruction, artifact analysis, IOC extraction
4. **Correlate**: Cross-reference findings across multiple evidence sources
5. **Report**: Generate forensic report suitable for legal proceedings

```python
from shieldops.agents.forensics.runner import ForensicsRunner

runner = ForensicsRunner()
result = await runner.investigate(
    incident_id="INC-042",
    evidence_type="memory_dump",
    target_host="web-server-3",
    chain_of_custody=True,
    priority="high",
)
```

### Ransomware (Ransomware Investigation)
1. **Identify variant**: Determine ransomware family and version
2. **Map blast radius**: Identify all affected systems and data
3. **Check encryption**: Assess encryption status and recovery options
4. **Find patient zero**: Trace initial infection vector
5. **Recovery assessment**: Evaluate backup availability and integrity

```python
from shieldops.agents.ransomware_forensics.runner import RansomwareForensicsRunner

runner = RansomwareForensicsRunner()
result = await runner.investigate(
    incident_id="INC-RANSOM-001",
    affected_hosts=["file-server-1", "file-server-2", "dc-01"],
    first_detected="2026-03-26T08:00:00Z",
)
```

### Recover (Cyber Recovery)
1. **Validate clean state**: Clean room validation of recovery environment
2. **Select recovery point**: Choose last known clean backup
3. **Restore**: Execute orchestrated service restoration
4. **Verify integrity**: Confirm data integrity post-recovery
5. **Monitor**: Enhanced monitoring for re-infection

```python
from shieldops.agents.cyber_recovery.runner import CyberRecoveryRunner

runner = CyberRecoveryRunner()
result = await runner.recover(
    incident_id="INC-RANSOM-001",
    recovery_point="2026-03-25T00:00:00Z",
    clean_room_validation=True,
    services=["file-server", "database", "api"],
)
```

### DR Test (Disaster Recovery Testing)
1. **Select scenario**: Choose DR scenario (region failure, data center loss, etc.)
2. **Execute failover**: Run controlled failover to DR site
3. **Validate**: Confirm all services operational in DR mode
4. **Failback**: Return to primary site
5. **Report**: Generate DR test report with RTO/RPO measurements

```python
from shieldops.agents.disaster_recovery.runner import DisasterRecoveryRunner

runner = DisasterRecoveryRunner()
result = await runner.test(
    scenario="region_failure",
    target_region="us-east-1",
    dr_region="us-west-2",
    measure_rto_rpo=True,
)
```

### Evidence (Evidence Management)
1. **Collect**: Gather specified evidence types with cryptographic hashing
2. **Store**: Secure storage with chain of custody tracking
3. **Analyze**: Automated artifact analysis and IOC extraction
4. **Export**: Generate evidence package for legal or compliance

## Key Files
- `src/shieldops/agents/forensics/` — Digital forensics agent
- `src/shieldops/agents/ransomware_forensics/` — Ransomware forensics agent
- `src/shieldops/agents/cyber_recovery/` — Cyber recovery agent
- `src/shieldops/agents/disaster_recovery/` — DR agent
- `src/shieldops/agents/backup_validator/` — Backup validation agent
- `src/shieldops/agents/backup_security_posture/` — Backup security agent
- `src/shieldops/agents/log_analyzer/` — Log analysis agent
- `src/shieldops/incidents/blast_radius_containment_engine.py` — Blast radius
- `src/shieldops/incidents/recovery_verification_engine.py` — Recovery verification
- `src/shieldops/operations/disaster_recovery_intelligence.py` — DR intelligence
- `src/shieldops/operations/recovery_dependency_mapper.py` — Recovery dependencies

## Conventions
- All forensic evidence MUST maintain cryptographic chain of custody
- Memory dumps must be captured before any remediation actions
- Recovery points validated for integrity before restoration
- DR tests must measure and report actual RTO and RPO
- Ransomware investigations must identify patient zero and blast radius
- Clean room validation mandatory before declaring recovery complete
