# Run Red Team Skill

Execute adversarial testing — red team exercises, blue team validation, chaos engineering, detection testing, and security validation.

## Usage
`/run-redteam <action> [--target <agent|infra|model>] [--technique <mitre-id>] [--safe-mode]`

Actions: `attack`, `defend`, `chaos`, `detect`, `validate`, `purple`, `status`

## Agents Used
- `ai_red_team` — Adversarial testing of AI agent behaviors and boundaries
- `ai_blue_team` — Defensive monitoring and hardening of AI agents
- `adversarial_validation` — Closed-loop adversarial data flywheel
- `chaos_engineering` — Chaos experiments with safety gates and auto-rollback
- `detection_engineering` — Detection rule lifecycle and MITRE coverage
- `security_testing` — Vulnerability prioritization and credential hygiene testing
- `deception` — Honeypot deployment and attacker profiling
- `digital_twin_security` — Pre-deployment attack simulation via digital twins

## Process

### Attack (Red Team Exercise)
1. **Define scope**: Target agents, infrastructure, or models
2. **Select techniques**: Choose MITRE ATT&CK techniques to simulate
3. **Execute**: Run controlled attack simulations
4. **Document**: Record findings, successful paths, defense gaps

```python
from shieldops.agents.ai_red_team.runner import AIRedTeamRunner

runner = AIRedTeamRunner()
result = await runner.exercise(
    target="remediation_agent",
    techniques=["prompt_injection", "privilege_escalation", "data_exfiltration"],
    scope="staging",
    safe_mode=True,
)
```

### Defend (Blue Team Validation)
1. **Monitor**: Validate detection coverage against red team activities
2. **Harden**: Apply defensive measures based on findings
3. **Tune**: Adjust detection thresholds and alert rules
4. **Report**: Generate defense posture report

```python
from shieldops.agents.ai_blue_team.runner import AIBlueTeamRunner

runner = AIBlueTeamRunner()
result = await runner.validate(
    red_team_report=red_team_findings,
    check_detection_coverage=True,
    check_response_time=True,
)
```

### Chaos (Chaos Engineering)
1. **Define experiment**: Specify fault type, target, blast radius
2. **Safety gates**: Verify OPA policy, SLO guard, auto-rollback
3. **Inject fault**: Execute controlled failure injection
4. **Observe**: Monitor system behavior under stress
5. **Report**: Document resilience findings

```python
from shieldops.agents.chaos_engineering.runner import ChaosEngineeringRunner

runner = ChaosEngineeringRunner()
result = await runner.experiment(
    fault_type="pod_kill",
    target_namespace="staging",
    blast_radius="single_pod",
    slo_guard=True,
    auto_rollback=True,
    duration="5m",
)
```

### Detect (Detection Engineering)
1. **Assess coverage**: Map current detections to MITRE ATT&CK matrix
2. **Identify gaps**: Find techniques without detection rules
3. **Author rules**: Generate detection rules for gaps
4. **Test**: Validate rules against historical and simulated data

### Validate (Adversarial Validation)
1. **Run scenarios**: Execute adversarial scenarios against security controls
2. **Measure**: Track control effectiveness and bypass rates
3. **Learn**: Feed results back into agent training (closed-loop flywheel)
4. **Improve**: Update controls based on validation findings

### Purple (Purple Team Campaign)
1. **Combine red + blue**: Coordinate attack and defense simultaneously
2. **Real-time feedback**: Defenders observe attack in progress
3. **Collaborative**: Joint improvement of detection and response
4. **Campaign report**: Unified findings with attack paths and defense gaps

## Key Files
- `src/shieldops/agents/ai_red_team/` — AI red team agent
- `src/shieldops/agents/ai_blue_team/` — AI blue team agent
- `src/shieldops/agents/adversarial_validation/` — Adversarial validation agent
- `src/shieldops/agents/chaos_engineering/` — Chaos engineering agent
- `src/shieldops/agents/detection_engineering/` — Detection engineering agent
- `src/shieldops/agents/security_testing/` — Security testing agent
- `src/shieldops/agents/deception/` — Deception/honeypot agent
- `src/shieldops/agents/digital_twin_security/` — Digital twin simulation agent
- `src/shieldops/security/purple_team_campaign_engine.py` — Purple team engine
- `src/shieldops/security/adversary_emulation_engine.py` — Adversary emulation
- `src/shieldops/security/detection_engineering_pipeline_v2.py` — Detection pipeline
- `src/shieldops/operations/chaos_experiment_tracker.py` — Chaos tracking

## Conventions
- Red team exercises MUST use safe_mode in production (no destructive actions)
- Chaos experiments limited to blast_radius=single_pod in production
- All adversarial findings require responsible disclosure timeline
- Detection rules must be tested against both benign and malicious data
- Purple team campaigns require both red and blue team sign-off
- Chaos experiments require OPA policy check + SLO guard + auto-rollback
