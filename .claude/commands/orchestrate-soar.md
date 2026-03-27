# Orchestrate SOAR Skill

Manage SOAR workflows — playbook orchestration, automated response, runbook execution, and workflow intelligence.

## Usage
`/orchestrate-soar <action> [--playbook <name>] [--trigger <event>] [--mode <auto|manual|hybrid>]`

Actions: `run`, `create`, `list`, `test`, `automate`, `status`

## Agents Used
- `soar_orchestration` — SOAR workflow orchestration with policy gates
- `soar_workflow` — Intake → enrich → contain → eradicate → recover pipeline
- `intelligent_soar` — LangGraph-native adaptive playbooks
- `runbook_automation` — SRE runbook execution with approval workflows and rollback
- `workflow_engine` — General workflow orchestration engine
- `automation_orchestrator` — Multi-agent automation chaining with policy gates

## Process

### Run (Execute Playbook)
1. **Select playbook**: Choose from available SOAR playbooks
2. **Validate inputs**: Check required parameters and permissions
3. **Execute**: Run playbook through SOAR pipeline (intake → enrich → contain → eradicate → recover)
4. **Monitor**: Track execution status, actions taken, approvals needed
5. **Report**: Generate execution report with timeline

```python
from shieldops.agents.soar_workflow.runner import SOARWorkflowRunner

runner = SOARWorkflowRunner()
result = await runner.execute(
    playbook="phishing_response",
    trigger_event={"alert_id": "PHI-001", "type": "phishing", "severity": "high"},
    mode="hybrid",  # auto for low-risk steps, approval for high-risk
)
```

### Create (Author Playbook)
1. **Define trigger**: Specify event type and conditions
2. **Design steps**: Build sequential/parallel workflow steps
3. **Add gates**: Insert OPA policy checks and approval points
4. **Test**: Validate with dry-run mode
5. **Deploy**: Register playbook in SOAR engine

```python
from shieldops.agents.intelligent_soar.runner import IntelligentSOARRunner

runner = IntelligentSOARRunner()
result = await runner.create_playbook(
    name="ransomware_containment",
    trigger={"type": "ransomware", "severity": "critical"},
    steps=[
        {"action": "isolate_host", "approval": "auto"},
        {"action": "snapshot_disk", "approval": "auto"},
        {"action": "kill_processes", "approval": "manual"},
        {"action": "restore_from_backup", "approval": "manual"},
    ],
)
```

### Automate (Runbook Automation)
1. **Select runbook**: Choose operational runbook
2. **Set triggers**: Define automation trigger conditions
3. **Configure approval**: Set approval workflow (auto/manual/hybrid)
4. **Enable rollback**: Configure automatic rollback on failure
5. **Activate**: Enable runbook automation

```python
from shieldops.agents.runbook_automation.runner import RunbookAutomationRunner

runner = RunbookAutomationRunner()
result = await runner.automate(
    runbook="scale_deployment",
    trigger={"metric": "cpu_utilization", "threshold": 0.85, "duration": "5m"},
    approval="auto",
    rollback_on_failure=True,
)
```

### Test (Playbook Validation)
1. **Dry run**: Execute playbook in simulation mode
2. **Validate steps**: Verify each step has required permissions and tools
3. **Check policies**: Confirm OPA policies allow all actions
4. **Report**: Generate test results with pass/fail per step

## Key Files
- `src/shieldops/agents/soar_orchestration/` — SOAR orchestration agent
- `src/shieldops/agents/soar_workflow/` — SOAR workflow agent
- `src/shieldops/agents/intelligent_soar/` — Adaptive SOAR agent
- `src/shieldops/agents/runbook_automation/` — Runbook automation agent
- `src/shieldops/agents/workflow_engine/` — Workflow engine agent
- `src/shieldops/agents/automation_orchestrator/` — Automation orchestrator agent
- `src/shieldops/playbooks/` — YAML playbook definitions
- `src/shieldops/security/soar_workflow_intelligence.py` — SOAR intelligence
- `src/shieldops/operations/workflow_intelligence_engine.py` — Workflow intelligence

## Conventions
- All SOAR playbooks must have rollback capability for every action
- High-risk actions (containment, eradication) require OPA policy approval
- Playbook execution must be fully auditable (every step logged)
- Automation mode requires confidence >0.85 for autonomous execution
- Runbooks must be tested in staging before production activation
- Maximum parallel step count limited to prevent resource exhaustion
