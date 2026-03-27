# Create Playbook Skill

Create a new remediation playbook for ShieldOps agents.

## Usage
`/create-playbook <name> [--trigger <alert-type>] [--risk-level <level>] [--type <remediation|investigation|compliance>]`

## Agents Used
- `soar_workflow` — SOAR workflow orchestration (intake → enrich → contain → eradicate → recover)
- `intelligent_soar` — LangGraph-native adaptive playbooks
- `runbook_automation` — SRE runbook execution with approval workflows

## Process

1. **Identify the incident type**: What alert/condition triggers this playbook?
2. **Define investigation steps**: What data should the agent gather?
3. **Design decision tree**: What conditions map to which remediation actions?
4. **Specify remediation actions**: What does the agent do for each condition?
5. **Add OPA policy gates**: What approval/policy checks are required?
6. **Define validation checks**: How do we confirm the fix worked?
7. **Set failure handling**: What happens if remediation fails?
8. **Register playbook**: Add to runbook recommender for auto-suggestion

## Playbook YAML Structure
```yaml
name: playbook-name
version: "1.0"
description: "What this playbook handles"
trigger:
  alert_type: "AlertName"
  severity: ["critical", "warning"]

investigation:
  steps:
    - name: step_name
      action: query_type  # query_logs, query_metrics, query_k8s, query_health
      query: "query string"
      extract: [fields]

remediation:
  decision_tree:
    - condition: "condition expression"
      action: action_name
      risk_level: low|medium|high|critical
      params: {}
      approval: auto|manual  # manual for high/critical risk

validation:
  checks:
    - name: check_name
      query: "validation query"
      expected: "expected result"
      timeout_seconds: 300

  on_failure:
    action: rollback_and_escalate
    escalation_channel: "#sre-oncall"
```

## Registration

```python
from shieldops.playbooks.runbook_recommender import RunbookRecommender

recommender = RunbookRecommender()
recommender.register_runbook(
    name="oomkilled-remediation",
    trigger_patterns=["OOMKilled", "memory_pressure", "container_restart"],
    playbook_path="playbooks/oomkilled-remediation.yaml",
)
```

## Key Files
- `playbooks/` — YAML playbook definitions
- `src/shieldops/playbooks/runbook_recommender.py` — Runbook auto-suggestion engine
- `src/shieldops/agents/soar_workflow/` — SOAR workflow agent
- `src/shieldops/agents/intelligent_soar/` — Adaptive SOAR agent
- `src/shieldops/agents/runbook_automation/` — Runbook automation agent
- `src/shieldops/security/soar_workflow_intelligence.py` — SOAR intelligence engine
- `src/shieldops/policy/approval_workflow.py` — Approval gate integration

## Conventions
- Save playbooks to `playbooks/{name}.yaml`
- Every remediation action MUST have a corresponding rollback action
- High-risk actions (risk_level: high|critical) require `approval: manual`
- All playbook executions logged to immutable audit trail
- Test playbooks in dry-run mode before production activation
- Register playbooks with RunbookRecommender for auto-suggestion
