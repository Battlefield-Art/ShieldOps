# Manage GitOps Skill

Manage GitOps reconciliation — detect drift, plan changes, apply reconciliation, verify deployments, and track change risk.

## Usage
`/manage-gitops <action> [--repo <url>] [--namespace <ns>] [--dry-run]`

Actions: `detect-drift`, `reconcile`, `verify`, `risk-assess`, `history`, `status`

## Agents Used
- `gitops` — GitOps drift detection and reconciliation
- `change_risk_analyzer` — Deployment risk scoring and blast radius prediction
- `config_validator` — Configuration baseline compliance checking

## Process

### Detect Drift
1. **Compare desired state** (git repo) vs **actual state** (infrastructure)
2. **Categorize drift**: config, resource, policy, secret, version
3. **Assess severity**: critical (security drift), high (config drift), medium (version drift)
4. **Generate report** with drift items and recommended actions

```python
from shieldops.agents.gitops.runner import GitOpsRunner

runner = GitOpsRunner()
result = await runner.run(
    repo_url="https://github.com/org/infra-manifests",
    branch="main",
    namespace="production",
    dry_run=True,
)
```

### Reconcile
1. **Generate plan** from detected drift items
2. **Assess risk** of each reconciliation action
3. **Check approval requirements** (high-risk changes need human approval)
4. **Apply changes** (dry-run by default, always)
5. **Verify** changes were applied correctly

### Risk Assess (Change Risk Scoring)
1. **Score deployment risk**: Analyze change complexity, blast radius, time of day
2. **Predict impact**: Estimate failure probability and affected services
3. **Recommend**: Suggest deployment strategy (canary, blue-green, rolling)

```python
from shieldops.agents.change_risk_analyzer.runner import ChangeRiskAnalyzerRunner

runner = ChangeRiskAnalyzerRunner()
result = await runner.assess(
    change_type="deployment",
    target_service="api-server",
    environment="production",
    changes=["image_update", "config_change"],
)
```

### Verify
1. **Post-deploy checks**: Validate service health after reconciliation
2. **SLO impact**: Check if changes affected SLO compliance
3. **Rollback readiness**: Confirm rollback path is viable

## Key Files
- `src/shieldops/agents/gitops/` — GitOps LangGraph agent
- `src/shieldops/agents/change_risk_analyzer/` — Change risk agent
- `src/shieldops/agents/config_validator/` — Config validation agent
- `src/shieldops/changes/` — 66 change management engines
- `src/shieldops/changes/gitops_reconciliation_engine.py` — GitOps reconciliation
- `src/shieldops/changes/iac_validation_engine.py` — IaC validation
- `src/shieldops/changes/deployment_intelligence_engine.py` — Deployment intelligence
- `src/shieldops/changes/deployment_reliability_impact_engine.py` — Reliability impact
- `src/shieldops/changes/service_readiness_engine.py` — Service readiness

## Conventions
- Always dry-run before applying changes
- High-risk changes (DELETE, security policy changes) require human approval
- All changes are audited via the audit trail
- Rollback is always available for applied changes
- Follow conventional commits for change tracking
- Drift detection runs continuously; critical drift alerts within 5 minutes
