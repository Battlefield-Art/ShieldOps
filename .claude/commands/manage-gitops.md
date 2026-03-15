# Manage GitOps Skill

Manage GitOps reconciliation — detect drift, plan changes, apply reconciliation, verify deployments.

## Usage
`/manage-gitops <action> [options]`

Actions: `detect-drift`, `reconcile`, `verify`, `history`

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

### Key Files
- `src/shieldops/agents/gitops/` — GitOps LangGraph agent
- `src/shieldops/changes/gitops_reconciliation_engine.py` — GitOps reconciliation analytics
- `src/shieldops/changes/` — Change management engines (68+ modules)

## Conventions
- Always dry-run before applying changes
- High-risk changes (DELETE, security policy changes) require human approval
- All changes are audited via the audit trail
- Rollback is always available for applied changes
- Follow conventional commits for change tracking
