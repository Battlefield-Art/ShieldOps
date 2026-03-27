# Deploy Agent Skill

Deploy ShieldOps agents to target environments with pre-flight checks, risk assessment, and rollback capability.

## Usage
`/deploy-agent <environment> [--agent <type>] [--dry-run] [--skip-tests]`

## Environments
- `dev` — Local/dev Kubernetes cluster
- `staging` — Staging environment (shadow mode by default)
- `production` — Production (requires approval workflow)

## Agents Used
- `change_risk_analyzer` — Deployment risk scoring and blast radius prediction
- `config_validator` — Configuration baseline compliance checking
- `gitops` — GitOps drift detection and reconciliation
- `sla_monitor` — SLO burn rate prediction for deployment impact

## Process

### 1. Pre-Flight Checks
- Run full test suite: `pytest tests/ -v`
- Security scan: `ruff check` + bandit + dependency audit
- Verify OPA policies loaded for target environment
- Verify configuration parity across environments

### 2. Build Artifacts
- Build Docker image: `docker build -t shieldops-agent:{version}`
- Push to container registry
- Generate SBOM for the image

### 3. Risk Assessment
Run automated risk scoring before deploying:

```python
from shieldops.agents.change_risk_analyzer.runner import ChangeRiskAnalyzerRunner

runner = ChangeRiskAnalyzerRunner()
result = await runner.assess(
    change_type="agent_deployment",
    target_service="soc-analyst-agent",
    environment="production",
    changes=["image_update", "config_change"],
)
# result.risk_score < 0.5: auto-approve
# result.risk_score 0.5-0.85: require human approval
# result.risk_score > 0.85: block deployment
```

**Risk checks include:**
- Deployment risk scoring (blast radius, complexity, time-of-day)
- SLO burn rate prediction (will this exhaust error budget?)
- Service dependency impact analysis
- Certificate expiry verification
- Container image vulnerability scan
- Change conflict detection
- Cascade failure prediction

### 4. Deploy
- **Dev**: Direct kubectl apply
- **Staging**: Rolling deployment with canary analysis
- **Production**: Blue-green or canary with approval gate

```python
# Canary analysis
from shieldops.changes.canary_analyzer import DeploymentCanaryAnalyzer

analyzer = DeploymentCanaryAnalyzer()
analyzer.record_item(
    deployment_id="deploy-142", canary_pct=10,
    error_rate_canary=0.001, error_rate_baseline=0.001,
    latency_p99_canary=120, latency_p99_baseline=115,
)
report = analyzer.generate_report()
```

### 5. Post-Deploy Verification
- Validate service health via health endpoints
- Check SLO compliance post-deployment
- Monitor error rates for 15 minutes
- Confirm rollback path is viable
- Record deployment event for DORA metrics

### 6. Rollback (if needed)
- Automatic rollback triggers: error rate >5%, SLO breach, health check failure
- Manual rollback via: `kubectl rollout undo` or GitOps revert

## Key Files
- `src/shieldops/agents/change_risk_analyzer/` — Risk scoring agent
- `src/shieldops/agents/config_validator/` — Config validation agent
- `src/shieldops/agents/gitops/` — GitOps agent
- `src/shieldops/agents/sla_monitor/` — SLA monitoring agent
- `src/shieldops/changes/` — 66 change management engines
- `src/shieldops/changes/deployment_risk.py` — Deployment risk predictor
- `src/shieldops/changes/canary_analyzer.py` — Canary deployment analysis
- `src/shieldops/changes/change_intelligence.py` — Change risk intelligence
- `src/shieldops/changes/deployment_confidence.py` — Deployment confidence scoring
- `infrastructure/kubernetes/` — K8s deployment manifests
- `infrastructure/docker/Dockerfile` — Container image definition
- `.github/workflows/cd-*.yml` — CI/CD deployment workflows

## Conventions
- Always dry-run before production deployment
- Production deployments require human approval when risk_score > 0.5
- Canary deployment required for production (minimum 10% traffic, 15min soak)
- Rollback must be tested and verified before declaring deployment complete
- All deployments recorded for DORA metrics tracking
- Deployment freeze windows enforced automatically
