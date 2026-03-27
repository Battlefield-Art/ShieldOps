# Manage Costs Skill

Manage cloud costs and FinOps — cost optimization, anomaly detection, budget management, and LLM spend tracking.

## Usage
`/manage-costs <action> [--provider <aws|gcp|azure|all>] [--period <timeframe>] [--budget <name>]`

Actions: `analyze`, `optimize`, `anomalies`, `budget`, `forecast`, `llm-costs`, `status`

## Agents Used
- `cost` — Cost analysis and optimization recommendations
- `cost_anomaly` — Cost spike detection and root cause analysis
- `finops_intelligence` — FinOps analytics and resource optimization
- `cloud_risk_ranker` — Multi-cloud risk-cost correlation
- `capacity_planner` — Capacity forecasting and bottleneck tracking

## Process

### Analyze (Cost Analysis)
1. **Collect billing**: Pull billing data from cloud providers
2. **Normalize**: Standardize costs across AWS/GCP/Azure
3. **Attribute**: Map costs to teams, services, environments
4. **Recommend**: Generate optimization recommendations

```python
from shieldops.agents.cost.runner import CostRunner

runner = CostRunner(connectors={"aws": aws, "gcp": gcp, "azure": azure})
result = await runner.analyze(
    providers=["aws", "gcp", "azure"],
    period="30d",
    group_by=["service", "team", "environment"],
)
```

### Optimize (Cost Optimization)
1. **Identify waste**: Find unused resources, oversized instances, idle capacity
2. **Rightsizing**: Generate rightsizing recommendations
3. **Reserved instances**: Analyze RI/SP coverage and utilization
4. **Spot/preemptible**: Identify workloads suitable for spot pricing
5. **Schedule**: Recommend shutdown schedules for dev/staging

```python
from shieldops.agents.finops_intelligence.runner import FinOpsIntelligenceRunner

runner = FinOpsIntelligenceRunner()
result = await runner.optimize(
    scope="all_accounts",
    optimization_types=["rightsizing", "ri_coverage", "waste", "scheduling"],
)
```

### Anomalies (Cost Spike Detection)
1. **Baseline**: Establish normal spend patterns
2. **Detect**: Identify cost anomalies exceeding baseline
3. **Root cause**: Analyze cause (new deployment, runaway, attack, misconfig)
4. **Alert**: Notify finance and engineering teams

```python
from shieldops.agents.cost_anomaly.runner import CostAnomalyRunner

runner = CostAnomalyRunner()
result = await runner.detect(
    providers=["aws", "gcp"],
    sensitivity="medium",
    lookback="7d",
)
```

### Budget (Budget Management)
1. **Set budgets**: Define per-team, per-service, per-environment budgets
2. **Track**: Monitor real-time spend against budgets
3. **Alert**: Notify at 50%, 75%, 90%, 100% thresholds
4. **Enforce**: Optional hard limits for non-production environments

### Forecast (Cost Forecasting)
1. **Historical analysis**: Analyze spending trends
2. **Project**: Forecast next 30/60/90 days
3. **Scenario modeling**: What-if analysis for planned changes
4. **RI planning**: Recommend reservation purchases

### LLM Costs (AI Spend Tracking)
1. **Track usage**: Monitor LLM API calls, tokens, costs per agent
2. **Optimize routing**: Use LLM router for cost-effective model selection
3. **Budget alerts**: Alert when agent LLM spend exceeds thresholds
4. **Report**: Per-agent, per-model cost breakdown

## Key Files
- `src/shieldops/agents/cost/` — Cost analysis agent
- `src/shieldops/agents/cost_anomaly/` — Cost anomaly agent
- `src/shieldops/agents/finops_intelligence/` — FinOps agent
- `src/shieldops/agents/capacity_planner/` — Capacity planning agent
- `src/shieldops/billing/` — 87 billing/FinOps engines
- `src/shieldops/billing/cloud_spend_forecaster.py` — Spend forecasting
- `src/shieldops/billing/intelligent_waste_classifier.py` — Waste classification
- `src/shieldops/billing/reservation_yield_optimizer.py` — RI optimization
- `src/shieldops/billing/cost_anomaly_root_cause_engine.py` — Anomaly root cause
- `src/shieldops/utils/llm_cost_tracker.py` — LLM cost tracking
- `src/shieldops/utils/llm_router.py` — LLM router (Haiku/Sonnet/Opus)

## Conventions
- Cost data normalized to USD across all providers
- Anomaly detection runs hourly; alerts within 15 minutes of spike
- Budget alerts are non-negotiable — always notify at thresholds
- LLM cost tracking mandatory for all agent executions
- Optimization recommendations must include estimated savings
- Reserved instance recommendations require 12-month commitment analysis
