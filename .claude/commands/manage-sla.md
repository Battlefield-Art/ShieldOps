# Manage SLA Skill

Manage SLOs, error budgets, and service reliability — tracking, forecasting, burn rate alerting, and breach response.

## Usage
`/manage-sla <action> [--service <name>] [--slo <target>] [--window <rolling|calendar>]`

Actions: `track`, `budget`, `forecast`, `breach`, `report`, `status`

## Agents Used
- `sla_monitor` — Error budget burn rate monitoring with exhaustion forecasting
- `capacity_planner` — Capacity forecasting to prevent SLA breaches

## Process

### Track (SLO Tracking)
1. **Define SLOs**: Set availability, latency, throughput targets per service
2. **Measure SLIs**: Calculate service level indicators from telemetry
3. **Track compliance**: Monitor SLO compliance over rolling windows
4. **Dashboard**: Real-time SLO compliance dashboard

```python
from shieldops.sla.engine import SLAEngine

engine = SLAEngine()
engine.add_record(
    service="api-server", slo_name="availability",
    target=0.999, actual=0.9985,
    window="30d", measurement_time="2026-03-26T10:00:00Z",
)
report = engine.generate_report()
```

### Budget (Error Budget Management)
1. **Calculate**: Compute remaining error budget per SLO
2. **Allocate**: Distribute budget across planned changes and incidents
3. **Burn rate**: Track 1h/6h/24h/30d burn rates
4. **Alert**: Alert at configurable burn rate thresholds

```python
from shieldops.sla.error_budget_burn_intelligence import ErrorBudgetBurnIntelligence

engine = ErrorBudgetBurnIntelligence()
engine.add_record(
    service="payment-service", slo_target=0.999,
    current_error_rate=0.002,
    burn_rate_1h=2.5, burn_rate_6h=1.8,
    budget_remaining_pct=42.0,
)
report = engine.generate_report()
```

### Forecast (Budget Exhaustion)
1. **Analyze trends**: Historical error budget consumption patterns
2. **Project**: Forecast when budget will be exhausted
3. **Scenarios**: Model impact of planned deployments on budget
4. **Recommend**: Suggest freeze or remediation actions

```python
from shieldops.sla.burn_predictor import BurnPredictor

predictor = BurnPredictor()
predictor.add_record(
    service="api-server", budget_remaining_pct=35.0,
    burn_rate_trend="increasing",
    days_until_exhaustion=12,
)
report = predictor.generate_report()
```

### Breach (SLA Breach Response)
1. **Detect**: Identify SLO breaches in real-time
2. **Impact**: Assess customer and business impact
3. **Respond**: Trigger automated response (deploy freeze, escalation)
4. **Remediate**: Execute remediation playbook
5. **Report**: Generate breach postmortem

### Report (Reliability Reports)
1. **Executive summary**: SLO compliance across all services
2. **Error budget**: Budget status and trends per team
3. **Improvement**: Track reliability improvement initiatives
4. **Benchmarks**: Compare against industry standards

## Key Files
- `src/shieldops/sla/` — 54 SLA/SLO engines
- `src/shieldops/sla/engine.py` — Core SLA engine
- `src/shieldops/sla/error_budget_burn_intelligence.py` — Burn rate intelligence
- `src/shieldops/sla/burn_rate_alert_engine.py` — Burn rate alerting
- `src/shieldops/sla/error_budget_tracker_engine.py` — Budget tracking
- `src/shieldops/sla/burn_predictor.py` — Budget exhaustion forecasting
- `src/shieldops/sla/availability_pattern_engine.py` — Availability patterns
- `src/shieldops/sla/service_reliability_scorer.py` — Reliability scoring
- `src/shieldops/sla/reliability_improvement_tracker.py` — Improvement tracking
- `src/shieldops/sla/api_sla_compliance_tracker.py` — API SLA compliance
- `src/shieldops/sla/automated_sla_breach_responder.py` — Auto breach response
- `src/shieldops/sla/error_budget_allocator.py` — Budget allocation
- `src/shieldops/sla/dependency_sla.py` — Dependency SLA tracking

## Related Agents
- `src/shieldops/agents/sla_monitor/` — SLA monitoring agent
- `src/shieldops/agents/capacity_planner/` — Capacity planning agent

## Conventions
- SLOs use rolling 30-day windows by default
- Error budget burn rate alerts: >2x triggers page, >5x triggers incident
- SLA breach automatically triggers deploy freeze in production
- Budget allocation requires team lead approval for >10% of remaining budget
- Reliability reports generated weekly for SRE review
- All SLI calculations use server-side measurements (not client-side)
