# Analyze Analytics Skill

Run AIOps analytics — root cause analysis, DORA metrics, agent benchmarking, performance attribution, and predictive intelligence.

## Usage
`/analyze-analytics <action> [--scope <service|team|platform>] [--period <timeframe>] [--type <aiops|dora|agent|perf>]`

Actions: `root-cause`, `dora`, `benchmark`, `predict`, `capacity`, `toil`, `status`

## Agents Used
- `anomaly_detector` — Behavioral anomaly detection across telemetry
- `prediction` — Predictive analytics and forecasting
- `calibration` — Confidence calibration for agent decisions
- `benchmarker` — Agent performance benchmarking
- `performance_profiler` — Service performance profiling and regression detection
- `platform_intelligence` — Platform-wide intelligence and correlation

## Process

### Root Cause (AIOps Root Cause Analysis)
1. **Ingest signals**: Collect metrics, logs, traces from affected services
2. **Correlate**: Find temporal and causal correlations across services
3. **Rank causes**: Use ML to rank potential root causes by probability
4. **Explain**: Generate human-readable explanation of root cause chain

```python
from shieldops.analytics.aiops_root_cause_engine import AIOpsRootCauseEngine

engine = AIOpsRootCauseEngine()
engine.add_record(
    service="payment-service", signal_type="metric",
    anomaly="latency_spike", value=2500, baseline=200,
    timestamp="2026-03-26T10:00:00Z",
)
report = engine.generate_report()
```

### DORA (Deployment Metrics)
1. **Collect**: Pull deployment events, incidents, recovery timestamps
2. **Calculate**: Compute DORA four key metrics:
   - Deployment frequency
   - Lead time for changes
   - Change failure rate
   - Time to restore service
3. **Benchmark**: Compare against elite/high/medium/low performers
4. **Trend**: Track improvement over time

```python
from shieldops.analytics.deployment_analytics_engine import DeploymentAnalyticsEngine

engine = DeploymentAnalyticsEngine()
engine.add_record(
    deployment_id="deploy-142", service="api-server",
    environment="production", status="success",
    lead_time_hours=2.5, rollback=False,
)
report = engine.generate_report()
```

### Benchmark (Agent Performance)
1. **Measure**: Track agent decision quality, response time, accuracy
2. **Compare**: Benchmark across agent types and versions
3. **Fitness score**: Calculate multi-dimensional fitness scores
4. **Optimize**: Identify underperforming agents for tuning

```python
from shieldops.analytics.agent_performance_benchmark_engine import AgentPerformanceBenchmarkEngine

engine = AgentPerformanceBenchmarkEngine()
engine.add_record(
    agent_type="soc_analyst", decision="escalate",
    confidence=0.92, response_time_ms=1200,
    outcome="true_positive",
)
report = engine.generate_report()
```

### Predict (Predictive Intelligence)
1. **Analyze trends**: Historical pattern analysis
2. **Forecast**: Predict incidents, capacity needs, cost trends
3. **Alert**: Proactive alerting before thresholds are breached
4. **Recommend**: Generate preemptive recommendations

### Capacity (Capacity Forecasting)
1. **Collect utilization**: CPU, memory, disk, network across services
2. **Forecast**: Project resource needs 30/60/90 days out
3. **Bottleneck**: Identify current and projected bottlenecks
4. **Right-size**: Generate rightsizing recommendations

### Toil (Toil Reduction)
1. **Measure**: Identify repetitive manual operational tasks
2. **Quantify**: Calculate toil hours and engineering cost
3. **Automate**: Suggest automation opportunities
4. **Track**: Monitor toil reduction over time

## Key Files
- `src/shieldops/analytics/` — 255 analytics engines
- `src/shieldops/analytics/aiops_root_cause_engine.py` — AIOps root cause
- `src/shieldops/analytics/causal_inference_engine.py` — Causal inference
- `src/shieldops/analytics/deployment_analytics_engine.py` — DORA metrics
- `src/shieldops/analytics/agent_performance_benchmark_engine.py` — Agent benchmarking
- `src/shieldops/analytics/agent_fitness_scorer.py` — Agent fitness scoring
- `src/shieldops/analytics/agent_decision_quality_engine.py` — Decision quality
- `src/shieldops/analytics/capacity_demand_forecaster.py` — Capacity forecasting
- `src/shieldops/analytics/perf_regression_detector.py` — Perf regression detection
- `src/shieldops/analytics/toil_reduction_intelligence.py` — Toil reduction
- `src/shieldops/analytics/sre_golden_signal_engine.py` — SRE golden signals
- `src/shieldops/analytics/intelligent_root_cause_ranker.py` — Root cause ranking
- `src/shieldops/analytics/resilience_debt_engine.py` — Resilience debt
- `src/shieldops/analytics/responder_effectiveness_scorer.py` — Responder effectiveness
- `src/shieldops/analytics/alert_lifecycle_intelligence.py` — Alert lifecycle

## Related Agents
- `src/shieldops/agents/anomaly_detector/` — Anomaly detection agent
- `src/shieldops/agents/prediction/` — Prediction agent
- `src/shieldops/agents/calibration/` — Calibration agent
- `src/shieldops/agents/benchmarker.py` — Benchmarker module
- `src/shieldops/agents/performance_profiler/` — Performance profiler agent
- `src/shieldops/agents/platform_intelligence/` — Platform intelligence agent

## Conventions
- All analytics engines follow the standard engine pattern: add_record → process → generate_report
- DORA metrics calculated on rolling 30-day windows by default
- Root cause analysis requires minimum 3 correlated signals
- Agent benchmarks run against standardized test scenarios
- Capacity forecasts include confidence intervals
- Performance regression detection uses p95/p99 latency baselines
