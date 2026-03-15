# Telemetry Optimizer Agent

Cost-aware telemetry optimization agent inspired by the autoresearch pattern. It continuously experiments with sampling rates, cardinality controls, and pipeline configurations to minimize observability costs while maintaining signal quality.

## Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Profile    │────▶│  Experiment  │────▶│   Evaluate   │────▶│    Apply     │
│  Telemetry   │     │  Strategies  │     │   Results    │     │  Optimized   │
└──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
       │                    │                    │                    │
       ▼                    ▼                    ▼                    ▼
  Volume Analysis     Sampling Rates       Cost vs Signal      Config Deploy
  Cardinality Map     Filter Rules         SLO Compliance      Rollback Guard
  Cost Attribution    Aggregation          A/B Comparison       Budget Track
```

## Workflow

1. **Profile** -- Analyzes current telemetry volume, cardinality hotspots, and cost attribution per service. Identifies high-cost, low-value metric series and verbose trace spans.
2. **Experiment** -- Generates candidate optimization strategies: adjusted tail sampling rates, metric aggregation rules, span filtering policies, and cardinality limits. Runs A/B experiments in isolated pipeline segments.
3. **Evaluate** -- Measures each experiment against convergence criteria: cost reduction percentage, SLO signal preservation, alert fidelity, and debugging capability retention. Uses the single-metric-focus pattern for clear optimization targets.
4. **Apply** -- Deploys winning configurations with rollback guards. Tracks budget consumption in real-time and triggers re-optimization if costs drift above thresholds.

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `TELEMETRY_BUDGET_MONTHLY` | Monthly telemetry budget (USD) | `10000` |
| `OPTIMIZATION_TARGET` | Primary metric to optimize | `cost_per_useful_signal` |
| `MIN_SLO_COVERAGE` | Minimum SLO signal retention % | `99.5` |
| `EXPERIMENT_DURATION_HOURS` | Duration of each A/B experiment | `4` |
| `MAX_CARDINALITY_PER_METRIC` | Max label combinations per metric | `1000` |

## Usage

```bash
# Trigger via CLI
shieldops run-agent telemetry_optimizer --budget 5000 --target cost

# Trigger via API
curl -X POST /api/v1/agents/telemetry_optimizer/run \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"budget_usd": 5000, "preserve_slos": true}'
```

Returns an optimization report with before/after cost projections, applied changes, and SLO impact analysis.
