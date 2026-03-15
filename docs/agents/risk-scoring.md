# Risk Scoring Agent

Risk-Based Alerting (RBA) agent inspired by Splunk's RBA methodology. Aggregates risk signals from multiple detection sources, computes entity-level risk scores, and triggers actions based on composite risk thresholds rather than individual alert severity.

## Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Ingest     │────▶│  Aggregate   │────▶│    Score     │────▶│    Act       │
│   Signals    │     │  Per Entity  │     │    Risk      │     │   Decide     │
└──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
       │                    │                    │                    │
       ▼                    ▼                    ▼                    ▼
  Detection Rules     Entity Graph         MITRE Weights       Notable Events
  Anomaly Scores      Time Windows         Decay Functions     SOC Escalation
  Threat Intel        Source Fusion         Confidence Band     Auto-Response
```

## Workflow

1. **Ingest** -- Consumes risk signals from SIEM detection rules, anomaly detection engines, threat intel correlations, and behavioral analytics. Each signal carries a base risk score, MITRE technique mapping, and source confidence rating.
2. **Aggregate** -- Groups signals by entity (user, host, IP, service account) within configurable time windows. Applies multi-source fusion to deduplicate and weight overlapping detections. Builds entity-level risk profiles.
3. **Score** -- Computes composite risk scores using technique-aware weighting (tactic chain analysis), temporal decay functions, and confidence-band adjustments. Higher scores for kill-chain progression patterns.
4. **Act** -- When entity risk exceeds thresholds: generates notable events for SOC review (score 50-85), triggers automated containment playbooks (score >85), or escalates to incident response (score >95 with high confidence).

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `RBA_HIGH_RISK_THRESHOLD` | Score to trigger auto-response | `85` |
| `RBA_NOTABLE_THRESHOLD` | Score to generate notable event | `50` |
| `RBA_DECAY_HOURS` | Hours for risk score half-life | `24` |
| `RBA_AGGREGATION_WINDOW` | Time window for signal grouping | `1h` |
| `RBA_MITRE_WEIGHT_MULTIPLIER` | Multiplier for kill-chain patterns | `1.5` |

## Usage

```bash
# Trigger via CLI
shieldops run-agent risk_scoring --entity-type user --window 4h

# Trigger via API
curl -X POST /api/v1/agents/risk_scoring/run \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"entity_type": "host", "threshold": 75, "auto_respond": true}'
```

Returns a risk report with per-entity scores, contributing signals, MITRE technique mappings, and actions taken.
