# analytics/ — Analytics Engine Modules

255 analytics engines for DORA metrics, AIOps, root cause analysis, and agent intelligence.

## Domains
- DORA metrics + engineering productivity
- AIOps + root cause analysis
- Experiment lifecycle + A/B testing
- Agent benchmarking + hyperparameter tuning
- Swarm intelligence + self-healing
- Knowledge distillation + autoresearch
- Compute budget management

## Engine Pattern
Same as `security/CLAUDE.md` — 3 StrEnums, 3 Pydantic models, Engine class.

Use `add_record(**kwargs)` for all analytics engines.

## Key Files
- `engine.py` — Core analytics engine
- `soc_assistant_analytics.py` — AI assistant effectiveness
- `analyst_productivity_engine.py` — Analyst productivity measurement
- `hunt_effectiveness_analytics.py` — Threat hunting ROI
