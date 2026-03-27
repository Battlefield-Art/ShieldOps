# operations/ — Operations Engine Modules

160+ operations engines for runbooks, automation, chaos engineering, and capacity management.

## Domains
- Runbook execution + automation
- Chaos engineering + fault injection safety
- Capacity planning + resource budgets
- SIEM migration + SOC transformation
- Playbook effectiveness + adaptation
- Code vulnerability tracking
- App deployment lifecycle

## Engine Pattern
Same as `security/CLAUDE.md` — 3 StrEnums, 3 Pydantic models, Engine class.

Use `record_item(**kwargs)` for operations engines (not `add_record`).

## Key Files
- `situation_lifecycle_engine.py` — Situation queue lifecycle
- `action_recommendation_engine.py` — Recommended actions
- `soc_maturity_engine.py` — SOC maturity assessment
- `siem_migration_engine.py` — SIEM migration tracking
