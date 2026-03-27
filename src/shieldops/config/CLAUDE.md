# config/ — Feature Flags & Configuration

11 modules for feature flags, drift analysis, and validation.

## Key Files
- `settings.py` — Pydantic Settings for all environment config
- Feature flag management
- Configuration drift detection
- Validation rules

## Environment Variables
See root CLAUDE.md for full list. Key ones:
- `ANTHROPIC_API_KEY` — Claude API key
- `DATABASE_URL` — PostgreSQL
- `REDIS_URL` — Redis
- `OPA_ENDPOINT` — OPA policy engine
