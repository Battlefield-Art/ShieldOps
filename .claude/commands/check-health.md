# Check Health Skill

Run health checks on ShieldOps platform — environment, services, code quality, tests, and engine modules.

## Usage
`/check-health [--scope <env|services|code|tests|engines|all>] [--fix]`

## Agents Used
- `sla_monitor` — SLO compliance and error budget monitoring
- `config_validator` — Configuration baseline compliance
- `observability_intelligence` — Platform observability health

## Process

### 1. Check Python Environment
- Verify Python 3.12+: `python3 --version`
- Check virtual env: verify `.venv` or `VIRTUAL_ENV` is set
- Validate dependencies: `pip check` for conflicts

### 2. Check Service Dependencies
- PostgreSQL: `pg_isready -h localhost -p 5432` or connect test
- Redis: `redis-cli ping`
- OPA: `curl http://localhost:8181/health`
- Kafka: Check `docker ps` for kafka container

### 3. Check Code Quality
- Lint: `python3 -m ruff check src/ tests/`
- Format: `python3 -m ruff format --check src/ tests/`
- Type check: `python3 -m mypy src/shieldops/ --ignore-missing-imports`

### 4. Run Test Suite
- Unit tests: `python3 -m pytest tests/unit/ -v --tb=short`
- Integration tests: `python3 -m pytest tests/integration/ -v --tb=short`
- Report: total tests, passed, failed, coverage

### 5. Platform Engine Health
Verify key engines across all 13 packages can instantiate and report stats:

**Analytics (255 engines)**: Capacity trends, SRE metrics, incident clustering, DORA, agent benchmarking
**Observability (232 engines)**: Health reports, alert noise, threshold tuning, backup verification, OTel pipeline
**Security (518 engines)**: Vulnerability lifecycle, API security, cert expiry, network flows, cloud posture
**Operations (160 engines)**: Runbook execution, workload scheduling, self-healing, scaling efficiency
**Compliance (116 engines)**: Gap analysis, automation rules, license scanning, access certification, evidence chain
**Incidents (88 engines)**: Severity prediction, deduplication, escalation analysis, on-call fatigue
**Billing (87 engines)**: Cost forecast, orphan detection, tag governance, budget management, RI optimization
**Changes (66 engines)**: Deployment risk, change intelligence, canary analysis, velocity tracking
**Topology (65 engines)**: Service catalog, dependency scoring, API health, circuit breakers, cascade prediction
**SLA (54 engines)**: SLO burn rate, error budget, availability patterns, reliability scoring
**Audit (30 engines)**: Config audit, decision audit, audit intelligence
**Knowledge (27 engines)**: Article manager, knowledge gaps, decay detection, onboarding
**Config (11 engines)**: Feature flags, parity validation, drift analysis

```python
# Example: verify an engine instantiates correctly
from shieldops.analytics.capacity_trends import CapacityTrendAnalyzer

engine = CapacityTrendAnalyzer()
stats = engine.get_stats()
assert stats["record_count"] == 0  # Fresh engine, no data
```

### 6. Agent Health
Verify agent runners can instantiate and compile their LangGraph workflows:

```python
from shieldops.agents.investigation.runner import InvestigationRunner

runner = InvestigationRunner()
assert runner._app is not None  # Graph compiled successfully
```

## Key Files
- `src/shieldops/api/routes/health.py` — Health check endpoints (/health, /ready)
- `src/shieldops/agents/` — 179 agent directories/modules
- `src/shieldops/analytics/` — 255 analytics engines
- `src/shieldops/security/` — 518 security engines
- `src/shieldops/observability/` — 232 observability engines
- `src/shieldops/operations/` — 160 operations engines
- `src/shieldops/compliance/` — 116 compliance engines
- `pyproject.toml` — Dependencies and tool configuration
- `infrastructure/docker/docker-compose.yml` — Service dependencies

## Conventions
- Health checks must complete within 30 seconds
- `--fix` flag auto-fixes lint/format issues but never modifies business logic
- Failed health checks should suggest specific remediation steps
- Engine health verified by instantiation + get_stats() (no data required)
- Agent health verified by runner instantiation + graph compilation
