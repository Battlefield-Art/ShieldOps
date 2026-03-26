# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ShieldOps is an AI Security Control Plane that governs, monitors, and responds to AI agent activity across enterprise infrastructure. The platform deploys autonomous security agents for runtime interception, non-human identity governance, MCP ecosystem security, and SOC automation — across multi-cloud (AWS/GCP/Azure) and on-premise environments.

**Core thesis:** The security control plane for AI agents. Intercepts tool calls, governs non-human identities, secures MCP ecosystems, and automates SOC operations — with policy gates at every layer.

## Build & Development Commands

```bash
# Install dependencies
pip install -e ".[dev]"

# Run all tests
python3 -m pytest tests/ -v --tb=short

# Run a single test file
python3 -m pytest tests/unit/test_<module>.py -v

# Run tests with coverage
python3 -m pytest tests/ -v --cov=src/shieldops

# Linting and formatting
ruff check src/ tests/ --fix
ruff format src/ tests/

# Type checking
mypy src/shieldops/

# Security scan
bandit -c pyproject.toml -ll -r src/

# Pre-commit hooks (ruff lint+format, mypy, bandit, trailing whitespace, etc.)
pre-commit run --all-files

# Start API server
uvicorn shieldops.api.main:app --reload

# CLI
shieldops --help
```

## Architecture

### Four Layers
1. **Connector Layer** — 17 connectors: AWS, GCP, Azure, Kubernetes, Linux, Windows, CrowdStrike, Microsoft Defender, Wiz, Splunk, Elastic, Datadog, New Relic, PagerDuty, ServiceNow, Jira, OpsGenie (`src/shieldops/connectors/{provider}/`)
2. **Observability Ingestion** — Vendor-neutral OpenTelemetry (Splunk, Datadog, Prometheus)
3. **Agent Orchestration** — LangGraph-based agents with graph→nodes→tools pattern
4. **Policy & Safety** — OPA policies, approval workflows, rollback, compliance

### Agent Architecture (LangGraph)
Each agent in `src/shieldops/agents/{type}/` follows this structure:
```
graph.py      # LangGraph StateGraph definition — nodes + edges + routing
nodes.py      # Node function implementations (investigate, act, validate)
tools.py      # Tool functions called by nodes (API calls, infra ops)
models.py     # Pydantic state/input/output models
prompts.py    # LLM prompt templates
runner.py     # Entry point — lifecycle management, execution
policy.py     # OPA policy integration (optional)
```

There are 89 LangGraph agents: investigation, remediation, security, learning, supervisor, soc_analyst, threat_hunter, forensics, deception, incident_response, attack_surface, ml_governance, finops_intelligence, zero_trust, threat_automation, soar_orchestration, itdr, auto_remediation, observability_intelligence, xdr, intelligent_automation, platform_intelligence, security_convergence, autonomous_defense, chatops, enterprise_integration, automation_orchestrator, cost, prediction, otel_pipeline, risk_scoring, auto_learning, security_automation, gitops, telemetry_optimizer, threat_intel, incident_commander, compliance_auditor, otel_collector_manager, adaptive_security, otel_deployer, security_posture, otel_semantic, soar_workflow, otel_tail_sampling, detection_engineering, otel_metrics_pipeline, security_testing, otel_logs_pipeline, threat_modeling, ai_runtime_defense, soc_brain, identity_graph, ai_red_team, ai_blue_team, agent_firewall, nhi_registry, mcp_security, data_pipeline_security, credential_lifecycle, vendor_normalizer, attack_campaign, situation_composer, compliance_reporter, oauth_analyzer, lateral_movement, shadow_ai_discovery, secrets_scanner, api_security, policy_engine, cloud_posture, container_security, supply_chain_security, incident_triage, change_risk_analyzer, cost_anomaly, adversarial_validation, mcp_gateway, service_account_tracker, data_classification, access_review, runbook_automation, capacity_planner, disaster_recovery, log_analyzer, chaos_engineering, sla_monitor, config_validator.

### Engine Module Pattern
The bulk of the codebase (~1,562+ modules) are analytics/intelligence engines across 13 packages. Each follows a strict pattern:
```python
# 3 StrEnum classes, 3 Pydantic models (Record, Analysis, Report)
# Engine class with: add_record()/record_item(), process(key),
#   generate_report(), get_stats(), clear_data(), 3 domain methods
# Ring-buffer storage with max_records eviction
```
- `add_record(**kwargs)` for: analytics, observability, security, knowledge, sla, billing, incidents, compliance
- `record_item(**kwargs)` for: changes, operations, topology

### Key Packages
| Package | Purpose | Count |
|---------|---------|-------|
| `observability/` | Alert intelligence, telemetry, SLI/SLO, OTel pipeline/autoscaler/sampling/attribution/cost, SLO-aware sampling, cardinality control, eBPF telemetry, collector fleet management, backpressure analysis, span-to-metric conversion | 204+ |
| `security/` | Threat detection, SOAR, zero trust, XDR, RBA pipeline (detection→risk→notable), MITRE mapping, hunt automation, playbook selection, IOC lifecycle, identity risk, threat feed quality, entity risk aggregation, AI runtime defense (prompt injection, LLM firewall, exfiltration guard), identity graph (OAuth grants, service accounts, trust relationships), attack simulation, defense hardening, cross-vendor SOC correlation, agent behavioral firewall (runtime interception, tool call auditing, behavioral baselines), NHI governance (registry, posture monitoring, shadow AI discovery, JIT credentials), MCP security (gateway, supply chain, zero-trust, God Key detection) | 390+ |
| `operations/` | Runbooks, automation, chaos, capacity, resource budgets | 128+ |
| `analytics/` | DORA, AIOps, root cause, experiment lifecycle, agent benchmarking, hyperparameter tuning, swarm intelligence, self-healing, knowledge distillation, autoresearch experiments, compute budget management | 222+ |
| `incidents/` | Triage, escalation, postmortem, on-call burden, notification | 85+ |
| `compliance/` | Evidence, audit, regulatory, policy enforcement, cost governance | 99+ |
| `billing/` | FinOps, cost optimization, RI planning, waste classification | 84+ |
| `topology/` | Service mesh, dependencies, API lifecycle, traffic patterns | 63+ |
| `sla/` | SLO tracking, error budgets, reliability, API SLA compliance | 52+ |
| `knowledge/` | Knowledge base, onboarding, feedback, agent knowledge distillation | 26+ |
| `audit/` | Audit trails, evidence, compliance mapping, governance | 30+ |
| `changes/` | GitOps, IaC validation, deployment intelligence, canary | 58+ |
| `config/` | Feature flags, drift analysis, validation | 11 |

### API & Dashboard
- FastAPI at `src/shieldops/api/` — RESTful, versioned `/api/v1/`, JWT auth, OpenAPI auto-gen
- React + TypeScript + Tailwind dashboard at `dashboard-ui/`
- **Design System**: Surface-based depth hierarchy (surface-0 through surface-4), opacity-based borders (`rgba(255,255,255,0.XX)`), brand cyan accent, Inter + JetBrains Mono typography. Premium component library: `btn-primary` (gradient + glow), `btn-secondary`, `card-surface`, `card-interactive` (hover-lift), `tab-bar`, `section-heading`. CSS custom properties for `--border-subtle/default/strong` and `--surface-*` tokens.
- Situations Queue (outcome-centric UX replacing widget dashboards)
- Agent Firewall SDK at `src/shieldops/sdk/` — Python SDK for LangChain, CrewAI, LlamaIndex interception
- Agent Firewall Monitor (runtime tool call interception dashboard)
- NHI Registry (non-human identity inventory and risk dashboard)
- MCP Security (MCP ecosystem security with God Key detection)
- Notification integrations: Slack, Teams, PagerDuty, email, SMS, voice, webhooks

### SDK
- Agent Firewall SDK at `src/shieldops/sdk/` — one-line integration with AI agent frameworks
- Supports: LangChain (`ShieldOpsCallbackHandler`), CrewAI (`ShieldOpsCrewAIWrapper`), LlamaIndex
- Modes: audit (observe only) or enforce (block risky calls)
- OTEL-compatible telemetry export to any collector (Splunk, Datadog, etc.)

### Connectors (17 total)
- **Cloud**: AWS (`connectors/aws/`), GCP, Azure, Kubernetes, Linux, Windows
- **Security**: CrowdStrike Falcon (OAuth2 + RTR + Threat Graph), Microsoft Defender (MSAL + KQL), Wiz (GraphQL + attack paths)
- **Observability**: Splunk (REST + HEC + SPL + ITSI), Elastic (DSL + EQL + SIEM), Datadog (metrics + logs + monitors), New Relic (NerdGraph + NRQL + SLIs)
- **Incident**: PagerDuty (REST + Events API v2), OpsGenie (alerts + on-call)
- **ITSM**: ServiceNow (Table API + CMDB + change requests), Jira (REST v3 + JQL)

## Tech Stack
- Python 3.12+, LangGraph, LangChain, Anthropic Claude (primary LLM)
- Multi-cloud LLM: Anthropic (direct), AWS Bedrock (Strands SDK), Google Vertex AI, Azure OpenAI
- FastAPI, Pydantic v2, SQLAlchemy (async), PostgreSQL, Redis, Kafka
- OpenTelemetry, LangSmith, structlog
- OPA (Open Policy Agent) for policy enforcement
- Terraform/OpenTofu, Kubernetes
- React, TypeScript, Tailwind CSS (dashboard)
- pytest, pytest-asyncio, playwright (e2e)
- GitHub Actions CI/CD

## Development Conventions

### Code Standards
- **Ruff** for lint + format (line-length=100, target py312)
- **mypy** strict mode — type hints required on all public functions
- **Pydantic v2** models for all data structures
- **structlog** for structured logging
- **async/await** for all I/O operations
- Pre-commit hooks: ruff, ruff-format, mypy, bandit, trailing-whitespace, end-of-file-fixer

### Testing
- Unit tests: `tests/unit/` (mirror source structure)
- Integration tests: `tests/integration/` (require Docker)
- Agent simulations: `tests/agents/` (replay historical incidents)
- Minimum 80% coverage on new code

### Git
- Branch naming: `feat/`, `fix/`, `chore/`, `docs/`
- Commit messages: conventional commits (`feat:`, `fix:`, `chore:`, `docs:`)
- PRs require passing CI + 1 review

### Security (Non-Negotiable)
- Never hardcode credentials — use env vars or secret managers
- All agent actions must pass OPA policy evaluation before execution
- Audit trail for every infrastructure change (immutable log)
- Blast-radius limits enforced per environment (dev/staging/prod)
- No agent can delete databases, drop tables, or modify IAM root policies
- Confidence thresholds: autonomous >0.85, human approval 0.5-0.85, escalate <0.5

## Infrastructure
- **CI/CD**: 7 GitHub Actions workflows (ci.yml, cd-backend.yml, cd-dashboard.yml, cd-staging.yml, cd-production.yml, gitops-sync.yml)
- **Kubernetes**: 16 manifests in `infrastructure/kubernetes/` (deployment, HPA, ingress, network policies, PDB, Kafka, Redis, OPA sidecar, secrets, configmaps)
- **Terraform**: `infrastructure/terraform/{aws,gcp,azure}/` — validated in CI
- **Docker**: `infrastructure/docker/Dockerfile` + `docker-compose.yml`
- **Helm**: `infrastructure/helm/` — chart for self-hosted deployments
- **Database**: `src/shieldops/db/` — SQLAlchemy models, Alembic migrations, async sessions, repository pattern
- **Monitoring**: `infrastructure/monitoring/`

## Productionization Status
- **Phase 135 (LLM Wiring)**: Done — all 38 agents wired with `llm_structured()` via `src/shieldops/utils/llm.py`
- LLM Router at `src/shieldops/utils/llm_router.py` (Haiku/Sonnet/Opus complexity routing)
- Cloud connectors have real SDK implementations (boto3, google-cloud, azure, kubernetes-client)
- 14 API middleware modules (rate limiter, tenant isolation, billing enforcement, security headers)
- See `docs/tasks.md` for remaining GA checklist (integration tests, pentest, SOC 2, docs site)

## Environment Variables
```
ANTHROPIC_API_KEY=     # Claude API key (primary LLM)
OPENAI_API_KEY=        # Fallback LLM
DATABASE_URL=          # PostgreSQL connection
REDIS_URL=             # Redis connection
KAFKA_BROKERS=         # Kafka broker list
OPA_ENDPOINT=          # OPA policy engine URL
LANGSMITH_API_KEY=     # Agent tracing
STRIPE_SECRET_KEY=     # Billing integration
STRIPE_WEBHOOK_SECRET= # Stripe webhooks
SLACK_BOT_TOKEN=       # ChatOps approvals
PAGERDUTY_API_KEY=     # Alert ingestion
VAULT_ADDR=            # Secret management
```

## Custom Slash Commands
`/build`, `/test`, `/deploy`, `/scan`, `/review`, `/analyze`, `/design`, `/task`, `/build-agent`, `/scan-security`, `/check-health`, `/run-agent`, `/review-agent`, `/manage-otel`, `/manage-gitops`
