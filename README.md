<p align="center">
  <img src="dashboard-ui/public/favicon.svg" width="48" height="48" alt="ShieldOps" />
</p>

<h1 align="center">ShieldOps</h1>
<p align="center"><strong>The security control plane for AI agents</strong></p>

<p align="center">
  <a href="#quick-start">Quick Start</a> ·
  <a href="#product-modules">Modules</a> ·
  <a href="#sdk">SDK</a> ·
  <a href="#deployment">Deploy</a> ·
  <a href="#docs">Docs</a>
</p>

---

## Why ShieldOps

AI agents are bypassing traditional EDR and endpoint controls because they operate through APIs, not executables. Non-human identities (service accounts, API keys, OAuth tokens) now outnumber human users 100:1, yet most security tools ignore them entirely. The Model Context Protocol (MCP) creates "God Key" risks where a single compromised tool server grants lateral access across your entire stack.

ShieldOps intercepts every AI agent tool call at runtime, governs non-human identity sprawl, secures MCP server ecosystems, and unifies security operations across vendors — giving your SOC team full visibility and control over autonomous AI workloads.

## Product Modules

| Module | What It Does | Key Features |
|--------|-------------|--------------|
| **Agent Firewall** | Runtime interception of AI agent tool calls | Behavioral baselines, circuit breaker, kill switch, audit reports |
| **NHI Registry** | Discover and govern non-human identities | Shadow AI detection, posture monitoring, JIT credentials |
| **MCP Security** | Secure MCP server ecosystem | God Key detection, supply chain scanning, zero-trust transport |
| **SOC Brain** | Cross-vendor AI-driven security operations | Situations queue, CrowdStrike/Defender/Wiz integration, HITL approval |

## Quick Start

### SDK

```bash
pip install shieldops-sdk
```

```python
from shieldops.sdk.langchain import ShieldOpsCallbackHandler

agent = create_agent(
    callbacks=[ShieldOpsCallbackHandler(api_key="sk-...")]
)
```

The callback handler intercepts all tool calls, enforces policies, and streams audit events to your ShieldOps tenant.

### Self-Hosted

```bash
git clone https://github.com/ghantakiran/ShieldOps.git
cd ShieldOps

cp .env.example .env
# Add your ANTHROPIC_API_KEY and other secrets to .env

docker compose -f infrastructure/docker/docker-compose.yml up -d
```

Visit `http://localhost:3000` for the dashboard, `http://localhost:8000/api/v1/docs` for the API.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        Dashboard (React)                     │
│              Agent Monitor · SOC Queue · NHI Registry         │
├──────────────────────────────────────────────────────────────┤
│                      API Gateway (FastAPI)                    │
│         JWT Auth · Rate Limiting · Tenant Isolation           │
├────────────────┬─────────────────┬───────────────────────────┤
│  Agent Firewall│   SOC Brain     │      MCP Security         │
│  Intercept     │   Investigate   │      Scan & Govern        │
│  Evaluate      │   Correlate     │      Detect God Keys      │
│  Enforce       │   Respond       │      Zero-Trust Transport │
├────────────────┴─────────────────┴───────────────────────────┤
│                   Policy Engine (OPA)                         │
│        Rego Policies · Approval Workflows · Rollback          │
├──────────────────────────────────────────────────────────────┤
│               Agent Orchestration (LangGraph)                │
│    50 Autonomous Agents · Supervisor · Confidence Routing     │
├──────────────────────────────────────────────────────────────┤
│              Observability Ingestion (OpenTelemetry)          │
│     Splunk · Datadog · Prometheus · CloudWatch · Elastic      │
├──────────────────────────────────────────────────────────────┤
│              Multi-Cloud & ITSM Connectors (17)              │
│  AWS · GCP · Azure · K8s · Linux · Windows · Datadog · NR    │
│  PagerDuty · ServiceNow · Jira · OpsGenie · Splunk · Elastic │
└──────────────────────────────────────────────────────────────┘
```

## Tech Stack

Python 3.12 · LangGraph · FastAPI · React · TypeScript · Tailwind CSS · PostgreSQL · Redis · Kafka · OPA · OpenTelemetry · Pydantic v2 · structlog · Anthropic Claude

## Platform Stats

| Metric | Count |
|--------|-------|
| Autonomous AI agents | 50 |
| Security & analytics engines | 1,562+ |
| Cloud connectors | 17 (AWS, GCP, Azure, K8s, Linux, Windows, CrowdStrike, Defender, Wiz, Splunk, Elastic, Datadog, New Relic, PagerDuty, ServiceNow, Jira, OpsGenie) |
| Dashboard pages | 69 |
| API endpoints | 700+ |
| OPA policies | 10+ (HIPAA, SOC 2, PCI-DSS, GDPR, FedRAMP) |
| Unit tests | 62,000+ |

## Deployment

### Docker Compose (recommended for evaluation)

```bash
docker compose -f infrastructure/docker/docker-compose.yml up -d
```

### Kubernetes (Helm)

```bash
helm install shieldops infrastructure/helm/ \
  --namespace shieldops \
  --create-namespace \
  --values infrastructure/helm/values-production.yaml
```

### Railway (PaaS)

[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/template/shieldops)

One-click deploy with managed PostgreSQL, Redis, and auto-scaling.

## Development

```bash
# Install dependencies
pip install -e ".[dev]"

# Run tests
python3 -m pytest tests/ -v --tb=short

# Run tests with coverage
python3 -m pytest tests/ -v --cov=src/shieldops

# Lint and format
ruff check src/ tests/ --fix
ruff format src/ tests/

# Type check
mypy src/shieldops/

# Security scan
bandit -c pyproject.toml -ll -r src/

# Pre-commit hooks
pre-commit run --all-files

# Start API server (dev mode)
uvicorn shieldops.api.main:app --reload

# Start dashboard (dev mode)
cd dashboard-ui && npm install && npm run dev
```

## GitOps

ShieldOps supports GitOps-driven deployment via ArgoCD and Kustomize.

```
infrastructure/gitops/
  argocd/            # ArgoCD Application & AppProject
  kustomize/
    base/            # Base manifests (refs to kubernetes/)
    overlays/
      staging/       # Staging patches (audit mode, 1 replica)
      production/    # Production patches (enforce mode, 3 replicas, TLS)
```

ArgoCD watches the `main` branch and auto-syncs with self-heal enabled. Kustomize overlays patch replica counts, resource limits, ingress hosts, and firewall modes per environment. See `infrastructure/gitops/` for the full configuration.

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `ANTHROPIC_API_KEY` | Claude API key (primary LLM) |
| `DATABASE_URL` | PostgreSQL connection string |
| `REDIS_URL` | Redis connection string |
| `KAFKA_BROKERS` | Kafka broker list |
| `OPA_ENDPOINT` | OPA policy engine URL |
| `LANGSMITH_API_KEY` | Agent tracing |
| `STRIPE_SECRET_KEY` | Billing integration |
| `SLACK_BOT_TOKEN` | ChatOps approvals |
| `PAGERDUTY_API_KEY` | Alert ingestion |

## Docs

| Document | Description |
|----------|-------------|
| [Architecture Overview](docs/architecture/overview.md) | Four-layer architecture design |
| [ADR-001: LangGraph](docs/architecture/adr-001-langgraph-selection.md) | Why LangGraph over CrewAI/AutoGen |
| [ADR-002: Multi-Cloud](docs/architecture/adr-002-multi-cloud-abstraction.md) | Connector architecture |
| [ADR-003: Safety Model](docs/architecture/adr-003-agent-safety-model.md) | Five-layer defense in depth |
| [Production Runbook](docs/PRODUCTION_LAUNCH_RUNBOOK.md) | 8-phase deployment guide |
| [API Docs](http://localhost:8000/api/v1/docs) | Interactive OpenAPI (when running) |

## Contributing

1. Fork the repository
2. Create a feature branch (`feat/your-feature`)
3. Write tests for new functionality
4. Ensure `ruff check` and `pytest` pass
5. Submit a pull request

Please follow [conventional commits](https://www.conventionalcommits.org/) for commit messages.

## License

Apache 2.0 — see [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>ShieldOps</strong> — The security control plane for AI agents.
</p>
