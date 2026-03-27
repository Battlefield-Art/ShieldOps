<p align="center">
  <img src="dashboard-ui/public/favicon.svg" width="48" height="48" alt="ShieldOps" />
</p>

<h1 align="center">ShieldOps</h1>
<p align="center"><strong>The security control plane for AI agents</strong></p>

<p align="center">
  <a href="#quick-start">Quick Start</a> ·
  <a href="#product-modules">Modules</a> ·
  <a href="#competitive-positioning">vs CrowdStrike/Palo Alto/Rubrik</a> ·
  <a href="#deployment">Deploy</a> ·
  <a href="#docs">Docs</a>
</p>

---

## Why ShieldOps

AI agents are bypassing traditional EDR and endpoint controls because they operate through APIs, not executables. Non-human identities (service accounts, API keys, OAuth tokens) now outnumber human users 100:1, yet most security tools ignore them entirely. The Model Context Protocol (MCP) creates "God Key" risks where a single compromised tool server grants lateral access across your entire stack.

ShieldOps intercepts every AI agent tool call at runtime, governs non-human identity sprawl, secures MCP server ecosystems, and unifies security operations across vendors — giving your SOC team full visibility and control over autonomous AI workloads.

## Platform Stats

| Metric | Count |
|--------|-------|
| Autonomous LangGraph agents | **151** |
| Security & analytics engines | **1,709** |
| Dashboard pages | **158** |
| API endpoints | **749** |
| Cloud/vendor connectors | **18** |
| Test files | **1,961** |
| OPA policies | 10+ (HIPAA, SOC 2, PCI-DSS, GDPR, FedRAMP) |
| Modular CLAUDE.md files | 29 (hierarchical documentation) |

## Product Modules

| Module | What It Does | Key Features |
|--------|-------------|--------------|
| **Agent Firewall** | Runtime interception of AI agent tool calls | Behavioral baselines, circuit breaker, kill switch, audit |
| **NHI Registry** | Discover and govern non-human identities | Shadow AI detection, posture monitoring, JIT credentials |
| **MCP Security** | Secure MCP server ecosystem | God Key detection, supply chain scanning, zero-trust |
| **SOC Brain** | Cross-vendor AI-driven security operations | Situations queue, auto-triage, closed-loop learning |
| **Agentic MDR** | Machine-speed managed detection & response | Vendor-neutral, <5min MTTR, 97%+ accuracy |
| **AI Runtime Guardian** | Comprehensive AI runtime protection | Prompt injection, model behavior, tool abuse, output sanitization |
| **Situation Manager** | Outcome-centric alert management | 847 alerts → 3 actionable situations with narratives |
| **Cross-Vendor Correlator** | Unified signal correlation | CrowdStrike + Defender + Wiz + Splunk + Okta → OCSF |
| **Agent Memory Store** | Persistent episodic memory for agents | Cross-agent learning, FP pattern recall |
| **Reflection Engine** | Agent self-evaluation & improvement | "Did my action work?" threshold auto-tuning |

## Competitive Positioning

### vs CrowdStrike

| CrowdStrike Product | ShieldOps Agent | Advantage |
|---|---|---|
| Agentic MDR | `agentic_mdr` | Vendor-neutral across ANY vendor, not Falcon-locked |
| Falcon OverWatch ($250K/yr) | `managed_threat_hunting` | Autonomous 24/7, included in platform |
| Charlotte AI | `ai_soc_assistant` | Open, cross-vendor, Claude-powered |
| Falcon Identity | `identity_protection` | Multi-IdP (Okta+Entra+AWS+GCP+K8s) |
| Falcon LogScale | `log_intelligence` | Any log source, LLM reasoning |
| Falcon Spotlight | `vulnerability_intelligence` | Scanless, multi-vendor telemetry |
| Falcon Foundry | `security_app_builder` | Real LangGraph code, not no-code |

### vs Palo Alto Networks

| Palo Alto Product | ShieldOps Agent | Advantage |
|---|---|---|
| Cortex XDR | `autonomous_xdr` | Any sensor, not PA-locked |
| Cortex XSIAM ($1M+) | `autonomous_soc` | Open AI SOC, no proprietary data lake |
| Prisma Cloud CNAPP | `cnapp_analyzer` | CSPM+CWPP+CIEM unified, multi-cloud |
| Prisma Access ZTNA | `zero_trust_network` | ZTNA for AI agents + NHIs |
| Cortex XSOAR | `intelligent_soar` | LangGraph adaptive playbooks |
| WildFire | `malware_analyzer` | LLM analysis in seconds vs sandbox minutes |
| Prisma AIRS | `ai_runtime_guardian` | Deeper: prompt+model+tool+agent+output |

### vs Rubrik

| Rubrik Product | ShieldOps Agent | Advantage |
|---|---|---|
| Cyber Recovery | `cyber_recovery` | Clean room validation, multi-cloud |
| Data Threat Analytics | `data_threat_hunting` | LLM-powered, backups+prod+AI pipelines |
| Sensitive Data Monitoring | `sensitive_data_monitor` | Continuous, includes AI pipeline data |
| Ransomware Investigation | `ransomware_forensics` | LLM forensics + blast radius prediction |
| Data Lock | `data_resilience` | Immutable protection for AI models too |
| Cloud Vault | `air_gap_vault` | Air-gapped vault for models+configs |

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

### Self-Hosted

```bash
git clone https://github.com/ghantakiran/ShieldOps.git
cd ShieldOps

cp .env.example .env
# Add your ANTHROPIC_API_KEY and other secrets

docker compose -f infrastructure/docker/docker-compose.yml up -d
```

Visit `http://localhost:3000` for the dashboard, `http://localhost:8000/api/v1/docs` for the API.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                   Dashboard (React · 158 pages)              │
│    Situations Queue · Agent Monitor · SOC Assistant · DLP     │
├──────────────────────────────────────────────────────────────┤
│                   API Gateway (FastAPI · 749 endpoints)       │
│         JWT Auth · Rate Limiting · Tenant Isolation           │
├─────────────┬──────────────┬──────────────┬──────────────────┤
│ Agent       │  SOC Brain   │ MCP Security │ AI Runtime       │
│ Firewall    │  Investigate │ God Key      │ Guardian         │
│ Intercept   │  Correlate   │ Detection    │ Prompt Shield    │
│ Enforce     │  Respond     │ Zero-Trust   │ Model Behavior   │
├─────────────┴──────────────┴──────────────┴──────────────────┤
│                   Policy Engine (OPA · Rego)                  │
│        HIPAA · SOC 2 · PCI-DSS · GDPR · FedRAMP             │
├──────────────────────────────────────────────────────────────┤
│              Agent Orchestration (LangGraph · 151 agents)     │
│   Supervisor · Memory · Reflection · Cross-Vendor Correlation │
├──────────────────────────────────────────────────────────────┤
│            Observability Ingestion (OpenTelemetry)            │
│     Splunk · Datadog · Prometheus · CloudWatch · Elastic      │
├──────────────────────────────────────────────────────────────┤
│            Multi-Cloud & Vendor Connectors (18)               │
│  AWS · GCP · Azure · K8s · CrowdStrike · Defender · Wiz      │
│  Splunk · Elastic · Datadog · New Relic · PagerDuty · Jira    │
└──────────────────────────────────────────────────────────────┘
```

## Tech Stack

Python 3.12 · LangGraph · FastAPI · React 18 · TypeScript · Tailwind CSS · PostgreSQL · Redis · Kafka · OPA · OpenTelemetry · Pydantic v2 · structlog · Anthropic Claude (Haiku/Sonnet/Opus routing)

## Deployment

### Docker Compose (evaluation)

```bash
docker compose -f infrastructure/docker/docker-compose.yml up -d
```

### Kubernetes (Helm)

```bash
helm install shieldops infrastructure/helm/ \
  --namespace shieldops --create-namespace \
  --values infrastructure/helm/values-production.yaml
```

### Cloud (Terraform)

```bash
# AWS
cd infrastructure/terraform/aws && terraform apply

# GCP
cd infrastructure/terraform/gcp && terraform apply

# Azure
cd infrastructure/terraform/azure && terraform apply
```

See [docs/DEPLOYMENT_GUIDE.md](docs/DEPLOYMENT_GUIDE.md) for detailed multi-cloud deployment instructions.

## Development

```bash
pip install -e ".[dev]"           # Install dependencies
python3 -m pytest tests/ -v       # Run tests
ruff check src/ tests/ --fix      # Lint
ruff format src/ tests/           # Format
mypy src/shieldops/               # Type check
bandit -c pyproject.toml -ll -r src/  # Security scan
pre-commit run --all-files        # All hooks

# Start servers
uvicorn shieldops.api.main:app --reload   # API
cd dashboard-ui && npm run dev            # Dashboard
```

## Project Structure

```
ShieldOps/
├── CLAUDE.md                    # Root project instructions
├── src/shieldops/
│   ├── agents/                  # 151 LangGraph agents
│   ├── api/                     # FastAPI (749 endpoints)
│   ├── security/                # 518 security engines
│   ├── analytics/               # 255 analytics engines
│   ├── observability/           # 232 telemetry engines
│   ├── operations/              # 160 operations engines
│   ├── compliance/              # 116 compliance engines
│   ├── connectors/              # 18 vendor connectors
│   ├── sdk/                     # Agent Firewall SDK
│   ├── db/                      # Database (SQLAlchemy + Alembic)
│   ├── policy/                  # OPA policy engine
│   └── utils/                   # LLM integration, routing
├── dashboard-ui/                # React dashboard (158 pages)
├── tests/                       # 1,961 test files
├── infrastructure/              # Docker, K8s, Terraform, Helm
└── docs/                        # Documentation
```

## Docs

| Document | Description |
|----------|-------------|
| [CLAUDE.md](CLAUDE.md) | Root project instructions (+ 28 modular CLAUDE.md files) |
| [Deployment Guide](docs/DEPLOYMENT_GUIDE.md) | AWS, GCP, Azure, On-Prem deployment |
| [Production Runbook](docs/PRODUCTION_LAUNCH_RUNBOOK.md) | 8-phase launch guide |
| [Task Tracker](docs/tasks.md) | Phase 142-157 history |
| [CrowdStrike Disruption Plan](docs/strategy/crowdstrike-disruption-plan.md) | 5-phase competitive strategy |
| [API Docs](http://localhost:8000/api/v1/docs) | Interactive OpenAPI (when running) |

## Contributing

1. Fork the repository
2. Create a feature branch (`feat/your-feature`)
3. Write tests for new functionality
4. Ensure `ruff check` and `pytest` pass
5. Submit a pull request

Follow [conventional commits](https://www.conventionalcommits.org/) for commit messages.

## License

Apache 2.0 — see [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>ShieldOps</strong> — The security control plane for AI agents.
</p>
