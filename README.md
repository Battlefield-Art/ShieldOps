<p align="center">
  <img src="dashboard-ui/public/favicon.svg" width="48" height="48" alt="ShieldOps" />
</p>

<h1 align="center">ShieldOps</h1>
<p align="center"><strong>The security control plane for AI agents</strong></p>

<p align="center">
  <a href="#quick-start">Quick Start</a> ·
  <a href="#product-modules">Modules</a> ·
  <a href="#capabilities">Capabilities</a> ·
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
| Autonomous LangGraph agents | **448** |
| Security & analytics engines | **1,780** |
| Dashboard pages | **455** |
| API route files | **888** |
| Cloud/vendor connectors | **17** |
| Test files | **2,214** |
| OPA policies | 10+ (HIPAA, SOC 2, PCI-DSS, GDPR, FedRAMP) |

## Product Modules

| Module | What It Does | Key Features |
|--------|-------------|--------------|
| **Agent Firewall** | Runtime interception of AI agent tool calls | Behavioral baselines, circuit breaker, kill switch, audit |
| **NHI Registry** | Discover and govern non-human identities | Shadow AI detection, posture monitoring, JIT credentials |
| **MCP Security** | Secure MCP server ecosystem | God Key detection, supply chain scanning, zero-trust |
| **SOC Brain** | Cross-vendor AI-driven security operations | Situations queue, auto-triage, closed-loop learning |
| **Agentic MDR** | Machine-speed managed detection & response | Vendor-neutral, <5min MTTR, 97%+ accuracy |
| **AI Runtime Guardian** | Comprehensive AI runtime protection | Prompt injection, model behavior, tool abuse, output sanitization |
| **Situation Manager** | Outcome-centric alert management | Hundreds of alerts → actionable situations with narratives |
| **Cross-Vendor Correlator** | Unified signal correlation across vendors | Multi-vendor normalization to OCSF, kill chain mapping |
| **Agent Memory Store** | Persistent episodic memory for agents | Cross-agent learning, FP pattern recall |
| **Reflection Engine** | Agent self-evaluation & improvement | "Did my action work?" threshold auto-tuning |
| **Agent Evolution** | Self-evolving agent fleet | Fitness tracking, prompt A/B testing, cross-agent learning |
| **Cloud Cost Optimizer** | Multi-cloud billing analysis | Savings identification, rightsizing, waste detection |
| **Infrastructure Drift Detector** | IaC baseline drift detection | Compare actual vs. declared state, auto-remediate |

## Capabilities

### Detection & Response
| Capability | Agent | Key Differentiator |
|---|---|---|
| Vendor-neutral MDR | `agentic_mdr` | Works across any EDR/SIEM/identity provider |
| Autonomous 24/7 threat hunting | `managed_threat_hunting` | AI-driven, no human analyst dependency |
| AI SOC assistant | `ai_soc_assistant` | Natural language investigation, cross-vendor context |
| Multi-IdP identity protection | `identity_protection` | Covers all identity providers + AI agent identities |
| AI-native log analytics | `log_intelligence` | LLM reasoning across any log source |
| Scanless vulnerability assessment | `vulnerability_intelligence` | Uses existing telemetry, no active scanning |
| Sub-5-min breakout containment | `breakout_defender` | Automated containment with cross-cloud detection |

### Extended Detection & Response (XDR)
| Capability | Agent | Key Differentiator |
|---|---|---|
| Autonomous XDR | `autonomous_xdr` | Correlates ANY endpoint/network/cloud/identity source |
| Autonomous SOC | `autonomous_soc` | Open AI-native SOC, works with existing SIEM |
| Intelligent SOAR | `intelligent_soar` | LangGraph-native adaptive playbooks |
| Cross-vendor correlation | `cross_vendor_correlator` | OCSF normalization across 8+ vendors |

### Cloud & Infrastructure Security
| Capability | Agent | Key Differentiator |
|---|---|---|
| Unified cloud security | `unified_cloud_security` | CSPM+CWPP+CDR+CIEM+DSPM, multi-cloud |
| CNAPP analysis | `cnapp_analyzer` | Unified posture + workload + identity + code |
| Zero trust network access | `zero_trust_network` | Identity-first ZTNA for humans + AI agents + NHIs |
| IoT/OT security | `iot_ot_security` | Device discovery + behavioral profiling + segmentation |
| IT asset intelligence | `it_asset_intelligence` | Security + IT asset convergence with AI risk context |

### AI Security
| Capability | Agent | Key Differentiator |
|---|---|---|
| AI runtime protection | `ai_runtime_guardian` | Prompt/model/tool/agent/output guardrails |
| Prompt injection defense | `prompt_shield` | Multi-layer: regex + semantic + behavioral + LLM |
| Model security | `model_security` | Integrity verification, backdoor detection, provenance |
| AI supply chain scanning | `supply_chain_scanner` | RAG poisoning, model registry, prompt template integrity |
| Multi-agent security | `multi_agent_security` | Trust chains, communication auditing, impersonation detection |
| AI compliance | `ai_compliance` | EU AI Act, NIST AI RMF, ISO 42001 automated evidence |

### Data Protection & Recovery
| Capability | Agent | Key Differentiator |
|---|---|---|
| Data loss prevention | `data_loss_prevention` | Cross-surface DLP including AI pipelines + MCP tools |
| Endpoint DLP | `endpoint_dlp` | Clipboard, USB, AI prompt paste, screen capture |
| Cyber recovery | `cyber_recovery` | Clean room validation, ransomware-safe restore |
| Data resilience | `data_resilience` | Immutable protection for databases + AI models |
| Air-gap vault | `air_gap_vault` | Air-gapped storage with continuous integrity |
| Ransomware forensics | `ransomware_forensics` | LLM-powered forensics + blast radius prediction |
| Sensitive data monitoring | `sensitive_data_monitor` | Continuous classification including AI pipeline data |

### Agentic Best Practices
| Capability | Agent | Key Differentiator |
|---|---|---|
| Agent memory | `agent_memory_store` | Persistent episodic memory across all agents |
| Self-reflection | `reflection_engine` | Retrospective analysis + automatic threshold tuning |
| Trust mapping | `trust_relationship_mapper` | Federation, delegation, cross-account trust chains |
| Security app builder | `security_app_builder` | Generate LangGraph apps from natural language |
| Situation management | `situation_manager` | Outcome-centric queue replacing alert dashboards |

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
│                   Dashboard (React · 455 pages)              │
│    Situations Queue · Agent Monitor · SOC Assistant · DLP     │
├──────────────────────────────────────────────────────────────┤
│                   API Gateway (FastAPI · 888 routes)          │
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
│              Agent Orchestration (LangGraph · 448 agents)     │
│   Supervisor · Memory · Reflection · Cross-Vendor Correlation │
├──────────────────────────────────────────────────────────────┤
│            Observability Ingestion (OpenTelemetry)            │
│          Multi-vendor telemetry normalization (OCSF)          │
├──────────────────────────────────────────────────────────────┤
│            Multi-Cloud & Vendor Connectors (17)               │
│     AWS · GCP · Azure · K8s · EDR · SIEM · IdP · ITSM       │
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

### Cloud (Native)

| Cloud | Tool | Command |
|-------|------|---------|
| AWS | CDK | `cd infrastructure/aws-cdk && cdk deploy --all` |
| AWS | CloudFormation | `aws cloudformation deploy --template-file template.yaml` |
| GCP | gcloud CLI | `cd infrastructure/gcp-native && ./deploy.sh` |
| Azure | Bicep | `cd infrastructure/azure-bicep && ./deploy.sh` |
| On-Prem | Ansible | `cd infrastructure/onprem-ansible && ansible-playbook playbook.yml` |

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
│   ├── agents/                  # 448 LangGraph agents
│   ├── api/                     # FastAPI (888 routes)
│   ├── security/                # 551 security engines
│   ├── analytics/               # 276 analytics engines
│   ├── observability/           # 232 telemetry engines
│   ├── operations/              # 177 operations engines
│   ├── compliance/              # 116 compliance engines
│   ├── connectors/              # 17 vendor connectors
│   ├── sdk/                     # Agent Firewall SDK
│   ├── db/                      # Database (SQLAlchemy + Alembic)
│   ├── policy/                  # OPA policy engine
│   └── utils/                   # LLM, routing, self-evolution
├── dashboard-ui/                # React dashboard (455 pages)
├── tests/                       # 2,214 test files
├── infrastructure/              # Docker, K8s, Terraform, CDK, Helm
└── docs/                        # Documentation
```

## Docs

| Document | Description |
|----------|-------------|
| [CLAUDE.md](CLAUDE.md) | Root project instructions (+ 29 modular CLAUDE.md files) |
| [Deployment Guide](docs/DEPLOYMENT_GUIDE.md) | AWS, GCP, Azure, On-Prem deployment |
| [Production Runbook](docs/PRODUCTION_LAUNCH_RUNBOOK.md) | 8-phase launch guide |
| [Task Tracker](docs/tasks.md) | Development phase history |
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
