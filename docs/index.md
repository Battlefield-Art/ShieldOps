# ShieldOps

**The Security Control Plane for AI Agents**

> AI agents are bypassing traditional security. ShieldOps intercepts, governs, and defends.

ShieldOps is an AI Security Control Plane that governs, monitors, and responds to AI agent
activity across enterprise infrastructure. The platform deploys 395 autonomous LangGraph agents
for runtime interception, non-human identity governance, MCP ecosystem security, SOC automation,
and self-evolving defense -- across multi-cloud (AWS/GCP/Azure) and on-premise environments.

Unlike existing tools that only *analyze*, ShieldOps agents *act* -- with policy-gated
safety, full audit trails, and one-click rollback.

---

## Key Features

- **AI Agent Firewall** -- Runtime interception of every AI agent tool call
- **Non-Human Identity Governance** -- Discover and govern NHIs, shadow AI, service accounts
- **MCP Ecosystem Security** -- God Key detection, supply chain scanning, zero-trust
- **Autonomous SOC** -- Cross-vendor AI-driven detection, triage, and response
- **Self-Evolving Agents** -- Fitness tracking, prompt A/B testing, cross-agent learning
- **Policy-Gated Remediation** -- Every action evaluated by OPA before execution
- **Multi-Cloud Support** -- AWS, GCP, Azure, Kubernetes, 17 vendor connectors
- **Defense in Depth** -- Five-layer safety model with snapshot and rollback

## How It Works

```
Alert Fires --> Investigation Agent --> Root Cause Hypothesis
                                              |
                                  confidence > 0.85?
                                 /                  \
                              Yes                     No
                               |                       |
                        Remediation Agent         Escalate to Human
                               |                  (with full context)
                        Policy Check (OPA)
                               |
                        Execute + Validate
                               |
                        Success --> Learn
                        Failure --> Rollback + Escalate
```

## Architecture at a Glance

```
+-----------------------------------------------------+
|  Layer 4: Policy & Safety                            |
|  OPA policies . Approval workflows . Rollback        |
|  Compliance reporting . Blast-radius limits          |
+-----------------------------------------------------+
|  Layer 3: Agent Orchestration (LangGraph)            |
|  Investigation . Remediation . Security . Learning   |
|  Supervisor agent . Multi-agent coordination         |
+-----------------------------------------------------+
|  Layer 2: Observability Ingestion                    |
|  OpenTelemetry . Splunk . Datadog . Prometheus       |
|  Vendor-neutral telemetry . No rip-and-replace       |
+-----------------------------------------------------+
|  Layer 1: Multi-Environment Connectors               |
|  AWS . GCP . Azure . Kubernetes . Linux (SSH)        |
|  Unified interface . Write once, deploy anywhere     |
+-----------------------------------------------------+
```

## Quick Links

| Section | Description |
|---------|-------------|
| [Quick Start](getting-started/quickstart.md) | Get ShieldOps running locally in 5 minutes |
| [Architecture Overview](architecture/overview.md) | System design, ADRs, and layer descriptions |
| [Agent Reference](agents/investigation.md) | Detailed agent documentation and graph workflows |
| [API Reference](api/authentication.md) | REST API endpoints with request/response examples |
| [Deployment Guide](deployment/local.md) | Local, Kubernetes, Helm, and multi-cloud deployment |
| [Contributing](contributing/setup.md) | Development setup, code style, and testing |

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3.12+ |
| Agent Framework | LangGraph |
| LLM | Anthropic Claude (primary), OpenAI (fallback) |
| API | FastAPI |
| Dashboard | React + TypeScript + Tailwind CSS |
| Database | PostgreSQL (state), Redis (coordination) |
| Messaging | Apache Kafka |
| Infrastructure | Kubernetes, Terraform |
| Observability | OpenTelemetry, LangSmith |
| Policy Engine | Open Policy Agent (OPA) |
| CI/CD | GitHub Actions |
