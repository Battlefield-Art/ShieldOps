# ShieldOps — One Pager

**The Security Control Plane for AI Agents**

---

## The Problem

- **Agentic AI is the most dangerous new attack vector.** AI agents execute real actions — deleting databases, rotating credentials, deploying code — but existing security tools (EDR, SIEM, IAM) cannot see or govern agent-layer behavior.

- **Non-Human Identities outnumber humans 100:1.** Every AI agent, service account, and API key is an ungoverned identity with no behavioral baseline, no anomaly detection, and no lifecycle management.

- **MCP creates a "God Key" problem.** Model Context Protocol gives agents standardized tool access, but ships with zero authorization, zero audit trail, and zero permission scoping. One compromised MCP server = full tool access for an attacker.

---

## The Solution

### Agent Behavioral Firewall
Runtime interception for every tool call, API request, and LLM invocation. Risk-scored, policy-enforced, with configurable approval workflows. One-line SDK integration for LangChain, CrewAI, LlamaIndex.

### NHI Registry & Governance
Unified inventory of every non-human identity across AWS, GCP, Azure, and Kubernetes. Continuous behavioral baselining, anomaly detection, credential lifecycle automation.

### MCP Security Gateway
Protocol-level security for MCP — tool-level authorization, request inspection, immutable audit trail, rate limiting, and anomaly detection.

---

## Go-To-Market

**Developer-first adoption, enterprise-ready platform.**

1. **Open SDK** — `pip install shieldops` — developers add one line to secure any AI agent
2. **Free tier** — audit mode with full visibility, no enforcement limits
3. **Enterprise platform** — enforcement mode, approval workflows, compliance reporting, SOC integration
4. **Channel partnerships** — CrowdStrike (extend Falcon to agent layer), AWS (Bedrock security), cloud security resellers

---

## Traction

| Metric | Value |
|--------|-------|
| Autonomous AI agents | 50+ |
| Security/analytics engines | 375+ |
| Test coverage | 62,000+ tests |
| Cloud providers supported | AWS, GCP, Azure, Kubernetes |
| Observability integrations | Splunk, Datadog, Grafana, Dynatrace, Honeycomb |
| SOC integrations | PagerDuty, Slack, Teams, OpsGenie |

---

## Market

- **TAM:** $28B+ (AI security + cloud security + identity governance)
- **Timing:** AI agent adoption is inflecting now — every enterprise deploying agents needs runtime governance within 12 months
- **Regulatory tailwind:** EU AI Act, SEC cyber disclosure rules, and NIST AI RMF all require auditability of automated decisions

---

## Business Model

| Tier | Price | Includes |
|------|-------|---------|
| **Free** | $0 | Audit mode, 10K events/month, community support |
| **Pro** | $500/mo | Enforce mode, 1M events/month, approval workflows |
| **Enterprise** | Custom | Unlimited events, SSO/SCIM, compliance reports, SLA, dedicated support |

Usage-based expansion: per-agent, per-event pricing scales with adoption.

---

## Competitive Landscape

| Company | What They Do | What They Miss |
|---------|-------------|----------------|
| CrowdStrike | Endpoint/kernel security | Cannot see agent-layer API calls |
| Wiz | Cloud posture management | Static scanning, no runtime agent governance |
| Prompt Armor / Lakera | Prompt-level guardrails | Only governs LLM input/output, not tool execution |
| Astrix / Oasis | NHI management | Identity only — no runtime firewall or protocol security |

**ShieldOps is the only platform securing runtime + identity + protocol layers for AI agents.**

---

## Team

Engineering-led founders with deep expertise in cloud security, AI agent orchestration, and enterprise SRE. Built the full platform (50 agents, 375+ engines, production infrastructure) before raising.

---

## The Ask

**Pre-seed round: $2M**

- Hire 3 additional engineers (ML security, infrastructure, developer experience)
- Launch public SDK and free tier
- Close 5 design-partner enterprises
- SOC 2 Type II certification

---

## Contact

- **Web:** https://shieldops.io
- **Email:** founders@shieldops.io
- **GitHub:** https://github.com/shieldops
