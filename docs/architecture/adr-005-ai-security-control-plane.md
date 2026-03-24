# ADR-005: AI Security Control Plane Architecture

**Status:** Accepted

**Date:** 2026-03-24

**Authors:** ShieldOps Engineering

---

## Context

The rise of autonomous AI agents in enterprise infrastructure has created a security gap that traditional tools cannot address:

1. **AI agents bypass endpoint security.** Tools like CrowdStrike Falcon and Microsoft Defender monitor human-initiated processes, file system changes, and network connections. AI agents operate through API calls, SDK invocations, and MCP server interactions — none of which trigger traditional EDR detections. An AI agent can exfiltrate data through a tool call to an MCP server without any endpoint alert firing.

2. **Non-human identities (NHIs) outnumber humans 100:1.** Service accounts, API keys, OAuth apps, bot tokens, and machine certificates proliferate across cloud environments. Most lack proper lifecycle management, rotation policies, or usage monitoring. Shadow AI — unauthorized LLM API keys and unregistered automation — compounds the problem.

3. **MCP creates a new attack surface.** The Model Context Protocol enables AI agents to discover and invoke tools dynamically. This introduces supply chain risks (malicious MCP servers), privilege escalation paths (overly broad tool permissions), and "God Key" vulnerabilities (single credentials granting unrestricted cross-server access).

4. **SOC teams lack AI-native visibility.** Security Operations Centers have no unified view of AI agent activity across their infrastructure. Alert correlation across CrowdStrike, Defender, Wiz, and Splunk remains manual. AI-specific threats (prompt injection, tool call abuse, behavioral drift) have no detection coverage.

## Decision

Build ShieldOps as a **three-tier AI Security Control Plane** that governs AI agent activity across existing security tools, rather than replacing them.

### Three-Tier Insertion Model

| Tier | Scope | Components |
|------|-------|------------|
| **Orchestration Layer** | LLM reasoning, agent goals, prompt flow | Agent Behavioral Firewall, Kill Switch, Prompt Injection Detection, LLM Firewall |
| **Tool/Action Layer** | APIs, MCP servers, databases, infrastructure | MCP Security Gateway, Zero-Trust Enforcer, Tool Call Interceptor, Supply Chain Scanner |
| **Data/Identity Layer** | Credentials, RAG data, permissions, secrets | NHI Registry, Shadow AI Discovery, JIT Credential Issuer, Identity Risk Engine |

### Core Product Modules

1. **Agent Behavioral Firewall** — Runtime interception of AI agent tool calls via SDK (LangChain, CrewAI, LlamaIndex). Establishes behavioral baselines per agent and detects anomalies (unusual tool access patterns, rate spikes, first-time sensitive operations). Supports audit mode (observe only) and enforce mode (block risky calls). Kill switch for immediate agent termination.

2. **NHI Governance** — Discovers and inventories all non-human identities across cloud providers (AWS IAM, Azure AD, GCP Service Accounts, GitHub tokens, Slack bots). Monitors identity posture (credential age, permission scope, usage patterns). Detects shadow AI (unauthorized LLM API keys, unregistered MCP clients). Issues JIT (just-in-time) credentials with automatic expiration.

3. **MCP Security** — Secures the MCP server ecosystem. Operates a security gateway that validates all MCP connections. Scans MCP server supply chains for vulnerabilities. Enforces zero-trust policies (mutual TLS, least-privilege tool access, connection allowlisting). Detects "God Key" configurations where single credentials grant unrestricted cross-server access.

4. **SOC Automation** — Cross-vendor AI-driven security operations. The SOC Brain agent correlates findings from CrowdStrike, Microsoft Defender, Wiz, Splunk, and other vendors into unified Situations. Automates triage, containment, and remediation with confidence-gated execution.

### Deployment Model

SDK-first: customers integrate via a one-line callback handler in their AI agent framework. No infrastructure changes required for initial value.

```python
from shieldops.sdk.langchain import ShieldOpsCallbackHandler
agent = create_agent(callbacks=[ShieldOpsCallbackHandler(api_key="sk-...")])
```

### Security Vendor Integration

ShieldOps operates as a vendor-neutral orchestrator above existing security tools:

| Vendor | Integration | Purpose |
|--------|------------|---------|
| CrowdStrike Falcon | OAuth2 + RTR + Threat Graph | Endpoint telemetry, containment actions |
| Microsoft Defender | MSAL + KQL advanced hunting | Identity signals, cloud app security |
| Wiz | GraphQL + Security Graph | Cloud posture, attack paths, IAM analysis |
| Splunk / Datadog / OTEL | Telemetry ingestion | Log correlation, metric analysis |

## Consequences

### Positive

- **Vendor-neutral positioning.** ShieldOps sits above CrowdStrike, Defender, and Wiz rather than competing with them. Customers keep their existing security stack and add ShieldOps as the AI governance layer.
- **SDK-first deployment.** Zero infrastructure changes for initial integration. Customers add a callback handler to their AI agents and immediately get tool call auditing, behavioral baselines, and policy enforcement.
- **MCP as differentiated attack surface.** No existing security vendor covers MCP ecosystem risks (God Keys, supply chain, zero-trust). This is a greenfield market position.
- **NHI governance fills a critical gap.** The 100:1 ratio of non-human to human identities is a widely acknowledged problem with few purpose-built solutions. Combining NHI governance with AI agent security creates a unique value proposition.
- **Existing engine and agent infrastructure reusable.** The 58 LangGraph agents, 1,562+ engine modules, and OPA policy framework built for SRE operations directly support the security control plane use case.

### Negative

- **Breadth of integration surface.** Supporting LangChain, CrewAI, LlamaIndex, and arbitrary MCP clients requires ongoing SDK maintenance as these frameworks evolve rapidly.
- **Vendor API dependencies.** CrowdStrike, Defender, and Wiz integrations depend on vendor API stability and rate limits. Changes to their APIs require connector updates.
- **Trust boundary complexity.** As a security governance layer, ShieldOps itself becomes a high-value target. The platform must maintain the highest security standards (SOC 2 Type II, penetration testing, supply chain security) to be credible.

### Risks Mitigated

- AI agents operating without security oversight
- Non-human identity sprawl and shadow AI proliferation
- MCP ecosystem supply chain attacks and privilege escalation
- Manual SOC correlation across disparate security vendors

## Alternatives Considered

### 1. Stay as SRE-only platform
Rejected. The SRE market is commoditizing with multiple autonomous remediation tools. AI security governance is a newer, less contested market with higher enterprise urgency.

### 2. Build a standalone NHI product
Rejected. NHI governance alone is valuable but narrow. Combining it with agent behavioral firewalling and MCP security creates a platform play with multiple expansion vectors.

### 3. Partner with an existing CSPM vendor
Rejected. CSPM vendors (Wiz, Orca, Lacework) focus on cloud posture, not AI agent runtime behavior. Integration (not replacement) is the correct relationship — ShieldOps consumes their signals and orchestrates responses.
