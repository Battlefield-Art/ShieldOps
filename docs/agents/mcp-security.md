# MCP Security Agent

The MCP Security Agent monitors, secures, and enforces zero-trust policies across all
Model Context Protocol (MCP) server connections. It detects God Key credentials,
scans for supply chain vulnerabilities, and operates an inline security gateway for
MCP traffic.

---

## Purpose

- Monitor all MCP server connections for security posture and compliance
- Detect and alert on God Key credentials (overly broad MCP permissions)
- Scan MCP server dependencies for supply chain vulnerabilities
- Enforce zero-trust principles: mTLS, credential rotation, least-privilege
- Operate an inline security gateway for real-time MCP traffic inspection
- Detect tool poisoning attempts and rug-pull attacks on MCP tools

---

## Architecture

```
┌──────────────┐     ┌──────────────────────┐     ┌──────────────┐
│  AI Agent    │────▶│  MCP Security Gateway │────▶│  MCP Server  │
│  (client)    │◀────│  (TLS termination,    │◀────│  (tools,     │
│              │     │   policy enforcement) │     │   resources)  │
└──────────────┘     └──────────┬───────────┘     └──────────────┘
                                │
                    ┌───────────┼───────────┐
                    ▼           ▼           ▼
            ┌────────────┐ ┌─────────┐ ┌──────────────┐
            │ God Key    │ │ Supply  │ │ Zero-Trust   │
            │ Detector   │ │ Chain   │ │ Compliance   │
            │            │ │ Scanner │ │ Engine       │
            └────────────┘ └─────────┘ └──────────────┘
```

### LangGraph Nodes

| Node | Description |
|------|-------------|
| `discover_mcp_servers` | Enumerate all registered and discovered MCP server endpoints |
| `scan_credentials` | Analyze credential scope and detect God Key (excessive permission) patterns |
| `scan_supply_chain` | Check MCP server dependencies against vulnerability databases |
| `evaluate_zero_trust` | Assess each server against zero-trust checklist (mTLS, rotation, scoping) |
| `inspect_traffic` | Analyze MCP request/response patterns for tool poisoning indicators |
| `score_compliance` | Compute per-server and aggregate compliance scores |
| `generate_findings` | Produce prioritized findings with remediation guidance |

---

## Key Features

### Security Gateway
An inline proxy that terminates TLS, inspects MCP JSON-RPC traffic, and enforces
security policies before forwarding requests to MCP servers. Supports both stdio
and SSE transport modes.

### God Key Detection
Identifies MCP credentials with overly broad permissions that grant unrestricted access
to tools and resources. Uses permission graph analysis to detect implicit privilege
escalation paths.

### Supply Chain Scanning
Scans MCP server packages and their transitive dependencies against CVE databases.
Monitors for known-malicious packages, typosquatting, and dependency confusion attacks.

### Zero-Trust Enforcement
Ensures all MCP connections use mTLS, credentials are rotated on schedule, server
identities are verified, and each connection follows the principle of least privilege.
Non-compliant servers can be blocked or quarantined.

### Tool Poisoning Detection
Analyzes MCP tool definitions for signs of poisoning: unexpected tool description
changes between versions, hidden instructions in tool schemas, and rug-pull patterns
where tool behavior changes after initial trust is established.

---

## MCP Transport Support

| Transport | Gateway Mode | Description |
|-----------|-------------|-------------|
| stdio | Sidecar | Gateway runs as sidecar process, wrapping stdio communication |
| SSE | Inline proxy | Gateway operates as HTTP reverse proxy with SSE pass-through |
| Streamable HTTP | Inline proxy | Gateway operates as HTTP reverse proxy |

---

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_GATEWAY_MODE` | `monitor` | Mode: `monitor`, `enforce`, `block_all` |
| `MCP_GATEWAY_PORT` | `8443` | Gateway listener port |
| `MCP_ZERO_TRUST_LEVEL` | `standard` | Enforcement: `basic`, `standard`, `strict` |
| `MCP_SUPPLY_CHAIN_SCAN_INTERVAL` | `24h` | Frequency of dependency scans |
| `MCP_CREDENTIAL_ROTATION_MAX_DAYS` | `90` | Maximum credential age before alert |
| `MCP_TOOL_POISONING_DETECTION` | `true` | Enable tool definition change detection |
| `MCP_GOD_KEY_AUTO_REMEDIATE` | `false` | Auto-scope-down God Keys (requires approval) |

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/mcp-security/servers` | List monitored MCP servers with posture |
| `GET` | `/api/v1/mcp-security/servers/{id}` | Server details, compliance score, findings |
| `POST` | `/api/v1/mcp-security/scan` | Trigger on-demand security scan |
| `GET` | `/api/v1/mcp-security/god-keys` | List detected God Key credentials |
| `GET` | `/api/v1/mcp-security/supply-chain/vulnerabilities` | Supply chain vulnerability report |
| `GET` | `/api/v1/mcp-security/compliance/summary` | Zero-trust compliance summary |
| `POST` | `/api/v1/mcp-security/gateway/policy` | Update gateway enforcement policy |

---

## Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `shieldops_mcp_servers_total` | Gauge | Total monitored MCP servers |
| `shieldops_mcp_god_keys_total` | Gauge | Servers with God Key credentials |
| `shieldops_mcp_supply_chain_vulnerabilities_total` | Gauge | Open supply chain vulnerabilities |
| `shieldops_mcp_zero_trust_compliant_total` | Gauge | Servers meeting zero-trust requirements |
| `shieldops_mcp_gateway_requests_total` | Counter | Gateway requests by action (allowed, blocked) |
| `shieldops_mcp_tool_poisoning_attempts_total` | Counter | Tool poisoning attempts detected |

---

## Integration with Other Agents

MCP Security findings feed into the [SOC Brain](soc-brain.md) as security situations
when critical vulnerabilities or active attacks are detected. God Key remediation
actions are executed via the [Remediation Agent](remediation.md) with human-in-the-loop
approval. Supply chain findings inform the [Compliance Auditor](compliance-auditor.md).
