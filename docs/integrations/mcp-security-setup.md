# MCP Security Gateway Setup Guide

The Model Context Protocol (MCP) Security Gateway protects your AI agent
infrastructure by enforcing access policies, detecting compromised tool
servers, and preventing supply-chain attacks on MCP connections.

## Prerequisites

- MCP servers deployed and accessible over `stdio` or `sse` transport
- ShieldOps platform running with `MCP_SECURITY_ENABLED=true`
- Admin access to configure gateway policies
- Network visibility between MCP clients and servers

---

## Step 1: Register MCP Servers

Register each MCP server that your agents connect to. This creates an
inventory for policy enforcement and anomaly detection.

```bash
curl -X POST https://your-shieldops.com/api/v1/mcp/servers \
  -H "Authorization: Bearer sk-your-shieldops-key" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "filesystem-server",
    "transport": "stdio",
    "command": "npx",
    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"],
    "allowed_tools": ["read_file", "write_file", "list_directory"],
    "trust_level": "verified",
    "owner_team": "platform-engineering"
  }'
```

Register all servers your organization uses:

```bash
# Database server
curl -X POST https://your-shieldops.com/api/v1/mcp/servers \
  -H "Authorization: Bearer sk-your-shieldops-key" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "postgres-server",
    "transport": "stdio",
    "command": "npx",
    "args": ["-y", "@modelcontextprotocol/server-postgres", "postgresql://..."],
    "allowed_tools": ["query"],
    "trust_level": "verified",
    "owner_team": "data-engineering",
    "restrictions": {
      "read_only": true,
      "max_rows": 1000,
      "blocked_tables": ["users_pii", "credentials"]
    }
  }'
```

Verify registration:

```bash
curl https://your-shieldops.com/api/v1/mcp/servers \
  -H "Authorization: Bearer sk-your-shieldops-key"
```

---

## Step 2: Configure Gateway Policies

Gateway policies define what MCP tool calls are allowed, denied, or
require human approval.

### Create a Base Policy

```bash
curl -X POST https://your-shieldops.com/api/v1/mcp/policies \
  -H "Authorization: Bearer sk-your-shieldops-key" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "production-mcp-policy",
    "description": "Restrict MCP tool usage in production",
    "rules": [
      {
        "action": "deny",
        "condition": "tool.name matches write_* AND server.trust_level != verified",
        "reason": "Write operations require verified servers"
      },
      {
        "action": "require_approval",
        "condition": "tool.name == execute_query AND query contains DROP|DELETE|TRUNCATE",
        "reason": "Destructive database operations require human approval"
      },
      {
        "action": "allow",
        "condition": "tool.name matches read_* AND server.trust_level in [verified, trusted]",
        "reason": "Read operations allowed on trusted servers"
      },
      {
        "action": "deny",
        "condition": "server.trust_level == untrusted",
        "reason": "Untrusted servers are blocked entirely"
      }
    ],
    "default_action": "audit"
  }'
```

### Policy Rule Syntax

| Field | Description |
|-------|-------------|
| `action` | `allow`, `deny`, `require_approval`, or `audit` |
| `condition` | Expression matching tool name, server trust level, arguments, etc. |
| `reason` | Human-readable explanation (included in audit logs) |

---

## Step 3: Validate God Key Detection

The "god key" detector identifies MCP servers or tool calls that request
overly broad permissions, potentially compromising the entire agent.

### Run a Detection Scan

```bash
curl -X POST https://your-shieldops.com/api/v1/mcp/security/god-key-scan \
  -H "Authorization: Bearer sk-your-shieldops-key" \
  -H "Content-Type: application/json" \
  -d '{
    "scan_scope": "all_registered_servers"
  }'
```

### Review Results

```bash
curl https://your-shieldops.com/api/v1/mcp/security/god-key-scan/latest \
  -H "Authorization: Bearer sk-your-shieldops-key"
```

Example response:

```json
{
  "scan_id": "scan-20260325-001",
  "findings": [
    {
      "severity": "critical",
      "server": "custom-admin-server",
      "finding": "Server exposes shell_execute tool with no argument restrictions",
      "recommendation": "Add argument allowlist or remove tool from production"
    }
  ],
  "servers_scanned": 5,
  "clean_servers": 4,
  "at_risk_servers": 1
}
```

---

## Step 4: Run Supply Chain Scan

Detect compromised or tampered MCP server packages before they reach
your agents.

```bash
curl -X POST https://your-shieldops.com/api/v1/mcp/security/supply-chain-scan \
  -H "Authorization: Bearer sk-your-shieldops-key" \
  -H "Content-Type: application/json" \
  -d '{
    "scan_type": "full",
    "checks": [
      "package_integrity",
      "known_vulnerabilities",
      "permission_drift",
      "tool_schema_changes"
    ]
  }'
```

The scan verifies:

- **Package integrity**: npm/pip package checksums match expected values
- **Known vulnerabilities**: Cross-reference with CVE databases
- **Permission drift**: Tools or capabilities changed since last scan
- **Tool schema changes**: Unexpected modifications to tool input schemas

---

## Step 5: Enable Zero-Trust Enforcement

Zero-trust mode treats every MCP tool call as potentially hostile until
verified by policy.

```bash
curl -X PUT https://your-shieldops.com/api/v1/mcp/security/config \
  -H "Authorization: Bearer sk-your-shieldops-key" \
  -H "Content-Type: application/json" \
  -d '{
    "zero_trust_enabled": true,
    "settings": {
      "require_server_verification": true,
      "tool_call_signing": true,
      "argument_sanitization": true,
      "max_tool_calls_per_minute": 100,
      "session_timeout_minutes": 30,
      "anomaly_detection": {
        "enabled": true,
        "baseline_window_hours": 168,
        "sensitivity": "medium"
      }
    }
  }'
```

### What Zero-Trust Enforces

| Check | Description |
|-------|-------------|
| Server verification | Every MCP server must be registered and trusted |
| Tool call signing | Cryptographic signature on each tool invocation |
| Argument sanitization | Strip injection patterns from tool arguments |
| Rate limiting | Per-agent, per-server call rate limits |
| Anomaly detection | Flag unusual tool call patterns vs. baseline |
| Session isolation | Each agent session has an independent trust boundary |

---

## Step 6: Monitor Gateway Dashboard

Access the MCP Security Gateway dashboard at:

```
https://your-shieldops.com/app/mcp-security
```

The dashboard shows:

- **Real-time tool call stream**: Every MCP invocation with risk scores
- **Policy violations**: Blocked or flagged calls with reasons
- **Server health**: Connection status, latency, error rates per server
- **Anomaly timeline**: Detected behavioral deviations over time
- **Supply chain status**: Last scan results and package integrity scores

### Set Up Alerts

```bash
curl -X POST https://your-shieldops.com/api/v1/mcp/alerts \
  -H "Authorization: Bearer sk-your-shieldops-key" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "mcp-critical-alert",
    "conditions": [
      "god_key_detected",
      "supply_chain_compromise",
      "anomaly_score > 0.9"
    ],
    "channels": ["slack", "pagerduty"],
    "severity": "critical"
  }'
```

---

## Configuration Reference

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_SECURITY_ENABLED` | `false` | Enable MCP Security Gateway |
| `MCP_ZERO_TRUST` | `false` | Enable zero-trust enforcement |
| `MCP_SCAN_INTERVAL_HOURS` | `24` | Supply chain scan frequency |
| `MCP_ANOMALY_SENSITIVITY` | `medium` | `low`, `medium`, or `high` |
| `MCP_MAX_SERVERS` | `50` | Maximum registered MCP servers |
| `MCP_AUDIT_RETENTION_DAYS` | `90` | Audit log retention period |

### Server Trust Levels

| Level | Description | Allowed Actions |
|-------|-------------|-----------------|
| `verified` | Audited and signed by ShieldOps | All policy-permitted actions |
| `trusted` | Registered with known source | Read operations, limited writes |
| `untrusted` | Unknown or unverified source | Blocked in zero-trust mode |

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| All MCP calls blocked | Zero-trust enabled with no registered servers | Register servers (Step 1) before enabling zero-trust |
| God key scan returns empty | No servers registered | Register servers first |
| High false positive rate | Anomaly sensitivity too high | Set `MCP_ANOMALY_SENSITIVITY=low` and retrain baseline |
| Server shows as untrusted | Registration expired or package updated | Re-register server and run supply chain scan |
| Policy not applying | Policy not attached to environment | Verify policy scope matches your deployment environment |
| Gateway latency > 100ms | Too many inline policy checks | Enable async policy evaluation for non-critical tools |
