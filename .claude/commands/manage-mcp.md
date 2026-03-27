# Manage MCP Skill

Manage Model Context Protocol security — MCP gateway policies, God Key detection, OAuth enforcement, and tool call governance.

## Usage
`/manage-mcp <action> [--server <name>] [--policy <name>] [--mode <audit|enforce>]`

Actions: `scan`, `gateway`, `govern`, `monitor`, `audit`, `status`

## Agents Used
- `mcp_security` — MCP ecosystem security with God Key detection
- `mcp_gateway` — MCP gateway with OAuth enforcement and tool call filtering
- `agent_firewall` — Runtime tool call interception for MCP tools
- `prompt_shield` — Prompt injection defense for MCP tool inputs

## Process

### Scan (MCP Security Assessment)
1. **Discover MCP servers**: Enumerate connected MCP servers and tools
2. **Assess permissions**: Review tool permissions and access scopes
3. **Detect God Keys**: Identify overprivileged MCP credentials
4. **Check OAuth**: Verify OAuth compliance for MCP connections
5. **Report**: Generate MCP security posture report

```python
from shieldops.agents.mcp_security.runner import MCPSecurityRunner

runner = MCPSecurityRunner()
result = await runner.scan(
    discover_servers=True,
    check_god_keys=True,
    check_oauth=True,
    check_tool_permissions=True,
)
```

### Gateway (MCP Gateway Management)
1. **Configure policies**: Define allowed/blocked tools per MCP server
2. **Set OAuth**: Enforce OAuth 2.0 for all MCP connections
3. **Filter tool calls**: Apply content-based filtering to tool inputs/outputs
4. **Rate limit**: Set per-client, per-tool rate limits

```python
from shieldops.agents.mcp_gateway.runner import MCPGatewayRunner

runner = MCPGatewayRunner()
result = await runner.configure(
    server="my-mcp-server",
    policies={
        "allowed_tools": ["read_file", "search", "query"],
        "blocked_tools": ["delete_file", "exec_command", "modify_permissions"],
        "require_oauth": True,
        "rate_limit_per_minute": 100,
    },
)
```

### Govern (Tool Call Governance)
1. **Define boundaries**: Set per-tool permission boundaries
2. **Input validation**: Validate tool call inputs against schemas
3. **Output filtering**: Filter sensitive data from tool outputs
4. **Audit logging**: Log all tool calls with full context

### Monitor (Runtime Monitoring)
1. **Track tool usage**: Monitor MCP tool call patterns and volumes
2. **Detect anomalies**: Identify unusual tool call patterns
3. **Alert**: Real-time alerts for suspicious MCP activity
4. **Dashboard**: MCP security dashboard with tool call analytics

### Audit (MCP Audit)
1. **Review connections**: Audit all active MCP connections
2. **Permission review**: Verify tool permissions match least-privilege
3. **Credential rotation**: Check MCP credential rotation status
4. **Compliance**: Verify MCP usage meets compliance requirements

## Key MCP Security Concerns

### God Key Detection
- **What**: Overprivileged API keys or tokens granting unrestricted MCP access
- **Risk**: Single compromised key enables full tool access across all servers
- **Detection**: Scope analysis, permission enumeration, usage pattern analysis
- **Remediation**: Rotate to scoped OAuth tokens with least-privilege grants

### Tool Call Injection
- **What**: Malicious inputs via MCP tool calls
- **Risk**: Command injection, data exfiltration, privilege escalation
- **Detection**: Input schema validation, content analysis, behavioral monitoring
- **Remediation**: Strict input validation, output filtering, tool sandboxing

### Eavesdropping / Man-in-the-Middle
- **What**: Intercepting MCP communications between client and server
- **Risk**: Data leakage, credential theft, response manipulation
- **Detection**: TLS verification, certificate pinning, traffic analysis
- **Remediation**: Mutual TLS, encrypted transports, connection integrity checks

## Key Files
- `src/shieldops/agents/mcp_security/` — MCP security agent
- `src/shieldops/agents/mcp_gateway/` — MCP gateway agent
- `src/shieldops/agents/agent_firewall/` — Agent firewall agent
- `src/shieldops/agents/prompt_shield/` — Prompt shield agent
- `src/shieldops/sdk/` — Agent Firewall SDK with MCP support
- `dashboard-ui/src/pages/MCPSecurityPage.tsx` — MCP security dashboard

## Conventions
- All MCP connections MUST use OAuth 2.0 (no API key auth in production)
- God Key detection runs continuously; alerts within 5 minutes
- Tool call inputs validated against JSON Schema before execution
- Sensitive data redacted from MCP tool outputs (PII, credentials)
- MCP audit logs retained for minimum 1 year (compliance)
- New MCP server connections require security review before activation
