# MCP Security API

Base path: `/api/v1/mcp-security`

All endpoints require JWT authentication via `Authorization: Bearer <token>` header.

## Endpoints

### List MCP Servers

```
GET /mcp-security/servers
```

Returns all registered MCP servers with risk scores and compliance status.

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `risk_level` | string | Filter: `critical`, `high`, `medium`, `low` |
| `compliant` | boolean | Filter by zero-trust compliance status |
| `limit` | int | Max results (default 50) |
| `offset` | int | Pagination offset |

**Response:** `200 OK` -- Array of MCP server objects with `id`, `name`, `risk_score`, `tools_count`, `zero_trust_compliant`, `last_scanned`.

### Get Server Details

```
GET /mcp-security/servers/{server_id}
```

Returns full details for an MCP server including tools, permissions, vulnerabilities, and compliance gaps.

**Response:** `200 OK` -- Server detail object with `tools`, `permissions_matrix`, `vulnerabilities`, `compliance_status`, `recommendations`.

### Trigger Security Scan

```
POST /mcp-security/scan
```

Triggers a security scan of MCP servers for god keys, supply chain vulnerabilities, and compliance gaps.

**Request Body:**

```json
{
  "server_ids": ["string"] ,
  "scan_type": "full|god_keys|supply_chain|zero_trust",
  "notify_on_complete": true
}
```

**Response:** `202 Accepted` -- `{"scan_id": "string", "status": "queued", "servers_queued": 12}`.

### List God Keys

```
GET /mcp-security/god-keys
```

Returns detected MCP servers with overly broad permissions (god keys).

**Response:** `200 OK` -- Array of god key findings with `server_id`, `server_name`, `permission_scope`, `downstream_resources`, `risk_score`, `recommendation`.

### Get Supply Chain Report

```
GET /mcp-security/supply-chain
```

Returns supply chain vulnerability report for MCP server dependencies.

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `severity` | string | Filter: `critical`, `high`, `medium`, `low` |

**Response:** `200 OK` -- Array of vulnerability objects with `cve_id`, `severity`, `affected_server`, `component`, `fix_available`, `description`.

### Get Zero-Trust Compliance

```
GET /mcp-security/zero-trust
```

Returns zero-trust compliance scores across all MCP servers.

**Response:** `200 OK` -- `{"overall_score": 0.87, "servers": [{"id": "string", "name": "string", "score": 0.92, "gaps": ["missing mTLS", "no token rotation"]}]}`.

### Create Gateway Policy

```
POST /mcp-security/policies
```

Creates a gateway policy to control tool calls through MCP servers.

**Request Body:**

```json
{
  "name": "string",
  "server_pattern": "string",
  "tool_pattern": "string",
  "action": "allow|block|audit",
  "conditions": {}
}
```

**Response:** `201 Created` -- Created policy object.

### Get Metrics

```
GET /mcp-security/metrics
```

Returns aggregated MCP security metrics.

**Response:** `200 OK` -- `{"total_servers": 12, "god_keys": 3, "critical_vulns": 0, "zero_trust_score": 0.87, "gateway_latency_p95_ms": 15}`.

### Health Check

```
GET /mcp-security/health
```

Returns MCP security service health including Wiz connector and gateway proxy status.

**Response:** `200 OK` -- `{"status": "healthy", "components": {"wiz": "up", "gateway_proxy": "up", "policy_engine": "up"}}`.
