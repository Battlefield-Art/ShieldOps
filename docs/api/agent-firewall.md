# Agent Firewall API

Base path: `/api/v1/agent-firewall`

All endpoints require JWT authentication via `Authorization: Bearer <token>` header.

## Endpoints

### List Agents

```
GET /agent-firewall/agents
```

Returns all registered agents with their current firewall status, circuit breaker state, and risk scores.

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `status` | string | Filter by status: `active`, `blocked`, `circuit_open` |
| `limit` | int | Max results (default 50) |
| `offset` | int | Pagination offset |

**Response:** `200 OK` -- Array of agent objects with `id`, `name`, `status`, `circuit_breaker_state`, `risk_score`, `last_seen`.

### Get Agent Events

```
GET /agent-firewall/agents/{agent_id}/events
```

Returns the event log for a specific agent including intercepted calls, blocks, and anomalies.

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `event_type` | string | Filter: `intercepted`, `blocked`, `anomaly` |
| `since` | datetime | Start time (ISO 8601) |
| `limit` | int | Max results (default 100) |

**Response:** `200 OK` -- Array of event objects.

### Get Agent Baseline

```
GET /agent-firewall/agents/{agent_id}/baseline
```

Returns the behavioral baseline for the agent, including normal call patterns, expected tools, and thresholds.

**Response:** `200 OK` -- Baseline object with `call_rate_avg`, `call_rate_p95`, `expected_tools`, `anomaly_threshold`.

### Evaluate Agent Call

```
POST /agent-firewall/agents/{agent_id}/evaluate
```

Submits an agent call for firewall evaluation. Returns allow/block decision with reasoning.

**Request Body:**

```json
{
  "tool_name": "string",
  "parameters": {},
  "context": {
    "session_id": "string",
    "tenant_id": "string"
  }
}
```

**Response:** `200 OK` -- `{"decision": "allow|block", "reason": "string", "confidence": 0.95, "latency_ms": 12}`.

### Create Firewall Policy

```
POST /agent-firewall/policies
```

Creates a new firewall policy rule.

**Request Body:**

```json
{
  "name": "string",
  "description": "string",
  "agent_pattern": "string",
  "tool_pattern": "string",
  "action": "allow|block|audit",
  "conditions": {}
}
```

**Response:** `201 Created` -- Created policy object.

### Activate Kill Switch

```
POST /agent-firewall/agents/{agent_id}/kill-switch
```

Immediately revokes all tokens and blocks all calls for the specified agent. This is an emergency action.

**Request Body:**

```json
{
  "reason": "string",
  "notify_channels": ["slack", "pagerduty"]
}
```

**Response:** `200 OK` -- `{"status": "killed", "tokens_revoked": 3, "sessions_terminated": 1}`.

### Get Metrics

```
GET /agent-firewall/metrics
```

Returns aggregated firewall metrics for dashboards and alerting.

**Response:** `200 OK` -- Metrics object with `calls_intercepted`, `calls_blocked`, `block_rate`, `anomaly_rate`, `p95_latency_ms`, `circuit_breakers_open`.

### Health Check

```
GET /agent-firewall/health
```

Returns firewall service health including Redis cache, CrowdStrike connector, and policy engine status.

**Response:** `200 OK` -- `{"status": "healthy", "components": {"redis": "up", "crowdstrike": "up", "policy_engine": "up"}}`.
