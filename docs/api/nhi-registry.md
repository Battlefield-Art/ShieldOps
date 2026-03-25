# NHI Registry API

Base path: `/api/v1/nhi`

All endpoints require JWT authentication via `Authorization: Bearer <token>` header.

## Endpoints

### List Identities

```
GET /nhi/identities
```

Returns all discovered non-human identities across cloud providers.

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `provider` | string | Filter by provider: `aws`, `gcp`, `azure`, `kubernetes` |
| `risk_level` | string | Filter: `critical`, `high`, `medium`, `low` |
| `status` | string | Filter: `active`, `orphaned`, `shadow` |
| `limit` | int | Max results (default 50) |
| `offset` | int | Pagination offset |

**Response:** `200 OK` -- Array of NHI objects with `id`, `name`, `provider`, `type`, `owner`, `risk_score`, `last_used`, `permissions_count`.

### Get Identity Details

```
GET /nhi/identities/{identity_id}
```

Returns full details for a specific NHI including permissions, usage history, and risk assessment.

**Response:** `200 OK` -- NHI detail object with `permissions`, `usage_history`, `risk_factors`, `recommendations`.

### Trigger Scan

```
POST /nhi/scan
```

Triggers a discovery scan across one or all cloud providers.

**Request Body:**

```json
{
  "provider": "aws|gcp|azure|kubernetes|all",
  "scope": "full|incremental",
  "notify_on_complete": true
}
```

**Response:** `202 Accepted` -- `{"scan_id": "string", "status": "queued", "estimated_duration_sec": 120}`.

### List Shadow AI

```
GET /nhi/shadow-ai
```

Returns detected unregistered AI agent identities calling external LLM APIs.

**Response:** `200 OK` -- Array of shadow AI objects with `source_service`, `api_provider`, `first_seen`, `call_count`, `risk_level`.

### List Orphaned Identities

```
GET /nhi/orphaned
```

Returns NHIs with no active owner or associated service.

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `provider` | string | Filter by cloud provider |
| `inactive_days` | int | Minimum days since last activity (default 30) |

**Response:** `200 OK` -- Array of orphaned NHI objects with `id`, `name`, `provider`, `last_used`, `days_inactive`, `permissions_count`.

### Get Metrics

```
GET /nhi/metrics
```

Returns aggregated NHI registry metrics.

**Response:** `200 OK` -- `{"total_nhis": 142, "orphaned": 8, "shadow_ai": 3, "over_privileged": 15, "scan_coverage": 0.94, "last_scan": "2026-03-25T10:00:00Z"}`.

### Health Check

```
GET /nhi/health
```

Returns NHI registry service health including cloud provider connectivity.

**Response:** `200 OK` -- `{"status": "healthy", "components": {"aws_iam": "up", "gcp_iam": "up", "azure_ad": "up", "k8s_rbac": "up"}}`.
