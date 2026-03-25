# Situations API

Base path: `/api/v1/situations`

All endpoints require JWT authentication via `Authorization: Bearer <token>` header.

## Endpoints

### List Situations

```
GET /situations
```

Returns AI-curated security situations from cross-vendor alert correlation.

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `status` | string | Filter: `new`, `investigating`, `resolved`, `dismissed` |
| `severity` | string | Filter: `critical`, `high`, `medium`, `low` |
| `source` | string | Filter by vendor: `crowdstrike`, `defender`, `wiz`, `internal` |
| `since` | datetime | Start time (ISO 8601) |
| `limit` | int | Max results (default 50) |
| `offset` | int | Pagination offset |

**Response:** `200 OK` -- Array of situation objects with `id`, `title`, `severity`, `status`, `sources`, `correlated_alerts`, `recommended_actions`, `created_at`.

### Get Situation Details

```
GET /situations/{situation_id}
```

Returns full details for a security situation including correlated alerts, timeline, and recommended actions with confidence scores.

**Response:** `200 OK` -- Situation detail object with `alerts`, `timeline`, `recommended_actions`, `affected_assets`, `mitre_techniques`, `investigation_notes`.

### Execute Action

```
POST /situations/{situation_id}/actions/{action_id}/execute
```

Executes a recommended action on a situation. Actions with confidence >= 0.85 execute autonomously; others require human approval.

**Request Body:**

```json
{
  "override_approval": false,
  "parameters": {},
  "notify_channels": ["slack"]
}
```

**Response:** `200 OK` -- `{"execution_id": "string", "status": "executing|pending_approval", "confidence": 0.92, "estimated_duration_sec": 30}`.

### Update Situation Status

```
PUT /situations/{situation_id}/status
```

Updates the status of a situation (e.g., acknowledge, resolve, dismiss).

**Request Body:**

```json
{
  "status": "investigating|resolved|dismissed",
  "resolution_notes": "string",
  "root_cause": "string"
}
```

**Response:** `200 OK` -- Updated situation object.

### Get Metrics

```
GET /situations/metrics
```

Returns SOC Brain performance metrics including MTTD, MTTA, and MTTR.

**Response:** `200 OK` -- `{"mttd_minutes": 3.2, "mtta_minutes": 1.5, "mttr_minutes": 22.4, "auto_resolved_pct": 0.67, "total_situations": 156, "pending": 8, "resolved_24h": 42}`.

### Health Check

```
GET /situations/health
```

Returns SOC Brain service health including Kafka consumer, vendor connectors, and correlation engine.

**Response:** `200 OK` -- `{"status": "healthy", "components": {"kafka_consumer": "up", "crowdstrike": "up", "defender": "up", "wiz": "up", "correlation_engine": "up"}}`.
