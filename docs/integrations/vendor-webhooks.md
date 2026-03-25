# Vendor Webhook Configuration Guide

ShieldOps receives real-time security events from CrowdStrike Falcon,
Microsoft Defender, and Wiz via webhook endpoints. This guide walks through
configuring each vendor to forward events into your ShieldOps instance.

## Prerequisites

- ShieldOps API running and accessible (see [Deployment Guide](../DEPLOYMENT.md))
- API key with `webhook:write` permissions
- Vendor admin access for webhook configuration
- Network connectivity from vendor to your ShieldOps endpoint (HTTPS/443)

---

## CrowdStrike Falcon

### Step 1: Create API Client

1. Navigate to **Falcon Console > Support and resources > API Clients & Keys**
2. Click **Create API Client**
3. Configure the following OAuth2 scopes:
   - `Detections: Read`
   - `Incidents: Read`
   - `Event Streams: Read` (required for streaming API)
4. Note the **Client ID** and **Client Secret** — you will need both

### Step 2: Configure Streaming API / Webhook

CrowdStrike uses an Event Stream (polling) model rather than push webhooks.
ShieldOps provides a built-in CrowdStrike stream consumer.

Add the following to your ShieldOps configuration:

```yaml
# config/webhooks/crowdstrike.yaml
crowdstrike:
  enabled: true
  client_id: "${CROWDSTRIKE_CLIENT_ID}"
  client_secret: "${CROWDSTRIKE_CLIENT_SECRET}"
  base_url: "https://api.crowdstrike.com"
  event_types:
    - DetectionSummaryEvent
    - IncidentSummaryEvent
    - AuthActivityAuditEvent
  poll_interval_seconds: 30
  batch_size: 100
```

Alternatively, use the CrowdStrike **Notifications** feature to push to
the ShieldOps webhook endpoint:

1. Go to **Falcon Console > Workflow > Notifications**
2. Create a new notification with:
   - **Type**: Webhook
   - **URL**: `https://your-shieldops.com/api/v1/webhooks/security/crowdstrike`
   - **Method**: POST
   - **Headers**: `Authorization: Bearer <your-shieldops-api-key>`
3. Select trigger conditions (detection severity, incident type, etc.)

### Step 3: Verify Connectivity

```bash
curl -X POST https://your-shieldops.com/api/v1/webhooks/security/crowdstrike \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sk-your-shieldops-key" \
  -H "X-CS-Hmac-Signature: test" \
  -d '{
    "metadata": {"eventType": "DetectionSummaryEvent"},
    "event": {
      "DetectId": "test-001",
      "Severity": 4,
      "DetectName": "Test Detection",
      "ComputerName": "web-server-01",
      "Tactic": "Execution",
      "Technique": "T1059"
    }
  }'
```

Expected response: `200 OK` with `{"status": "accepted", "event_id": "..."}`

---

## Microsoft Defender

### Step 1: Azure AD App Registration

1. Go to **Azure Portal > Azure Active Directory > App registrations**
2. Click **New registration**:
   - **Name**: `ShieldOps Webhook Integration`
   - **Supported account types**: Single tenant
3. Under **API permissions**, add:
   - `SecurityEvents.Read.All` (Microsoft Graph)
   - `ThreatIndicators.Read.All` (Microsoft Graph)
4. Grant admin consent for your organization
5. Under **Certificates & secrets**, create a new client secret
6. Note the **Application (client) ID**, **Directory (tenant) ID**, and **Client Secret**

### Step 2: Configure Webhook

1. Navigate to **Microsoft 365 Defender > Settings > Endpoints > APIs > SIEM**
2. Enable the SIEM connector
3. Configure forwarding to your ShieldOps endpoint:

```yaml
# config/webhooks/defender.yaml
microsoft_defender:
  enabled: true
  tenant_id: "${AZURE_TENANT_ID}"
  client_id: "${AZURE_DEFENDER_CLIENT_ID}"
  client_secret: "${AZURE_DEFENDER_CLIENT_SECRET}"
  webhook_url: "https://your-shieldops.com/api/v1/webhooks/security/defender"
  alert_severities:
    - High
    - Medium
    - Low
  resource: "https://graph.microsoft.com"
```

Alternatively, use **Microsoft Graph API** subscriptions for push notifications:

```bash
curl -X POST https://graph.microsoft.com/v1.0/subscriptions \
  -H "Authorization: Bearer <access-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "changeType": "created",
    "notificationUrl": "https://your-shieldops.com/api/v1/webhooks/security/defender",
    "resource": "/security/alerts_v2",
    "expirationDateTime": "2026-04-25T00:00:00Z",
    "clientState": "<your-shared-secret>"
  }'
```

### Step 3: Verify

```bash
curl -X POST https://your-shieldops.com/api/v1/webhooks/security/defender \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sk-your-shieldops-key" \
  -d '{
    "id": "da637810828901963819_-123456789",
    "incidentId": 42,
    "severity": "high",
    "status": "new",
    "classification": null,
    "title": "Suspicious PowerShell command line",
    "category": "Execution",
    "mitreTechniques": ["T1059.001"]
  }'
```

Expected response: `200 OK` with `{"status": "accepted", "event_id": "..."}`

---

## Wiz

### Step 1: Create Service Account & API Token

1. Go to **Wiz Console > Settings > Service Accounts**
2. Click **Create Service Account**:
   - **Name**: `ShieldOps Integration`
   - **Scopes**: `read:issues`, `read:vulnerabilities`, `read:cloud_configuration`
3. Generate an API token and note the **Client ID** and **Client Secret**

### Step 2: Configure Webhook (Automation Rule)

1. Navigate to **Wiz Console > Settings > Automation > Rules**
2. Click **Create Rule**:
   - **Trigger**: Issue Created or Updated
   - **Conditions**: Severity >= HIGH (adjust as needed)
   - **Action**: Webhook
3. Configure the webhook action:
   - **URL**: `https://your-shieldops.com/api/v1/webhooks/security/wiz`
   - **Method**: POST
   - **Headers**:
     - `Authorization: Bearer sk-your-shieldops-key`
     - `Content-Type: application/json`
   - **Body template**: Use the default Wiz issue payload

```yaml
# config/webhooks/wiz.yaml
wiz:
  enabled: true
  client_id: "${WIZ_CLIENT_ID}"
  client_secret: "${WIZ_CLIENT_SECRET}"
  api_url: "https://api.us1.app.wiz.io/graphql"
  webhook_secret: "${WIZ_WEBHOOK_SECRET}"
  issue_severities:
    - CRITICAL
    - HIGH
  sync_interval_minutes: 15
```

### Step 3: Verify

```bash
curl -X POST https://your-shieldops.com/api/v1/webhooks/security/wiz \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sk-your-shieldops-key" \
  -d '{
    "trigger": "issueCreated",
    "issue": {
      "id": "wiz-issue-001",
      "severity": "CRITICAL",
      "status": "OPEN",
      "title": "S3 bucket publicly accessible",
      "resource": {
        "type": "AWS::S3::Bucket",
        "id": "arn:aws:s3:::my-bucket",
        "region": "us-east-1"
      }
    }
  }'
```

Expected response: `200 OK` with `{"status": "accepted", "event_id": "..."}`

---

## Payload Format Reference

### CrowdStrike Detection Event

```json
{
  "metadata": {
    "eventType": "DetectionSummaryEvent",
    "eventCreationTime": 1711234567890
  },
  "event": {
    "DetectId": "ldt:abc123:456",
    "Severity": 4,
    "SeverityName": "High",
    "DetectName": "Process Injection",
    "ComputerName": "web-server-01",
    "UserName": "svc_app",
    "Tactic": "Defense Evasion",
    "Technique": "T1055",
    "FileName": "suspicious.exe",
    "SHA256": "a1b2c3..."
  }
}
```

### Defender Alert Event

```json
{
  "id": "da637810828901963819_-123456789",
  "incidentId": 42,
  "severity": "high",
  "status": "new",
  "title": "Suspicious PowerShell command line",
  "category": "Execution",
  "description": "A suspicious PowerShell command was detected...",
  "alertCreationTime": "2026-03-20T14:30:00Z",
  "mitreTechniques": ["T1059.001"],
  "devices": [
    {
      "deviceId": "abc123",
      "hostname": "dc-server-01",
      "osPlatform": "Windows10"
    }
  ]
}
```

### Wiz Issue Event

```json
{
  "trigger": "issueCreated",
  "issue": {
    "id": "wiz-issue-001",
    "severity": "CRITICAL",
    "status": "OPEN",
    "title": "S3 bucket publicly accessible",
    "createdAt": "2026-03-20T14:30:00Z",
    "resource": {
      "type": "AWS::S3::Bucket",
      "id": "arn:aws:s3:::my-bucket",
      "region": "us-east-1",
      "cloudAccount": "123456789012"
    },
    "controls": ["CIS AWS 2.1.5"]
  }
}
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Webhook returns `401 Unauthorized` | Invalid or missing API key | Verify `Authorization` header matches a valid ShieldOps API key with `webhook:write` scope |
| Webhook returns `403 Forbidden` | IP not allowlisted | Add vendor IP ranges to your network/firewall allowlist |
| Webhook returns `422 Unprocessable Entity` | Malformed payload | Check payload matches the expected format above; validate JSON syntax |
| Events not appearing in ShieldOps | Kafka connectivity issue | Check `KAFKA_BROKERS` env var and verify Kafka is reachable from the API pod |
| Duplicate events | Re-delivery from vendor | ShieldOps deduplicates by event ID within a 5-minute window; no action needed |
| High latency on event processing | Queue backpressure | Scale the webhook consumer pods and check Kafka partition count |
| CrowdStrike stream disconnects | Token expiry | ShieldOps auto-refreshes tokens; check `CROWDSTRIKE_CLIENT_SECRET` is valid |
| Defender subscription expires | Graph API subscription TTL | ShieldOps auto-renews; verify Azure AD app credentials are current |

## Security Considerations

- All webhook endpoints require HTTPS (TLS 1.2+)
- Signature verification is enabled by default for CrowdStrike (`X-CS-Hmac-Signature`) and Wiz (`X-Wiz-Signature`)
- Defender uses `clientState` validation on Graph API subscriptions
- Webhook secrets should be stored in your secret manager (Vault, AWS Secrets Manager, etc.)
- Rate limiting: 1000 events/minute per vendor per tenant
