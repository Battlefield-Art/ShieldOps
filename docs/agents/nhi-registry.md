# NHI Registry Agent

The NHI (Non-Human Identity) Registry Agent performs automated discovery, classification,
and posture monitoring of all non-human identities across multi-cloud and on-premise
environments. It detects shadow AI agents, orphaned service accounts, and over-privileged
machine credentials.

---

## Purpose

- Continuously discover and catalog all non-human identities (service accounts, API keys, machine tokens, AI agents)
- Detect shadow AI agents operating outside governance controls
- Monitor identity posture for over-privileged credentials and stale access
- Issue Just-In-Time (JIT) credentials with automatic expiration
- Provide unified visibility across AWS IAM, GCP Service Accounts, Azure AD, and Kubernetes
- Generate compliance reports for SOC 2 and identity governance audits

---

## Architecture

```
┌───────────────┐  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐
│   AWS IAM     │  │   GCP SA      │  │   Azure AD    │  │  Kubernetes   │
│   Scanner     │  │   Scanner     │  │   Scanner     │  │  SA Scanner   │
└───────┬───────┘  └───────┬───────┘  └───────┬───────┘  └───────┬───────┘
        │                  │                   │                  │
        └──────────────────┼───────────────────┼──────────────────┘
                           ▼
                  ┌─────────────────┐
                  │  Identity Store │
                  │  (unified DB)   │
                  └────────┬────────┘
                           │
           ┌───────────────┼───────────────┐
           ▼               ▼               ▼
   ┌──────────────┐ ┌─────────────┐ ┌────────────────┐
   │ Shadow AI    │ │  Posture    │ │ JIT Credential │
   │ Detector     │ │  Analyzer   │ │ Manager        │
   └──────────────┘ └─────────────┘ └────────────────┘
```

### LangGraph Nodes

| Node | Description |
|------|-------------|
| `discover_identities` | Scan cloud providers and K8s for all non-human identities |
| `classify_identities` | Categorize identities by type (service account, API key, bot, AI agent) |
| `detect_shadow_ai` | Identify unregistered AI agents via API call patterns and behavioral signatures |
| `assess_posture` | Evaluate privilege levels, credential age, usage frequency, and owner status |
| `score_risk` | Assign risk scores based on posture findings and environmental context |
| `generate_recommendations` | Produce actionable remediation recommendations (scope down, rotate, deactivate) |
| `issue_jit_credential` | (On-demand) Create time-boxed credentials with minimum required permissions |

---

## Key Features

### Automated Discovery
Scheduled scans (configurable interval, default 6 hours) enumerate all non-human identities
across connected cloud accounts. Network traffic analysis supplements API-based discovery
to catch identities that may not appear in provider IAM consoles.

### Shadow AI Detection
Uses behavioral heuristics to identify unregistered AI agents: high API call frequency,
LLM-characteristic request patterns (large payloads, structured prompts), and connections
to known AI provider endpoints.

### Posture Monitoring
Continuously evaluates each identity against best practices: least-privilege principle,
credential rotation schedules, owner assignment, and activity recency. Dormant identities
(no activity in configurable threshold) are flagged for deactivation.

### JIT Credentials
On-demand issuance of short-lived, scoped-down credentials for legitimate automation
tasks. Credentials automatically expire after the configured TTL (default: 1 hour)
and are revoked if the issuing task fails.

---

## Cloud Provider Support

### AWS IAM
- IAM users, roles, and policies
- Access key age and last-used tracking
- Service-linked roles and cross-account access
- STS assume-role session monitoring

### GCP Service Accounts
- Service account keys and metadata
- Workload identity federation bindings
- IAM policy bindings and custom roles
- Key rotation and disable status

### Azure AD
- App registrations and service principals
- Managed identities (system and user-assigned)
- Client secret and certificate expiration
- API permission grants and admin consent

### Kubernetes
- ServiceAccount tokens and bound tokens
- RBAC role bindings (ClusterRole, Role)
- Projected service account token volumes
- Pod identity associations

---

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `NHI_SCAN_INTERVAL_HOURS` | `6` | Hours between full discovery scans |
| `NHI_STALE_THRESHOLD_DAYS` | `90` | Days of inactivity before marking identity as stale |
| `NHI_SHADOW_AI_DETECTION` | `true` | Enable shadow AI behavioral detection |
| `NHI_JIT_DEFAULT_TTL_SECONDS` | `3600` | Default TTL for JIT credentials |
| `NHI_RISK_SCORE_CRITICAL_THRESHOLD` | `0.85` | Risk score threshold for critical classification |
| `NHI_AUTO_DEACTIVATE_ORPHANED` | `false` | Auto-deactivate orphaned identities (requires approval) |

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/nhi/identities` | List all discovered NHIs with filters |
| `GET` | `/api/v1/nhi/identities/{id}` | Get identity details, posture, and risk score |
| `POST` | `/api/v1/nhi/scan` | Trigger an on-demand discovery scan |
| `GET` | `/api/v1/nhi/shadow-ai` | List detected shadow AI agents |
| `POST` | `/api/v1/nhi/jit-credential` | Issue a JIT credential for a workload |
| `GET` | `/api/v1/nhi/posture/summary` | Posture summary across all providers |
| `GET` | `/api/v1/nhi/compliance/report` | Generate compliance report for auditors |

---

## Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `shieldops_nhi_registry_identities_total` | Gauge | Total NHIs by status and risk level |
| `shieldops_nhi_shadow_ai_detections_total` | Counter | Shadow AI agents detected |
| `shieldops_nhi_discovery_scans_total` | Counter | Discovery scan executions |
| `shieldops_nhi_jit_credentials_issued_total` | Counter | JIT credentials issued |
| `shieldops_nhi_posture_score` | Gauge | Overall NHI posture score (0-100) |

---

## Integration with Other Agents

The NHI Registry feeds identity risk data to the [Agent Firewall](agent-firewall.md) for
real-time access control decisions. Shadow AI detections are escalated to the
[SOC Brain](soc-brain.md) as security situations. Posture findings inform the
[Compliance Auditor Agent](compliance-auditor.md) for SOC 2 evidence collection.
