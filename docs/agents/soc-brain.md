# SOC Brain Agent

The SOC Brain Agent is an AI-powered Security Operations Center that performs cross-vendor
alert correlation, maintains a prioritized situations queue, supports human-in-the-loop
approval workflows, and builds evidence chains for incident response. It replaces manual
SIEM triage with autonomous situation management.

---

## Purpose

- Correlate alerts from multiple security vendors into unified situations
- Maintain a prioritized situations queue ranked by severity, confidence, and blast radius
- Automate triage, containment, and resolution for high-confidence situations
- Provide human-in-the-loop (HITL) approval for actions below confidence thresholds
- Build evidence chains linking alerts, logs, indicators, and remediation actions
- Track operational metrics: MTTD, MTTA, MTTR

---

## Architecture (9-Node Graph)

```
vendor_ingest
      │
      ▼
normalize_alerts
      │
      ▼
correlate ──────────────────┐
      │                     │
      ▼                     ▼
create_or_update_situation  deduplicate
      │
      ▼
triage_and_prioritize
      │
      ├── [confidence >= 0.85] ──▶ auto_execute ──▶ validate_outcome
      │                                                    │
      ├── [0.5 <= confidence < 0.85] ──▶ request_approval  │
      │                                       │            │
      │                                       ▼            │
      │                               [approved?]          │
      │                                 yes ──▶ auto_execute
      │                                 no  ──▶ close_situation
      │                                                    │
      └── [confidence < 0.5] ──▶ escalate_to_human         │
                                                           ▼
                                                  build_evidence_chain
```

### Nodes

| Node | Description |
|------|-------------|
| `vendor_ingest` | Receive alerts from CrowdStrike, Microsoft Defender, Wiz, and other vendors via webhooks and polling |
| `normalize_alerts` | Transform vendor-specific alert formats into a unified ShieldOps alert schema |
| `correlate` | Match alerts against correlation rules (time window, entity overlap, MITRE technique) |
| `deduplicate` | Identify and merge duplicate alerts from overlapping vendor coverage |
| `create_or_update_situation` | Create a new situation or update an existing one with correlated alerts |
| `triage_and_prioritize` | Assign severity, confidence score, and blast radius estimate using LLM reasoning |
| `auto_execute` | Execute containment/remediation playbook for high-confidence situations |
| `request_approval` | Send HITL approval request via Slack/Teams/PagerDuty with situation context |
| `validate_outcome` | Verify remediation was effective and no regression occurred |
| `build_evidence_chain` | Assemble the complete evidence chain (alerts, logs, actions, outcomes) |
| `escalate_to_human` | Route low-confidence situations to human analysts with full context |
| `close_situation` | Mark situation as resolved or false positive with disposition |

### Conditional Edges

- **After `triage_and_prioritize`:** Routes based on confidence score.
  >= 0.85 goes to `auto_execute`, 0.5-0.85 goes to `request_approval`,
  < 0.5 goes to `escalate_to_human`.
- **After `request_approval`:** If approved, proceeds to `auto_execute`. If rejected,
  proceeds to `close_situation`.
- **After `validate_outcome`:** Always proceeds to `build_evidence_chain`.

---

## Key Features

### Cross-Vendor Correlation
Ingests alerts from multiple security vendors and correlates them using temporal proximity,
shared entities (IPs, users, hosts), and MITRE ATT&CK technique mapping. A single
attacker campaign triggering alerts in CrowdStrike, Defender, and Wiz is correlated
into one unified situation.

### Situations Queue
Maintains a prioritized queue of active situations. Each situation has a severity level,
confidence score, affected entities, correlated alerts, and a recommended playbook.
The queue is continuously re-prioritized as new information arrives.

### Human-in-the-Loop Approval
For medium-confidence situations (0.5-0.85), the SOC Brain sends approval requests with
full context to security analysts via configured channels (Slack, Teams, PagerDuty).
Requests include the proposed action, evidence summary, and blast radius estimate.
Approval timeout is configurable (default: 30 minutes).

### Evidence Chains
Every situation builds a complete evidence chain: triggering alerts, correlated signals,
enrichment data, analyst decisions, executed actions, and validation results. Evidence
chains are immutable and exportable for compliance and post-incident review.

---

## Vendor Integration

| Vendor | Ingestion Method | Alert Types |
|--------|-----------------|-------------|
| CrowdStrike Falcon | API polling + webhook | Endpoint detections, IOCs, behavioral indicators |
| Microsoft Defender | Microsoft Graph API | Endpoint alerts, identity alerts, cloud app alerts |
| Wiz | Webhook + API | Cloud misconfigurations, vulnerabilities, attack paths |
| Palo Alto Cortex | API polling | Network detections, XDR alerts |
| SentinelOne | API polling | Endpoint threats, autonomous response events |
| Custom | Webhook (generic JSON) | Any structured alert payload |

---

## Outcome Metrics

| Metric | Description | Target |
|--------|-------------|--------|
| MTTD (Mean Time to Detect) | Time from attack start to first alert correlation | < 5 minutes |
| MTTA (Mean Time to Acknowledge) | Time from situation creation to first human/auto action | < 2 minutes |
| MTTR (Mean Time to Resolve) | Time from situation creation to validated resolution | < 30 minutes |
| Auto-Resolution Rate | Percentage of situations resolved without human intervention | > 60% |
| False Positive Rate | Percentage of situations closed as false positive | < 15% |

---

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SOC_AUTO_EXECUTE_THRESHOLD` | `0.85` | Confidence threshold for autonomous action |
| `SOC_ESCALATION_THRESHOLD` | `0.5` | Below this confidence, escalate to human |
| `SOC_APPROVAL_TIMEOUT_SECONDS` | `1800` | Timeout for HITL approval requests |
| `SOC_CORRELATION_WINDOW_SECONDS` | `300` | Time window for alert correlation |
| `SOC_MAX_ACTIVE_SITUATIONS` | `100` | Maximum concurrent active situations |
| `SOC_EVIDENCE_RETENTION_DAYS` | `365` | Days to retain evidence chains |
| `SOC_VENDOR_POLL_INTERVAL_SECONDS` | `60` | Polling interval for vendor APIs |

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/soc/situations` | List situations with filters (status, severity, time range) |
| `GET` | `/api/v1/soc/situations/{id}` | Situation details with full evidence chain |
| `POST` | `/api/v1/soc/situations/{id}/approve` | Approve a pending HITL action |
| `POST` | `/api/v1/soc/situations/{id}/reject` | Reject a pending HITL action |
| `POST` | `/api/v1/soc/situations/{id}/escalate` | Manually escalate a situation |
| `GET` | `/api/v1/soc/metrics` | SOC operational metrics (MTTD, MTTA, MTTR) |
| `GET` | `/api/v1/soc/vendors` | Connected vendor status and health |
| `POST` | `/api/v1/soc/webhook/{vendor}` | Vendor alert webhook ingestion endpoint |

---

## Integration with Other Agents

The SOC Brain receives security signals from the [Agent Firewall](agent-firewall.md)
(blocked calls, anomalies), the [NHI Registry](nhi-registry.md) (shadow AI, orphaned
identities), and the [MCP Security Agent](mcp-security.md) (God Keys, supply chain
vulnerabilities). Containment actions are executed via the
[Remediation Agent](remediation.md). Post-resolution analysis feeds into the
[Learning Agent](learning.md) to improve future correlation accuracy.
