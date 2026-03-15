# Incident Commander Agent

Multi-agent orchestration agent that coordinates complex incident response across investigation, remediation, security, and communication agents. Acts as the automated incident commander, managing the lifecycle from detection through resolution and postmortem.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  Incident Commander                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐  │
│  │ Triage   │  │ Delegate │  │ Monitor  │  │ Close  │  │
│  │ & Assess │─▶│ & Coord  │─▶│ Progress │─▶│ & RCA  │  │
│  └──────────┘  └──────────┘  └──────────┘  └────────┘  │
└────────┬───────────┬───────────┬───────────────┬────────┘
         ▼           ▼           ▼               ▼
   Investigation  Remediation  Security     Communication
      Agent         Agent       Agent      (Slack/PagerDuty)
```

## Workflow

1. **Triage** -- Receives incident signals, classifies severity (P1-P5), identifies affected services using topology maps, and determines blast radius. Assigns initial incident category (availability, performance, security, data).
2. **Delegate** -- Spawns and coordinates sub-agents: investigation agent for root cause analysis, remediation agent for fixes, security agent if threat indicators are present. Manages parallel workstreams with dependency tracking.
3. **Monitor** -- Tracks progress of all delegated tasks, enforces SLA timelines (P1: 15min response, 1hr resolution target), escalates stalled investigations, and sends stakeholder updates via ChatOps integrations.
4. **Close** -- Validates that remediation is effective (metrics recovered, errors resolved), generates automated postmortem draft with timeline, root cause, and action items. Archives incident data for learning agent consumption.

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `IC_AUTO_ESCALATE_MINUTES` | Minutes before auto-escalation | `30` |
| `IC_P1_RESPONSE_SLA` | P1 response time target | `15m` |
| `IC_MAX_PARALLEL_AGENTS` | Max concurrent sub-agents | `5` |
| `IC_NOTIFICATION_CHANNELS` | Slack/Teams/PagerDuty channels | Required |
| `IC_POSTMORTEM_AUTO_GENERATE` | Auto-generate postmortem on close | `true` |

## Usage

```bash
# Trigger via CLI (typically auto-triggered by alerts)
shieldops run-agent incident_response --incident-id INC-2024-0142 --severity P1

# Trigger via API
curl -X POST /api/v1/agents/incident_response/run \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"severity": "P1", "service": "payment-api", "signal": "5xx_spike"}'
```

Returns an incident report with full timeline, delegated agent actions, resolution steps, and postmortem draft.
