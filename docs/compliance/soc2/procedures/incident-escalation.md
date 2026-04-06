# Procedure: Incident Escalation

**Document ID:** SHIELDOPS-PROC-IR-001
**Version:** 1.1
**Owner:** Head of Security (interim: CTO)
**Related Policy:** `policies/incident-response.md`
**Last Reviewed:** 2026-04-01

## 1. Purpose

Define how ShieldOps pages, assembles responders, and escalates during a security or availability incident.

## 2. Paging Tree

```
Alert source (Datadog / Sentry / AWS / ShieldOps platform alert / customer report)
        |
        v
PagerDuty service: shieldops-prod-<service>
        |
        v
Primary on-call engineer  ---(15 min no-ack)-->  Secondary on-call engineer
        |                                               |
        |                                               v
        |                                     Head of Engineering
        |
        v  (if incident declared)
IC opens #inc-YYYYMMDD-<slug> via Slack /incident
        |
        v
IC pages: Head of Security (any SEV),
          Head of Engineering (SEV1/2),
          CEO (SEV1),
          Legal (any confirmed or suspected data breach)
```

No-ack timers:

- Primary to secondary: 15 minutes.
- Secondary to manager: 10 minutes.
- Manager to executive: 10 minutes.

All paging is logged by PagerDuty. PagerDuty records are exported monthly to `s3://shieldops-audit-exports/pagerduty/`.

## 3. Declaring an Incident

Any engineer can and should declare an incident. Declaration is cheap; under-reacting is expensive.

Steps:

1. In Slack, run `/incident` with a one-line description.
2. The command (implemented in `src/shieldops/integrations/slack/incident_create.py`) creates:
   - A Slack channel `#inc-YYYYMMDD-<slug>`.
   - A `war_rooms` row linked to the channel.
   - A PagerDuty incident of the appropriate severity.
   - A Zoom bridge URL attached to the channel topic.
3. The first responder acts as IC until handoff. The IC's first post is the initial situation report.

## 4. IC Responsibilities

- **Own** the incident until resolved or explicitly handed off.
- **Delegate**, don't do. The IC coordinates; SMEs investigate and act.
- **Communicate** at a predictable cadence: every 30 min for SEV1, every 60 min for SEV2, at each material state change otherwise.
- **Decide**. When there is disagreement, the IC makes the call.
- **Record**. Either be the scribe or designate one.

## 5. War Room Rules

- Slack channel is the authoritative running record. Zoom is for real-time discussion, but decisions are posted to Slack.
- No blame. No shaming. Facts, hypotheses, actions, results.
- Read-only participants (execs, CSMs, observers) stay read-only unless called on by the IC.
- External communications go through the Communications Lead, not random participants.

## 6. External Communications During an Incident

| Audience            | Channel                                             | When                                       | Who                         |
|---------------------|-----------------------------------------------------|--------------------------------------------|-----------------------------|
| Affected customers  | Email + in-app banner + CSM outreach                 | SEV1: within 1h; SEV2: within 4h          | Communications Lead         |
| All customers       | `status.shieldops.io`                                | Any multi-customer-visible impact         | Communications Lead         |
| Regulators          | Email + phone per jurisdiction                       | Confirmed breach of Restricted data       | Legal, coordinated with IC  |
| Media               | No direct statements without CEO approval            | Never without CEO + Legal                 | CEO                         |
| Public (security)   | `security@shieldops.io` auto-reply + status page     | Ongoing                                   | Communications Lead         |

Templates for breach notifications live in `docs/compliance/soc2/templates/breach-notification/`.

## 7. Handoff

When an incident crosses shift boundaries or when the IC needs to step away:

1. The outgoing IC posts a handoff message in the incident Slack channel:
   - Current state.
   - What has been tried and what worked or didn't.
   - Open questions and next steps.
   - Name of the incoming IC.
2. The incoming IC acknowledges in the channel.
3. PagerDuty incident is re-assigned.
4. Only one IC is active at a time.

## 8. Resolution

- IC declares resolution only when: the underlying cause is understood and contained, monitoring is green for at least 30 minutes, and customer-visible symptoms are gone.
- IC posts the resolution summary in the channel and updates `war_rooms.status = "resolved"`.
- Post-mortem owner and due date are assigned at resolution (`war_rooms.resolution_summary` contains the post-mortem link).

## 9. Post-Mortem

Required for every SEV1 and SEV2. See `policies/incident-response.md` §6.5 for content and timing. The post-mortem is stored in Notion and linked from the war room.

## 10. Drill and Test Schedule

- Monthly live-call PagerDuty routing test.
- Quarterly tabletop exercise (scenario rotates: ransomware, credential theft, insider, supply chain, regional outage).
- Annual full-scale exercise.

Drill results are logged in Notion and used to refine this procedure.
