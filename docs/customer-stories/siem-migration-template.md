# Customer Story Template: SIEM Migration — Splunk → ShieldOps

> Template for post-migration case studies. Fill in placeholders marked `{{...}}` after the customer success retro.
> Legal review required before publishing externally.

---

## Headline

**{{CUSTOMER_NAME}} cut SIEM spend by {{SAVINGS_PCT}}% and reduced MTTR from {{MTTR_BEFORE}} to {{MTTR_AFTER}} by replacing Splunk with ShieldOps in {{WEEKS}} weeks.**

## At a glance

| | |
|---|---|
| **Customer** | {{CUSTOMER_NAME}} |
| **Industry** | {{INDUSTRY}} |
| **Size** | {{EMPLOYEE_COUNT}} employees, {{REVENUE}} revenue |
| **Region** | {{REGION}} |
| **ShieldOps tier** | {{TIER}} ({{AGENT_COUNT}} agents) |
| **Previous SIEM** | Splunk Enterprise Security {{SPLUNK_VERSION}} |
| **Migration duration** | {{WEEKS}} weeks |
| **Go-live** | {{GO_LIVE_DATE}} |

---

## Customer overview

{{CUSTOMER_NAME}} is a {{INDUSTRY}} company with {{EMPLOYEE_COUNT}} employees across {{LOCATIONS}}. The security team of {{SEC_TEAM_SIZE}} analysts protects {{ASSET_COUNT}} endpoints, {{CLOUD_ACCOUNTS}} cloud accounts across {{CLOUDS}}, and {{APP_COUNT}} production applications.

**Compliance scope:** {{COMPLIANCE_FRAMEWORKS}}

---

## The problem

Before ShieldOps, {{CUSTOMER_NAME}}'s security operations ran on Splunk Enterprise Security. Over {{YEARS_ON_SPLUNK}} years, three forces made the status quo unworkable:

1. **Cost spiral.** Splunk licensing grew from ${{COST_START}} to ${{COST_PEAK}} annually as log volume doubled every {{DOUBLING_PERIOD}}. A {{RENEWAL_PCT}}% renewal uplift was quoted for {{RENEWAL_YEAR}}.
2. **Alert fatigue.** The team received {{ALERTS_PER_DAY}} alerts per day, of which ~{{FP_RATE}}% were false positives. Analysts spent {{TRIAGE_HOURS}} hours per week on triage alone.
3. **MTTR plateau.** Mean time to respond had been stuck at {{MTTR_BEFORE}} for {{PLATEAU_PERIOD}}. Investigations required pivoting across {{TOOL_COUNT}} tools; handoffs between tier-1 and tier-2 added {{HANDOFF_MINS}} minutes on average.

> "{{QUOTE_PROBLEM}}"
> — {{QUOTE_PROBLEM_AUTHOR}}, {{QUOTE_PROBLEM_TITLE}}, {{CUSTOMER_NAME}}

---

## Why ShieldOps

{{CUSTOMER_NAME}} evaluated {{COMPETITORS}} alongside ShieldOps. Three factors tipped the decision:

1. **Agent-led investigation.** ShieldOps runs {{AGENT_COUNT}} autonomous security agents (investigation, remediation, threat hunting, incident response) that collapse {{ALERTS_PER_DAY}} raw alerts into a small number of actionable situations.
2. **Control plane, not another SIEM.** ShieldOps intercepts tool calls, governs non-human identities, and enforces OPA policy gates at every layer — a strategic fit for {{CUSTOMER_NAME}}'s AI-agent roadmap.
3. **Design partner engagement.** A dedicated ShieldOps CSE guided the full migration with a tested playbook, parallel-run validator, and 72-hour rollback window.

---

## The solution

### Architecture

```
          ┌──────────────────────────────────────────────────┐
          │                   Data sources                   │
          │   AWS CloudTrail   CrowdStrike   Defender   Wiz  │
          │       Okta         K8s audit     ServiceNow      │
          └─────────────────────┬────────────────────────────┘
                                │
                                ▼
          ┌──────────────────────────────────────────────────┐
          │             ShieldOps Connector Layer            │
          │   17 connectors, OAuth2/MSAL/GraphQL, OTel out   │
          └─────────────────────┬────────────────────────────┘
                                │
                                ▼
          ┌──────────────────────────────────────────────────┐
          │          Agent Orchestration (LangGraph)         │
          │  investigation · remediation · soc_analyst       │
          │  threat_hunter · incident_response · identity    │
          │  alert_correlation · vulnerability_manager       │
          └─────────────────────┬────────────────────────────┘
                                │
                                ▼
          ┌──────────────────────────────────────────────────┐
          │         Policy & Safety (OPA + approvals)        │
          │    HIPAA / PCI / SOC 2 / GDPR / FedRAMP          │
          └─────────────────────┬────────────────────────────┘
                                │
                                ▼
          ┌──────────────────────────────────────────────────┐
          │     Situations Queue · NL Query · Biz Value      │
          │   Slack · PagerDuty · ServiceNow · Jira          │
          └──────────────────────────────────────────────────┘
```

### Deployment details

- **Tier:** {{TIER}}
- **Agents deployed:** {{AGENT_LIST}}
- **Connectors:** {{CONNECTOR_LIST}}
- **Compliance policies loaded:** {{OPA_POLICIES}}
- **Integration points:** {{INTEGRATIONS}}

### Migration timeline

| Week | Phase | Milestone |
|---|---|---|
| 1 | Pre-migration + parallel run setup | Connectors deployed, ingestion parity ≥98% |
| 2 | Parallel run + alert rule migration begin | {{RULE_COUNT}} SPL rules mapped to ShieldOps policies |
| 3 | Alert rule validation + dashboard recreation | 7-day alert parity ≥95% |
| 4 | Dashboard + report migration | {{DASHBOARD_COUNT}} dashboards, {{REPORT_COUNT}} reports migrated |
| 5 | SOC team training + shadow week | {{ANALYST_COUNT}} analysts trained, runbooks updated |
| 6 | Cutover | Splunk forwarders stopped, ShieldOps in enforce mode |
| 7 | Daily verification | No regressions, customer accepts |
| 8 | Splunk decommission + retro | Cost savings booked, lessons captured |

---

## Results

### Cost savings

| | Before (Splunk) | After (ShieldOps) | Delta |
|---|---|---|---|
| Annual license | ${{SPLUNK_LICENSE}} | ${{SHIELDOPS_LICENSE}} | ${{LICENSE_DELTA}} ({{LICENSE_PCT}}%) |
| Infrastructure | ${{SPLUNK_INFRA}} | ${{SHIELDOPS_INFRA}} | ${{INFRA_DELTA}} |
| Admin FTE | ${{SPLUNK_ADMIN}} | ${{SHIELDOPS_ADMIN}} | ${{ADMIN_DELTA}} |
| **Total annual** | **${{SPLUNK_TOTAL}}** | **${{SHIELDOPS_TOTAL}}** | **${{TOTAL_DELTA}} ({{SAVINGS_PCT}}%)** |

Payback period: **{{PAYBACK_WEEKS}} weeks.** 3-year TCO delta: **${{TCO_3YR}}**.

### Operational improvements

| Metric | Before | After | Improvement |
|---|---|---|---|
| MTTD | {{MTTD_BEFORE}} | {{MTTD_AFTER}} | {{MTTD_IMPROVEMENT}}% |
| MTTR | {{MTTR_BEFORE}} | {{MTTR_AFTER}} | {{MTTR_IMPROVEMENT}}% |
| Raw alerts / day | {{ALERTS_BEFORE}} | {{ALERTS_AFTER}} | {{ALERT_REDUCTION}}% |
| False-positive rate | {{FP_BEFORE}}% | {{FP_AFTER}}% | {{FP_IMPROVEMENT}}pp |
| Situations / day | n/a | {{SITUATIONS_AFTER}} | — |
| Analyst triage hours / week | {{TRIAGE_BEFORE}} | {{TRIAGE_AFTER}} | {{TRIAGE_REDUCTION}}% |

### Analyst time recovered

{{HOURS_RECOVERED}} analyst hours per year returned to proactive work — threat hunting, detection engineering, and purple-team exercises. Equivalent to {{FTE_EQUIVALENT}} FTEs of capacity without new hires.

### Customer voice

> "{{QUOTE_RESULT_1}}"
> — {{QUOTE_AUTHOR_1}}, {{QUOTE_TITLE_1}}

> "{{QUOTE_RESULT_2}}"
> — {{QUOTE_AUTHOR_2}}, {{QUOTE_TITLE_2}}

> "{{QUOTE_RESULT_3}}"
> — {{QUOTE_AUTHOR_3}}, {{QUOTE_TITLE_3}}

---

## Lessons learned

1. **{{LESSON_1_TITLE}}.** {{LESSON_1_BODY}}
2. **{{LESSON_2_TITLE}}.** {{LESSON_2_BODY}}
3. **{{LESSON_3_TITLE}}.** {{LESSON_3_BODY}}

## ROI calculation

```
annual_savings      = ${{TOTAL_DELTA}}
productivity_value  = ${{PRODUCTIVITY_VALUE}}
total_annual_value  = ${{TOTAL_ANNUAL_VALUE}}
onboarding_fee      = ${{ONBOARDING_FEE}}
payback_weeks       = {{PAYBACK_WEEKS}}
3_year_tco_delta    = ${{TCO_3YR}}
roi_1_year          = {{ROI_1YR}}%
roi_3_year          = {{ROI_3YR}}%
```

See `docs/runbooks/siem-cost-comparison.md` for the methodology.

---

## Next steps with {{CUSTOMER_NAME}}

- {{NEXT_STEP_1}}
- {{NEXT_STEP_2}}
- {{NEXT_STEP_3}}

---

## About ShieldOps

ShieldOps is the AI Security Control Plane for enterprises running autonomous AI agents and modern security operations. ShieldOps governs, monitors, and responds to AI-agent activity across multi-cloud and on-premise infrastructure, with policy gates, runtime interception, NHI governance, and SOC automation.

Learn more at [shieldops.io](https://shieldops.io).

---

*Publication review: Legal / Marketing / {{CUSTOMER_LEGAL_CONTACT}}*
*Last updated: {{PUBLICATION_DATE}}*
