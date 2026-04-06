# SIEM Migration Playbook: Splunk → ShieldOps

> **Audience:** ShieldOps design-partner customer success engineers, customer security leads, SOC managers.
> **Scope:** End-to-end migration of a production Splunk deployment to the ShieldOps AI Security Control Plane.
> **Duration:** 6–8 weeks from kickoff to decommission.
> **Status:** Production runbook — design partner engagements (issue #240).

---

## Overview

ShieldOps replaces the detection, investigation, dashboarding, and reporting functions of Splunk Enterprise Security with an agent-led control plane. This playbook is the authoritative step-by-step for cutting a customer over safely, with a parallel-run validation period, full alert-rule parity, and a documented rollback path.

### Outcomes

| Dimension | Splunk baseline | ShieldOps target |
|---|---|---|
| Annual license cost | $X/year | 40–70% reduction |
| MTTD | Hours | Minutes (agent investigation) |
| MTTR | Hours–days | <1 hour (auto-remediation gated) |
| Alert-to-situation ratio | 1:1 | ~30:1 (situation composer) |
| Analyst hours/week on triage | Baseline | 50–70% reduction |

### Migration pattern

```
Week 1-2   Parallel run setup         Dual-write data flows
Week 2-3   Alert rule migration       SPL → agent policies
Week 3-4   Dashboard recreation       Splunk dashboards → situations queue + BI
Week 4     Report migration           Scheduled reports → NL query templates
Week 5     SOC team training          Hands-on + runbook updates + shadow week
Week 6     Cutover                    Stop forwarders, enable enforce mode
Week 7-8   Post-cutover + decommission
```

---

## Pre-migration checklist

Complete this **before** the kickoff. The customer success engineer owns collection.

### Customer intake

- [ ] Splunk deployment topology documented (search heads, indexers, forwarders, heavy forwarders, HEC)
- [ ] Current license tier + daily ingest volume (GB/day) recorded
- [ ] Retention policies per index recorded (hot/warm/cold/frozen)
- [ ] Data sources inventoried — use `scripts/migration/splunk_inventory.py` or run manually:
  ```spl
  | metadata type=sourcetypes index=* | eval recentTime=strftime(recentTime, "%Y-%m-%d")
  | table sourcetype totalCount recentTime
  | sort - totalCount
  ```
- [ ] All `savedsearches.conf` entries exported:
  ```bash
  /opt/splunk/bin/splunk cmd btool savedsearches list --debug > savedsearches.out
  ```
- [ ] Dashboard inventory exported via Splunk REST:
  ```bash
  curl -k -u admin:$PASS \
    "https://splunk.example.com:8089/servicesNS/-/-/data/ui/views?output_mode=json&count=0" \
    > dashboards.json
  ```
- [ ] Scheduled reports listed (`| rest /services/saved/searches | where is_scheduled=1`)
- [ ] Integrations inventoried: CrowdStrike, Defender, Wiz, CloudTrail, GuardDuty, Okta, ServiceNow, PagerDuty, Jira, Slack
- [ ] SOC team roster + on-call schedule
- [ ] RBAC model (Splunk roles → ShieldOps RBAC mapping)
- [ ] Compliance scope: SOC 2, HIPAA, PCI, FedRAMP, GDPR, ISO 27001
- [ ] Change management window identified (4-hour cutover slot)
- [ ] Rollback criteria agreed with customer security lead
- [ ] Executive sponsor identified + sign-off meeting scheduled for week 6

### ShieldOps side

- [ ] Tenant provisioned (`shieldops tenant create --name <customer>`)
- [ ] Connectors deployed: AWS, CrowdStrike, Defender, Wiz, Okta (as applicable)
- [ ] OPA policies loaded matching customer compliance scope
- [ ] Situations Queue configured with customer-specific routing rules
- [ ] Business Value dashboard wired to customer billing context
- [ ] Agent fleet deployed: investigation, remediation, soc_analyst, threat_hunter, incident_response, compliance_auditor, vulnerability_manager, identity_graph, alert_correlation, cost
- [ ] Dedicated Slack channel `#cust-<name>-migration` created
- [ ] Shared runbook folder created in customer workspace

---

## Phase 1 — Parallel run setup (week 1-2)

**Goal:** ShieldOps ingests the same telemetry as Splunk, with verifiable volume parity, without disrupting existing Splunk flows.

### 1.1 Install connectors alongside Splunk

For each data source, configure the ShieldOps connector so it reads from the source-of-truth (not from Splunk). This avoids Splunk becoming a single point of failure in the migration.

**CloudTrail → both:**
```bash
# AWS connector — subscribes to CloudTrail S3 bucket via SQS
shieldops connector install aws \
  --account <ACCOUNT_ID> \
  --cloudtrail-bucket <BUCKET> \
  --cloudtrail-sqs <SQS_ARN> \
  --region us-east-1
```

**CrowdStrike → both:**
Splunk uses the CrowdStrike Falcon Data Replicator app. Configure ShieldOps to consume from the same CrowdStrike OAuth2 streaming API in parallel:
```bash
shieldops connector install crowdstrike \
  --client-id $CS_CLIENT_ID \
  --client-secret $CS_CLIENT_SECRET \
  --base-url https://api.crowdstrike.com \
  --stream-enabled true
```

**Defender / Wiz / Okta:** Use the ShieldOps connector CLI (`shieldops connector install <name>`). Each supports audit/observe mode for the parallel period.

**Syslog / HEC sources:** Configure a Vector or Fluent Bit sidecar to fan out to both Splunk HEC and ShieldOps OTel collector:
```yaml
# vector.yaml
sinks:
  splunk:
    type: splunk_hec_logs
    endpoint: https://splunk.example.com:8088
    token: ${SPLUNK_HEC_TOKEN}
  shieldops:
    type: http
    uri: https://api.shieldops.io/v1/ingest/otel
    auth:
      strategy: bearer
      token: ${SHIELDOPS_API_TOKEN}
```

### 1.2 Verify ingestion volume parity

Run the validator script daily during phase 1:

```bash
python scripts/migration/parallel_run_validator.py \
  --window 24h \
  --queries scripts/migration/queries.sample.json \
  --splunk-host https://splunk.example.com:8089 \
  --shieldops-host https://api.shieldops.io \
  --out reports/parity-day-$(date +%Y%m%d).md
```

**Parity target:** ≥98% match on event count per sourcetype over a 24-hour window. Investigate any sourcetype below 95% — usually indicates a dropped connector or a filter mismatch.

### 1.3 Exit criteria for phase 1

- [ ] All in-scope data sources writing to ShieldOps
- [ ] 7 consecutive days of ≥98% ingestion parity
- [ ] No elevated error rate on either side
- [ ] Customer security lead signs off on phase 1

---

## Phase 2 — Alert rule migration (week 2-3)

**Goal:** Every Splunk saved search / correlation search that generates an alert has an equivalent ShieldOps agent policy, validated to fire on the same events.

### 2.1 Convert SPL saved searches → agent policies

ShieldOps does not execute SPL. Instead, each Splunk alert rule maps to one of:

| Splunk construct | ShieldOps equivalent |
|---|---|
| Correlation search (ES) | `alert_correlation` agent policy + situation composer rule |
| Threshold-based saved search | `anomaly_detector` engine rule |
| Lookup-driven watchlist | NHI Registry or identity_graph watchlist |
| Scheduled report alert | NL query template with schedule |
| Notable event | Situation in situations queue |
| Adaptive response action | Agent tool call (gated by OPA) |

Use the **per-rule mapping table** (one row per SPL rule) in `reports/rule-mapping-<customer>.csv`:

```csv
splunk_rule_name,splunk_rule_type,splunk_schedule,splunk_search,shieldops_target,shieldops_policy_id,owner,status,notes
Brute Force Auth Failures,correlation,every-5min,"index=auth action=failure | stats count by user...",alert_correlation,policy_bf_auth_001,jdoe@cust.com,in_progress,
Impossible Travel,correlation,every-15min,...,identity_graph,policy_imp_travel_003,jdoe@cust.com,migrated,Validated 2026-04-02
```

### 2.2 Author ShieldOps policies

For each SPL rule, author the equivalent policy. Example — SPL brute force → ShieldOps:

```python
# policies/brute_force_auth.py
from shieldops.agents.framework import define_agent_policy

define_agent_policy(
    id="policy_bf_auth_001",
    agent="alert_correlation",
    description="Detect brute force auth failures (migrated from Splunk: Brute Force Auth Failures)",
    window="5m",
    condition={
        "source": "auth.events",
        "filter": {"action": "failure"},
        "group_by": ["user", "src_ip"],
        "threshold": {"count": 10},
    },
    severity="high",
    situation_template="brute_force_auth",
    actions=["enrich_user", "enrich_ip", "check_recent_successes"],
    enforce_mode=False,  # audit only during parallel run
)
```

### 2.3 Validation — same alert fires in both systems

For each migrated rule, run a 7-day side-by-side comparison:

```bash
python scripts/migration/parallel_run_validator.py \
  --window 7d \
  --queries reports/alert-rules-<customer>.json \
  --mode alerts \
  --out reports/alert-parity-$(date +%Y%m%d).md
```

**Parity target per rule:**
- Event-level recall ≥95% (ShieldOps catches ≥95% of Splunk alerts)
- False-positive rate ≤ Splunk baseline + 5 percentage points

Discrepancies → triage into three buckets:
1. **ShieldOps missed it** — tune policy condition
2. **Splunk false positive** — expected improvement, record as a win
3. **Legitimate difference** — document and get customer sign-off

### 2.4 Exit criteria for phase 2

- [ ] 100% of in-scope Splunk alert rules have a ShieldOps policy
- [ ] All policies in audit (observe) mode
- [ ] Alert parity report shows ≥95% recall for 7 days
- [ ] Mapping table fully populated and signed off

---

## Phase 3 — Dashboard recreation (week 3-4)

**Goal:** Every Splunk dashboard the customer actively uses has a ShieldOps equivalent, and stakeholders have approved the new layouts.

### 3.1 Splunk dashboard inventory

Pull the list of dashboards **actually used** in the last 30 days (not all defined dashboards). Use Splunk's audit log:

```spl
index=_audit action=search search="*|dashboard*"
| stats count by user, search_id, dashboard_name
| where count > 5
| sort - count
```

Classify each active dashboard:

| Type | ShieldOps replacement |
|---|---|
| SOC overview / daily standup | **Situations Queue** (outcome-centric) |
| Alert volume / noise trending | **SOC Metrics** dashboard (built-in) |
| Threat hunting workbench | **Threat Hunter** agent UI + NL query |
| Compliance posture (SOC 2, PCI) | **Compliance** dashboard (per-framework) |
| Cloud posture / CSPM | **Unified Cloud Security** dashboard |
| Identity overview | **NHI Registry** + **Identity Intelligence Hub** |
| Executive business value | **Business Value** dashboard + ROI calculator |
| Ad-hoc exploration | **NL Query** + ad-hoc saved views |

### 3.2 Recreate and review

For each customer dashboard:
1. Draft the ShieldOps equivalent (typically 1–2 hours per dashboard — most collapse into existing panels)
2. Walkthrough with the original owner
3. Capture deltas (missing panels, new insights, reduced noise)
4. Get written approval in the migration tracker

Dashboards that collapse into the Situations Queue should be explicitly retired — do not recreate them. Document the rationale so the customer can defend the decision internally.

### 3.3 Exit criteria for phase 3

- [ ] All active dashboards have an approved ShieldOps equivalent or a documented retirement rationale
- [ ] Dashboard owners trained on the replacement
- [ ] Links to new dashboards published in customer runbooks and Slack pinned messages

---

## Phase 4 — Report migration (week 4)

**Goal:** Scheduled reports continue to land in stakeholder inboxes, generated by ShieldOps NL query templates.

### 4.1 Inventory scheduled Splunk reports

```spl
| rest /services/saved/searches
| where is_scheduled=1 AND action.email=1
| table title cron_schedule action.email.to description
```

### 4.2 Convert each report to an NL query template

ShieldOps NL query accepts natural-language prompts and returns structured results. Each Splunk scheduled report becomes a template:

```bash
shieldops nl-query template create \
  --name "weekly-auth-failures-executive" \
  --prompt "Summarize the top 10 users and source IPs with the most failed authentications in the last 7 days, grouped by day. Format as an executive brief." \
  --schedule "0 8 * * MON" \
  --format pdf \
  --recipients security-leadership@cust.com
```

PDF export verification checklist:
- [ ] Rendered PDF layout matches stakeholder expectations (test first three runs)
- [ ] Charts readable on mobile
- [ ] Branding applied (customer logo if configured)
- [ ] Links back to ShieldOps open in authenticated context
- [ ] Delivery confirmed in at least two recipients' inboxes

### 4.3 Exit criteria for phase 4

- [ ] All in-scope scheduled reports migrated
- [ ] One full schedule cycle verified (weekly reports = 2 weeks of runs)
- [ ] Recipients sign off

---

## Phase 5 — SOC team training (week 5)

**Goal:** SOC analysts, incident responders, and on-call engineers can do their job entirely in ShieldOps.

### 5.1 Training sessions

Three live sessions, 90 minutes each, recorded:

1. **Situations Queue + triage** (tier-1 analysts)
   - Working a situation end-to-end
   - Evidence chain, auto-enrichment, agent suggestions
   - Escalation paths
2. **Investigation + threat hunting** (tier-2/3)
   - Investigation agent handoff
   - NL query for ad-hoc hunts
   - Threat hunter agent + hypothesis generation
3. **Incident response + on-call** (IR + on-call engineers)
   - Incident lifecycle: detect → respond → remediate → postmortem
   - Agent firewall interception (for customers running AI agents)
   - PagerDuty / Slack approval flows
   - Runbook execution

### 5.2 Runbook updates

Customer runbooks that reference Splunk dashboards, searches, or alerts must be updated **before** cutover. Deliverable: a PR to the customer's runbook repo with every `splunk` reference replaced by a ShieldOps link.

### 5.3 On-call shadowing week

One full on-call rotation runs in parallel: the on-call engineer primarily uses ShieldOps, falls back to Splunk only if blocked. Collect feedback daily in `#cust-<name>-migration`.

### 5.4 Exit criteria for phase 5

- [ ] All analysts attended training or watched recording + completed a short assessment
- [ ] Runbooks updated and merged
- [ ] Shadow week completed with no blocking issues
- [ ] SOC manager signs off

---

## Phase 6 — Cutover (week 6)

**Goal:** Splunk becomes read-only / is turned off. ShieldOps is the single source of truth for detection and response.

See `docs/runbooks/siem-cutover-checklist.md` for the tick-by-tick cutover checklist. The summary:

1. **T-24h** — final go/no-go call with customer security lead, CSE, on-call manager
2. **T-0** — stop Splunk universal forwarders, disable Splunk alert rules, enable ShieldOps policies in `enforce_mode=True`
3. **T-0 to T+4h** — CSE watches situations queue, validates alert flow, confirms no regressions
4. **T+24h** — daily verification standup begins (runs for 7 days)

### 6.1 Commands

```bash
# Stop universal forwarders across the fleet (customer-managed)
ansible -i inventory splunk_forwarders -m service \
  -a "name=SplunkForwarder state=stopped enabled=no"

# Disable all Splunk ES correlation searches
curl -k -u admin:$PASS -X POST \
  "https://splunk.example.com:8089/services/saved/searches/<name>/disable"

# Enable ShieldOps policies in enforce mode
shieldops policy set-mode --all --mode enforce --tenant <customer>

# Confirm ingestion uptick
shieldops metrics ingestion --tenant <customer> --window 1h
```

### 6.2 Final smoke test (T-0 + 30 min)

Run the smoke-test suite:
```bash
python scripts/migration/parallel_run_validator.py \
  --mode smoke \
  --tenant <customer> \
  --out reports/cutover-smoke-$(date +%Y%m%d-%H%M).md
```

Required checks:
- [ ] All critical policies report ≥1 evaluation in the last 10 minutes
- [ ] Slack / PagerDuty integration delivers a test notification
- [ ] NL query responds in <5 seconds
- [ ] Compliance dashboard loads without errors
- [ ] Situations queue receiving new situations

### 6.3 Exit criteria for phase 6

- [ ] Splunk forwarders stopped and verified via telemetry
- [ ] ShieldOps in enforce mode, no elevated errors for 4 hours
- [ ] Customer security lead and on-call manager formally accept cutover
- [ ] Cutover retro scheduled for end of week 7

---

## Phase 7 — Post-cutover (week 7-8)

**Goal:** The migration is finalized, savings are booked, and the customer is set up for steady-state operation.

### 7.1 Daily verification (7 days)

Each day for a week, the CSE runs:
```bash
shieldops health --tenant <customer> --full
shieldops metrics situations --tenant <customer> --window 24h
shieldops metrics alert-parity --tenant <customer> --baseline splunk --window 24h
```

Any regression vs. the parallel-run baseline is triaged same-day.

### 7.2 Splunk cost saved reconciliation

1. Pull the last full Splunk invoice
2. Compute the savings:
   ```
   annual_savings = (splunk_annual_cost - shieldops_annual_cost)
   savings_pct    = annual_savings / splunk_annual_cost
   payback_months = onboarding_fee / (annual_savings / 12)
   ```
3. Record in the customer's Business Value dashboard — this is the headline ROI number and feeds the quarterly business review.
4. See `docs/runbooks/siem-cost-comparison.md` for the worksheet.

### 7.3 Performance baseline

Capture 7-day post-cutover baselines for:
- MTTD per severity
- MTTR per severity
- Situations created / resolved / escalated
- False-positive rate
- Analyst hours on triage (via operations engine)

Compare against pre-migration baseline. Publish in customer success retro deck.

### 7.4 Decommission Splunk

Only after 14 days of clean operation:
1. Export compliance-mandated historical data from Splunk to cold storage (S3 Glacier or equivalent)
2. Archive `savedsearches.conf`, dashboards, lookups to the customer's migration repo
3. Power down Splunk indexers (keep search heads for 30 days read-only if compliance requires)
4. Cancel Splunk renewal / downsize contract
5. Remove Splunk forwarders from golden images and configuration management

### 7.5 Issue triage

Track any post-cutover issues in the customer's shared folder with fields: `discovered_at`, `severity`, `owner`, `root_cause`, `resolution`, `preventive_action`. Review in the customer success retro.

### 7.6 Exit criteria for phase 7

- [ ] 7 days of clean daily verification
- [ ] Cost reconciliation reviewed with customer finance
- [ ] Performance baseline published
- [ ] Splunk decommission ticket closed
- [ ] Customer success retro complete, lessons learned logged

---

## Roles and responsibilities

| Role | Pre | P1 | P2 | P3 | P4 | P5 | P6 | P7 |
|---|---|---|---|---|---|---|---|---|
| ShieldOps CSE | Lead | Lead | Lead | Drive | Drive | Drive | Lead | Lead |
| Customer security lead | Approve | Review | Review | Approve | Approve | Approve | Approve | Review |
| Customer SOC manager | Input | — | Input | Approve | Input | Lead | Approve | Review |
| Customer IT ops | Input | Execute | — | — | — | — | Execute | Execute |
| ShieldOps support | — | On-call | On-call | On-call | On-call | On-call | **On-call+** | On-call |
| Executive sponsor | Approve | — | — | — | — | — | Sign-off | Retro |

---

## References

- `docs/runbooks/siem-cutover-checklist.md` — tick-by-tick cutover checklist + rollback
- `docs/runbooks/siem-cost-comparison.md` — ROI worksheet with example
- `docs/customer-stories/siem-migration-template.md` — post-migration case study template
- `scripts/migration/parallel_run_validator.py` — parity validator (phase 1, 2, 6)
- `src/shieldops/api/routes/nl_query.py` — NL query API (phase 4 reports)
- `src/shieldops/api/routes/evolution.py` — fitness tracking for policy evolution (phase 7)
- `docs/strategy/crowdstrike-disruption-plan.md` — strategic context
- [Situations Queue UX](../../dashboard-ui/README.md)

## Change log

| Date | Author | Change |
|---|---|---|
| 2026-04-05 | CSE team | Initial runbook for design partner engagements (issue #240) |
