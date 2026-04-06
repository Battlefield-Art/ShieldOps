# SIEM Cutover Checklist: Splunk → ShieldOps

> Companion checklist to `siem-migration.md`. Use this for the actual T-0 cutover window.
> **Window:** 4 hours. **Owner:** ShieldOps Customer Success Engineer. **Approver:** Customer Security Lead.

---

## How to use this document

Print or open in a shared doc. Tick boxes in real time. Every box **must** be ticked or formally waived by the customer security lead before proceeding to the next section. If any item fails, halt and consult the rollback plan.

---

## Pre-cutover (T-24h)

Run a final go/no-go meeting. Attendees: CSE, customer security lead, SOC manager, IT ops lead, on-call engineer, executive sponsor (optional).

### Alert rule parity

- [ ] All Splunk alert rules have a ShieldOps policy (mapping table 100% complete)
- [ ] 7-day alert parity report shows ≥95% recall per rule
- [ ] Every rule with <95% recall has a documented, signed-off exception
- [ ] All policies currently in **audit** mode
- [ ] Policy-evolution fitness scores show stable trend (no open regressions)

### Dashboards

- [ ] All active Splunk dashboards have an approved ShieldOps equivalent **or** a retirement rationale
- [ ] Dashboard owners confirmed the replacement meets their needs
- [ ] Links to new dashboards published in customer runbook index
- [ ] Slack pinned messages updated

### Reports

- [ ] All scheduled reports migrated to NL query templates
- [ ] At least one full schedule cycle verified (weekly = 2 runs, daily = 5 runs)
- [ ] PDF output approved by recipients
- [ ] Delivery lists verified (no stale recipients)

### SOC readiness

- [ ] SOC team training complete (all three sessions)
- [ ] Analyst assessment pass rate ≥90%
- [ ] Runbooks updated — all Splunk references replaced, PR merged
- [ ] On-call shadow week complete with no blocking issues
- [ ] On-call engineer for cutover window named and acknowledged

### Operational prerequisites

- [ ] ShieldOps health check green for 72 hours (`shieldops health --full`)
- [ ] No open P0/P1 ShieldOps platform incidents
- [ ] ShieldOps support engineer on standby for the cutover window
- [ ] Slack bridge `#cust-<name>-migration` has CSE, customer lead, IT ops, on-call
- [ ] PagerDuty escalation tree tested end-to-end
- [ ] Jira / ServiceNow integration tested (ticket creation + update)

### Rollback preparedness

- [ ] Rollback plan reviewed (this document, section below)
- [ ] Splunk license remains valid through at least 30 days post-cutover
- [ ] Splunk admin credentials available to the CSE (sealed envelope / vault)
- [ ] Configuration management (Ansible / Chef / Puppet) verified — can re-enable forwarders within 15 minutes

### Sign-offs (T-24h)

- [ ] Customer security lead: _______________________
- [ ] Customer SOC manager: _______________________
- [ ] ShieldOps CSE: _______________________
- [ ] Executive sponsor (optional): _______________________

**Decision:** GO / NO-GO (circle one). If NO-GO, reschedule and document blockers.

---

## Cutover (T-0)

Run the cutover during the approved change window. Target window: 4 hours. Expected active work: 45–60 minutes.

### T-0 :00 — Open the window

- [ ] Post in `#cust-<name>-migration`: "Cutover starting — T-0"
- [ ] Open the ShieldOps situations queue, compliance dashboard, and SOC metrics dashboard as live tabs
- [ ] Open PagerDuty schedule and confirm on-call engineer
- [ ] Start screen recording of the cutover session (retention: 90 days)

### T-0 :05 — Freeze Splunk changes

- [ ] Disable any automated Splunk deployments (CI/CD, configuration management)
- [ ] Notify Splunk admins not to push changes

### T-0 :10 — Stop Splunk forwarders

```bash
ansible -i inventory splunk_forwarders -m service \
  -a "name=SplunkForwarder state=stopped enabled=no"
```

- [ ] Ansible / Chef / Puppet run completed
- [ ] Spot-check 10 random hosts: `systemctl status SplunkForwarder`
- [ ] Splunk indexer ingest rate drops to near-zero within 5 minutes (`index=_internal source=*metrics.log group=per_sourcetype_thruput`)

### T-0 :20 — Verify ShieldOps ingestion uptick

- [ ] `shieldops metrics ingestion --tenant <customer> --window 15m` shows expected volume increase
- [ ] No connector error rate elevation (`shieldops connectors status --tenant <customer>`)
- [ ] Kafka consumer lag within normal bounds

### T-0 :25 — Disable Splunk alert rules

```bash
# Disable all ES correlation searches
for rule in $(cat mapping-table.csv | tail -n +2 | cut -d, -f1); do
  curl -k -u admin:$PASS -X POST \
    "https://splunk.example.com:8089/services/saved/searches/${rule// /%20}/disable"
done
```

- [ ] All rules in mapping table disabled
- [ ] Spot-check: `| rest /services/saved/searches | where is_scheduled=1 AND disabled=0` returns only non-migrated rules (ideally empty)

### T-0 :30 — Enable ShieldOps policies in enforce mode

```bash
shieldops policy set-mode --all --mode enforce --tenant <customer>
shieldops policy list --tenant <customer> --mode enforce | wc -l
```

- [ ] Policy count matches the mapping-table count
- [ ] Audit log shows the mode change with CSE identity

### T-0 :35 — Final smoke test

```bash
python scripts/migration/parallel_run_validator.py \
  --mode smoke \
  --tenant <customer> \
  --out reports/cutover-smoke-$(date +%Y%m%d-%H%M).md
```

- [ ] All critical policies report ≥1 evaluation in the last 10 minutes
- [ ] Slack test notification delivered
- [ ] PagerDuty test incident delivered and auto-resolved
- [ ] NL query responds in <5 seconds with expected result
- [ ] Compliance dashboard loads without errors
- [ ] Situations queue has at least one active situation (even informational)

### T-0 :45 — Customer sign-off on cutover

- [ ] Customer security lead reviews the smoke test output
- [ ] Customer security lead confirms in Slack: "Cutover accepted"
- [ ] CSE posts the sign-off screenshot to the migration folder

### T-0 :45 to T+4h — Active monitoring

The CSE stays at the keyboard for 4 hours. Checks every 30 minutes:

- [ ] **T+00:30** ingestion rate stable, error rate nominal, situation volume within expected range
- [ ] **T+01:00** same checks + spot-check three high-severity policies evaluated at least once
- [ ] **T+01:30** same checks + verify at least one scheduled report ran (if window includes a report schedule)
- [ ] **T+02:00** same checks + analyst shadow: watch an active situation being worked
- [ ] **T+02:30** same checks + review any customer-reported issues
- [ ] **T+03:00** same checks + pull a 3-hour MTTD/MTTR snapshot
- [ ] **T+03:30** same checks
- [ ] **T+04:00** close the cutover window: post summary in `#cust-<name>-migration`, stop screen recording

---

## Post-cutover (T+24h through T+7d)

### Daily verification (run each day for 7 days)

- [ ] `shieldops health --tenant <customer> --full` → all green
- [ ] `shieldops metrics situations --tenant <customer> --window 24h` → within expected range
- [ ] `shieldops metrics alert-parity --tenant <customer> --baseline splunk --window 24h` → ≥95%
- [ ] Spot-check 3 situations resolved in the last 24h (quality of evidence + agent outputs)
- [ ] Customer-reported issues reviewed and triaged
- [ ] Daily post in `#cust-<name>-migration` with the verification summary

### Week-1 milestones

- [ ] **T+24h** first daily verification complete
- [ ] **T+48h** on-call handoff proceeds normally without CSE hand-holding
- [ ] **T+72h** executive sponsor briefed with 72-hour summary
- [ ] **T+7d** customer success retro scheduled

### Cost reconciliation (T+14d)

- [ ] Splunk invoice for the cutover month pulled
- [ ] Annual savings computed (see `siem-cost-comparison.md`)
- [ ] Business Value dashboard updated
- [ ] Finance stakeholder briefed

### Splunk decommission (T+14d)

- [ ] Historical data exported to cold storage (compliance retention requirements)
- [ ] Splunk configuration archived to customer migration repo
- [ ] Splunk indexers powered down (search heads may remain read-only for 30 days)
- [ ] Splunk renewal cancelled or contract downsized
- [ ] Forwarders removed from golden images

### Customer success retro (T+14d)

- [ ] Attended by: CSE, customer security lead, SOC manager, executive sponsor
- [ ] What worked / what didn't / what to change
- [ ] Lessons learned fed back into this playbook (PR to `docs/runbooks/siem-migration.md`)

---

## Rollback plan

Rollback is available up to **T+72 hours** after cutover. After 72 hours, the operational cost of re-enabling Splunk alert rules and catching up stale dashboards exceeds the value — fix forward instead.

### Rollback triggers

Any one of the following triggers an immediate rollback decision call:

- Critical alert rule silently stops firing for >30 minutes
- ShieldOps platform P0 incident lasting >15 minutes
- Connector outage affecting >25% of data sources for >30 minutes
- Customer security lead loses confidence and requests rollback
- Compliance auditor raises a blocking finding

### Rollback procedure (target: 15 minutes)

1. **Decision call (5 min)**
   - CSE + customer security lead + on-call engineer
   - Decision logged in `#cust-<name>-migration` with timestamp and reason

2. **Re-enable Splunk forwarders**
   ```bash
   ansible -i inventory splunk_forwarders -m service \
     -a "name=SplunkForwarder state=started enabled=yes"
   ```
   - [ ] All forwarders re-started
   - [ ] Splunk indexer ingest rate recovers within 10 minutes

3. **Re-enable Splunk alert rules**
   ```bash
   for rule in $(cat mapping-table.csv | tail -n +2 | cut -d, -f1); do
     curl -k -u admin:$PASS -X POST \
       "https://splunk.example.com:8089/services/saved/searches/${rule// /%20}/enable"
   done
   ```
   - [ ] All rules re-enabled
   - [ ] Spot-check: Splunk ES shows correlation searches running

4. **Disable ShieldOps enforce mode**
   ```bash
   shieldops policy set-mode --all --mode audit --tenant <customer>
   ```
   - [ ] All policies back to audit
   - [ ] Audit log shows mode change

5. **Notify stakeholders**
   - [ ] Post in `#cust-<name>-migration`: "Rollback complete at T+<offset>. Splunk is primary."
   - [ ] Executive sponsor notified via direct message
   - [ ] PagerDuty incident opened for the rollback with root-cause pending

6. **Root-cause analysis (within 48 hours)**
   - [ ] Incident postmortem drafted
   - [ ] Root cause identified
   - [ ] Fix plan approved
   - [ ] New cutover date proposed

### Rollback sign-offs

- [ ] Customer security lead: _______________________
- [ ] ShieldOps CSE: _______________________
- [ ] On-call engineer: _______________________

---

## Emergency contacts

| Role | Name | Contact | Escalation |
|---|---|---|---|
| ShieldOps CSE | | | Primary |
| ShieldOps on-call (platform) | | PagerDuty `shieldops-platform` | L1 |
| ShieldOps VP Customer Success | | | L2 |
| Customer security lead | | | Primary |
| Customer SOC manager | | | L1 |
| Customer CISO | | | L2 |
| Customer IT ops on-call | | | For forwarder issues |

---

## References

- `docs/runbooks/siem-migration.md` — full migration playbook
- `docs/runbooks/siem-cost-comparison.md` — ROI worksheet
- `scripts/migration/parallel_run_validator.py` — parity validator
- `docs/runbooks/rollback-deployment.md` — ShieldOps platform rollback procedure
