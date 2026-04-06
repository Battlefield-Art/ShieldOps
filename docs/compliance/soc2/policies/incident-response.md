# Incident Response Policy

**Document ID:** SHIELDOPS-POL-IR-001
**Version:** 1.3
**Owner:** Head of Security (interim: CTO)
**Approved By:** CEO
**Effective Date:** 2026-01-15
**Last Reviewed:** 2026-04-01
**Next Review:** 2026-07-01

## 1. Purpose

This policy defines how ShieldOps detects, triages, contains, eradicates, recovers from, and learns from security incidents. It supports SOC 2 criteria **CC7.2, CC7.3, CC7.4, CC7.5** and **A1.2** (Availability). It applies to all ShieldOps personnel and to any incident affecting the confidentiality, integrity, or availability of the ShieldOps platform or the data we process on behalf of customers.

## 2. Definitions

- **Event** — Any observed occurrence in a system (log line, metric spike, alert). Not all events are incidents.
- **Security incident** — A confirmed or suspected violation of confidentiality, integrity, or availability, or a policy violation with security implications.
- **Breach** — An incident where Restricted data was, or is reasonably believed to have been, accessed by an unauthorized party.
- **Near miss** — An incident that was detected and contained before impact. Still recorded and reviewed.

## 3. Severity Levels

| Severity | Definition                                                                                                             | Initial Response SLA | Resolution SLA |
|:--------:|------------------------------------------------------------------------------------------------------------------------|:--------------------:|:--------------:|
| **SEV1** | Confirmed breach of Restricted data, full platform outage, active exploitation, regulatory reporting threshold crossed | 15 minutes           | 4 hours        |
| **SEV2** | Partial outage, confirmed compromise of non-Restricted data, confirmed malware in production, exploitable CVE unpatched in prod | 30 minutes | 8 hours |
| **SEV3** | Degraded service, suspected compromise, policy violation, minor data integrity bug                                    | 2 hours              | 24 hours       |
| **SEV4** | Informational, near miss, cosmetic issue                                                                               | 1 business day       | 5 business days|

Response SLA is "page-to-ack". Resolution SLA is "ack-to-root-cause-contained", not "fully fixed".

## 4. Roles

- **Incident Commander (IC)** — Owns the incident end-to-end. Assigned by the first responder; can be any engineer on call. Swap IC only via explicit handoff.
- **Communications Lead** — Owns internal and external comms. For SEV1/2, this is the on-call manager or their delegate.
- **Scribe** — Captures the timeline in the incident Slack channel and the war room record (`war_rooms` table).
- **Subject Matter Experts (SMEs)** — Paged by the IC as needed.
- **Executive Sponsor** — CEO (SEV1) or CTO (SEV2). Does not run the response; owns external stakeholder communication.

## 5. Detection Sources

Incidents are detected through:

- ShieldOps platform alerts (eating our own dog food).
- PagerDuty alerts from Datadog / Prometheus / OTel pipeline.
- GitHub security alerts (Dependabot, secret scanning).
- AWS GuardDuty, CloudTrail anomalies.
- Vendor notifications.
- Customer reports via `security@shieldops.io` or in-product support.
- Responsible disclosure via `https://shieldops.io/.well-known/security.txt`.

## 6. Response Phases

### 6.1 Identify

- First responder creates the Slack channel `#inc-YYYYMMDD-<slug>` via the `/incident` Slack command, which invokes `src/shieldops/integrations/slack/incident_create.py`.
- A `war_rooms` record is written; the war room is linked to PagerDuty and a Zoom bridge.
- IC posts the initial situation report: what we know, what we don't, what we're doing next.

### 6.2 Contain

- Immediate actions to stop the bleed: revoke credentials, disable accounts, block IPs at the WAF, scale down a poisoned deployment.
- Containment must be reversible where possible. If a containment action has collateral impact (e.g., tenant isolation), it is itself a change requiring a secondary approver.
- No destructive evidence actions (e.g., terminating instances without a snapshot) without IC explicit approval.

### 6.3 Eradicate

- Remove the root cause: revoke attacker persistence, remove malicious artifacts, patch the vulnerability, rotate secrets.
- Confirm eradication with an independent check (e.g., fresh scan, log review by a second engineer).

### 6.4 Recover

- Restore service. Prefer forward recovery (fix and redeploy) over rollback unless rollback is clearly safer.
- Monitor for recurrence for at least 24 hours after declaring recovery.
- IC declares incident resolved in the Slack channel and updates the `war_rooms` record.

### 6.5 Learn

- A blameless post-mortem is **mandatory** for every SEV1 and SEV2 and strongly encouraged for SEV3.
- Draft due within 5 business days. Review meeting within 10 business days. Owners assigned for action items with due dates.
- Post-mortem document lives in Notion under `Security / Incidents / YYYY`. Linked from the `war_rooms.resolution_summary` field.

## 7. Breach Notification

If Restricted customer data is confirmed or reasonably believed to have been accessed by an unauthorized party:

- **Internal notification:** CEO + Head of Security + Legal within 1 hour of confirmation.
- **Customer notification:** Affected customers within **72 hours** of confirmation (per DPA and GDPR Art. 33–34).
- **Regulatory notification:** As required by applicable law (GDPR 72h, state breach laws). Legal counsel coordinates.
- **Content of notice:** Nature of the incident, categories and approximate number of records, likely consequences, measures taken, contact point.

The communications lead uses the templates in `docs/compliance/soc2/templates/breach-notification/`.

## 8. Evidence Preservation

- All relevant logs, screenshots, memory dumps, and artifacts are placed in the `s3://shieldops-incident-evidence/<incident-id>/` bucket, which has Object Lock enabled (compliance mode, 7-year retention).
- Chain of custody is recorded in the war room timeline with SHA-256 hashes of each artifact.
- Evidence is preserved for a minimum of 1 year, or the duration of any related legal hold, whichever is longer.

## 9. Retention of Incident Records

Incident records (Slack transcripts, post-mortems, war room records, audit log entries) are retained for **7 years**.

## 10. Testing

- Quarterly tabletop exercises covering at least one scenario from: ransomware, credential theft, insider threat, supply chain compromise, cloud account takeover.
- Annual full red-team engagement (external vendor).
- On-call rotation is verified monthly via PagerDuty's live-call routing test.

## 11. External Coordination

- Law enforcement: engagement requires CEO + Legal approval.
- Bug bounty researchers: handled per `docs/security/disclosure.md`; 90-day coordinated disclosure window.
- Customers: primary channel is the customer success manager, backed by a status page posting (`status.shieldops.io`) for any incident visible to multiple customers.

## 12. Enforcement and Exceptions

See `policies/access-control.md` §10 and §11.

## 13. References

- `policies/access-control.md`
- `policies/data-classification.md`
- `procedures/incident-escalation.md`
- `procedures/backup-and-restore.md`
- SOC 2 TSC: CC7.2, CC7.3, CC7.4, CC7.5, A1.2.
