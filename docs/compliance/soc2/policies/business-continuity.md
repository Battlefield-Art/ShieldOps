# Business Continuity and Disaster Recovery Policy

**Document ID:** SHIELDOPS-POL-BC-001
**Version:** 1.1
**Owner:** Head of Engineering (interim: CTO)
**Approved By:** CEO
**Effective Date:** 2026-02-01
**Last Reviewed:** 2026-04-01
**Next Review:** 2027-02-01

## 1. Purpose

This policy defines how ShieldOps plans for, tests, and executes recovery from significant disruptions. It supports SOC 2 criterion **A1.2** (Availability) and the recovery sub-controls of **CC7.5**.

## 2. Recovery Objectives

ShieldOps commits to the following objectives for the production SaaS tier. Objectives are tracked in `src/shieldops/sla/` and reported to customers via the status page.

| Metric                           | Production SaaS  | Notes                                                                 |
|----------------------------------|:----------------:|-----------------------------------------------------------------------|
| **RPO** (data loss tolerance)   | <= 5 minutes     | PostgreSQL continuous WAL shipping to a second AZ + cross-region snap |
| **RTO** (time to restore)        | <= 1 hour        | From declared disaster to customer-serving state                      |
| **MTPoD** (max tolerable outage) | 4 hours          | Beyond this, contractual credits apply                                |
| **Availability SLO**             | 99.9% monthly    | Excluding scheduled maintenance windows (max 2 hours/month)           |

Self-hosted deployments inherit the customer's own infrastructure RPO/RTO and are out of scope for this policy.

## 3. Scenarios Planned For

1. **Single-AZ failure.** Mitigated by multi-AZ deployment (Kubernetes nodes across 3 AZs, PostgreSQL primary + standby in different AZs, Redis cluster mode).
2. **Regional failure.** Mitigated by cross-region snapshots (daily) and runbook to spin up in the DR region (`us-west-2`). Accepted RPO in this scenario: up to 24 hours.
3. **Corrupted deployment.** Mitigated by rollback (`procedures/deployment-approval.md`), feature flags, and backup restore.
4. **Ransomware / destructive attack.** Mitigated by immutable backups (S3 Object Lock compliance mode) and the break-glass restore procedure.
5. **Key personnel unavailability.** Mitigated by cross-training, on-call rotation, and the 1Password shared vault.
6. **Upstream vendor outage.** Mitigated per vendor: LLM router fallback (Anthropic -> OpenAI -> Bedrock), multi-IdP trust, etc.
7. **Loss of source code hosting.** Mitigated by nightly mirror of all GitHub repos to `s3://shieldops-git-mirror/` (encrypted, versioned, Object Lock).

## 4. Architecture Controls

- **Compute:** EKS with min 3 nodes per AZ, PDBs set, HPA targeting 65% CPU.
- **Data:** PostgreSQL (Aurora) multi-AZ, automated backups (35-day retention), PITR enabled. Logical backups exported daily to `s3://shieldops-backups/pg/` in a second region.
- **Cache / queue:** Redis cluster, Kafka with min in-sync replicas = 2, replication factor = 3.
- **Ingress:** Multi-AZ ALB, Cloudflare in front with failover pool.
- **DNS:** Route53 with health checks and failover records; TTL 60s for critical records.
- **Secrets:** AWS Secrets Manager with cross-region replication; 1Password as out-of-band backup.

## 5. Backup and Restore

Full details in `procedures/backup-and-restore.md`. Summary:

- **Database snapshots:** Continuous (Aurora), plus a logical dump daily.
- **Object storage:** Versioning + Object Lock on audit and evidence buckets.
- **Configuration:** Terraform state versioned and locked in S3 + DynamoDB.
- **Restore test:** At least **one** restore test per quarter, to a scratch environment. Restore time recorded; deviation from RTO triggers an improvement ticket.

## 6. Testing

- **Quarterly DR drill.** A live drill where an on-call engineer simulates the loss of the primary database or primary region. Scored on: RTO achieved, RPO achieved, steps that needed clarification, runbook gaps. Results documented in Notion and reviewed by the Head of Engineering.
- **Annual full-scale exercise.** Includes communications, customer notification rehearsal, and executive involvement. Covers a multi-hour scenario.
- **Chaos engineering.** Continuous low-impact fault injection in staging via `src/shieldops/operations/chaos_*`. Failures surface as normal incident events.

## 7. Communications During a Disaster

- Internal: Slack `#incidents` + PagerDuty bridge.
- External: `status.shieldops.io` (hosted separately in a third region) + email to designated customer security contacts.
- Cadence: status page update every 30 minutes during SEV1, every hour during SEV2, until resolution.
- Post-mortem: published within 10 business days, redacted as needed.

## 8. Business Impact Analysis (BIA)

Conducted annually. Current top-three critical processes:

1. **Agent execution pipeline** — customer alerts, investigations, remediations. MTD: 1 hour.
2. **Audit logging and retention** — regulatory obligation. MTD: must never lose durability.
3. **Authentication and authorization** — blocks all other access. MTD: 30 minutes.

Non-critical processes (MTD >= 24h): marketing site, billing reconciliation, reporting exports.

## 9. Review and Maintenance

- Policy reviewed annually and after any SEV1 incident.
- Runbooks reviewed after each DR drill.
- On-call rotation and paging tree verified monthly.

## 10. Enforcement and Exceptions

See `policies/access-control.md` §10 and §11.

## 11. References

- `policies/incident-response.md`
- `procedures/backup-and-restore.md`
- `procedures/deployment-approval.md`
- SOC 2 TSC: A1.2, CC7.5.
