# Procedure: Backup and Restore

**Document ID:** SHIELDOPS-PROC-BC-001
**Version:** 1.1
**Owner:** Head of Engineering (interim: CTO)
**Related Policy:** `policies/business-continuity.md`, `policies/data-classification.md`
**Last Reviewed:** 2026-04-01

## 1. Purpose

Define how ShieldOps backs up production data, verifies those backups, and restores from them.

## 2. What Is Backed Up

| Asset                              | Mechanism                                    | Frequency          | Retention     | Target     |
|------------------------------------|----------------------------------------------|--------------------|---------------|------------|
| PostgreSQL (primary)               | Aurora continuous backup + PITR              | Continuous (WAL)   | 35 days       | us-east-1  |
| PostgreSQL (logical)               | `pg_dump` to encrypted S3                    | Daily 03:00 UTC    | 90 days       | us-west-2  |
| S3 — audit logs                    | Versioning + Object Lock (compliance, 7y)    | Real-time          | 7 years       | us-east-1 + us-west-2 (replication) |
| S3 — customer telemetry            | Versioning                                    | Real-time          | Per retention | us-east-1  |
| Kafka topics (critical)            | Mirror to cold store via `kafka-connect-s3`  | Continuous         | 30 days       | us-east-1  |
| Kubernetes manifests               | Git (GitOps source of truth)                 | On change          | Indefinite    | GitHub + S3 mirror |
| Terraform state                    | S3 versioned with DynamoDB lock              | On change          | Indefinite    | us-east-1  |
| Secrets Manager                    | Cross-region replication                     | On change          | 90 days deleted recovery | us-east-1 + us-west-2 |
| 1Password shared vaults            | 1Password cloud (vendor-managed)             | Continuous         | Vendor        | Vendor     |
| Git repositories                   | Nightly mirror to `s3://shieldops-git-mirror/` | Nightly          | 90 days       | us-west-2  |

All backups are encrypted at rest (see `policies/encryption.md`).

## 3. Daily Automated Job

A scheduled job (`scripts/backups/daily_snapshot.py`, runs at 03:00 UTC via a Kubernetes CronJob) performs the following and exits non-zero if any step fails:

1. Trigger a logical `pg_dump` of the production database.
2. Encrypt (via KMS) and upload to `s3://shieldops-backups/pg/<date>.sql.gz.enc`.
3. Record metadata in the `backup_runs` table: bucket, key, size, SHA-256, duration, status.
4. Emit a metric `shieldops_backup_success` for Datadog.
5. Page on-call if a failure occurs or if no backup completed within 25 hours.

## 4. Weekly Restore Test

Every Monday at 10:00 UTC, `scripts/backups/restore_test.py` runs against the scratch environment `restore-verify`:

1. Pick the most recent logical backup from S3.
2. Spin up a temporary Aurora instance in the scratch VPC.
3. Restore the backup.
4. Run a fixed set of smoke queries: row counts by table, critical foreign key joins, latest audit log entries.
5. Record the result in `restore_tests` table: backup restored, rows verified, duration, pass/fail.
6. Tear down the Aurora instance.
7. Post result to `#platform-ops` in Slack.

A failed restore test is a SEV2 incident.

## 5. Quarterly DR Drill

Once per calendar quarter, an on-call engineer runs a declared DR drill that additionally exercises:

- Standing up the production environment in us-west-2 from the latest cross-region backup.
- Validating that an end-to-end customer request flow works in the DR region.
- Measuring the elapsed wall-clock time from drill start to first successful request. Compared to the RTO objective in `policies/business-continuity.md` §2.

Drill results go into the `dr_drills` Notion database and are reviewed by the Head of Engineering.

## 6. On-Demand Restore (Production)

Used during an incident where data loss or corruption is confirmed. This is a high-risk operation; IC approval is mandatory.

### 6.1 Decide the target point

- For recent corruption: PITR to a timestamp just before the corruption.
- For loss of an entire table: logical restore into a separate database, then selectively re-insert.
- For regional loss: cross-region restore in us-west-2.

### 6.2 Steps

1. IC assembles: on-call DB engineer, Head of Engineering, Head of Security (if customer data is affected).
2. IC declares a pre-restore snapshot of the current state (even if corrupted) for forensic purposes.
3. On-call DB engineer performs the restore into an **isolated target**, not directly over production.
4. Smoke queries verify the restored data.
5. IC decides: cut over to the restored database, or selectively copy data back.
6. Cutover is a change: logged in `audit_log` as `action="db_restore_cutover"`.
7. Post-restore: monitor for 24 hours, write post-mortem.

### 6.3 Customer data impact

If the restore implies loss of customer data (e.g., reverting to an earlier point in time):

- Identify affected customers using the `audit_log` and telemetry timestamps.
- Communications Lead notifies affected customers within the SEV1 timeline (see `procedures/incident-escalation.md`).
- Document the data loss window in the post-mortem.

## 7. Access Control on Backups

- Only the `backup-writer` IAM role (used by the CronJob) can write to `s3://shieldops-backups/`.
- Only the `backup-reader` IAM role (used during restore) can read.
- Bucket has Object Lock in governance mode with a 35-day retention for `pg/` prefix; audit log bucket uses compliance mode with 7-year retention.
- Human access to read a backup requires a break-glass request approved by Head of Security; use is recorded in `audit_log`.

## 8. Evidence Collected

- `backup_runs` table — every snapshot attempt.
- `restore_tests` table — every weekly restore result.
- `dr_drills` Notion — quarterly drill reports.
- S3 bucket inventory reports.
- `scripts/audit/collect_evidence.py --section backups` aggregates these for the SOC 2 audit window.
