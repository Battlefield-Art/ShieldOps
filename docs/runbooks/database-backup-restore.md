# Database Backup & Restore

Restore the production PostgreSQL database from an automated or manual RDS snapshot.

## When to use
- Data corruption requiring point-in-time recovery (PITR).
- Accidental destructive DDL / DML (e.g., wrong-env apply, runaway migration).
- Security incident requiring forensic snapshot.
- Quarterly restore drill (verifies backup chain end-to-end).

## Automated backup verification
A Lambda runs weekly (`shieldops-production-backup-test`) restoring the latest automated snapshot into an ephemeral instance and tearing it down. Failures alert the on-call via PagerDuty. See `infrastructure/terraform/aws/production/backups.tf`.

## Prerequisites
- AWS SSO `shieldops-production` with `db-operator` role.
- Incident declared if this is a recovery operation.
- Engineering + product sign-off on data loss window.
- `psql` + `pg_dump` installed.

## Backup inventory

```bash
# Automated snapshots (retention: 7 days)
aws rds describe-db-snapshots \
  --db-instance-identifier shieldops-production-postgres \
  --snapshot-type automated \
  --query 'DBSnapshots[].{Id:DBSnapshotIdentifier,Time:SnapshotCreateTime,Status:Status}' \
  --output table

# Manual snapshots
aws rds describe-db-snapshots \
  --db-instance-identifier shieldops-production-postgres \
  --snapshot-type manual \
  --output table
```

## Take a manual snapshot

```bash
aws rds create-db-snapshot \
  --db-instance-identifier shieldops-production-postgres \
  --db-snapshot-identifier shieldops-production-manual-$(date +%Y%m%d%H%M%S) \
  --tags Key=Purpose,Value=pre-migration
```

## Restore path A — Point-in-time recovery (preferred)

1. **Choose a restore time** (UTC, within the 7-day PITR window).
2. **Restore to a new instance**
   ```bash
   aws rds restore-db-instance-to-point-in-time \
     --source-db-instance-identifier shieldops-production-postgres \
     --target-db-instance-identifier shieldops-production-postgres-restore \
     --restore-time 2026-04-05T14:23:00Z \
     --db-subnet-group-name shieldops-production-db-subnet \
     --vpc-security-group-ids sg-xxxxxxxx \
     --db-instance-class db.r6g.xlarge \
     --multi-az \
     --no-publicly-accessible
   ```
3. **Wait**
   ```bash
   aws rds wait db-instance-available \
     --db-instance-identifier shieldops-production-postgres-restore
   ```

## Restore path B — From a specific snapshot

```bash
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier shieldops-production-postgres-restore \
  --db-snapshot-identifier <snapshot-id> \
  --db-subnet-group-name shieldops-production-db-subnet \
  --vpc-security-group-ids sg-xxxxxxxx \
  --db-instance-class db.r6g.xlarge \
  --multi-az \
  --no-publicly-accessible
```

## Cutover (promote restored instance to production)

1. **Validate** the restored instance:
   ```bash
   psql -h <restored-endpoint> -U shieldops_admin -d shieldops -c 'SELECT count(*) FROM incidents;'
   ```
2. **Communicate** downtime window in `#incidents`.
3. **Stop writes**: set ECS desired count of API/worker to 0.
   ```bash
   for svc in shieldops-api shieldops-worker; do
     aws ecs update-service --cluster shieldops-production --service $svc --desired-count 0
   done
   ```
4. **Rename instances** to swap:
   ```bash
   aws rds modify-db-instance \
     --db-instance-identifier shieldops-production-postgres \
     --new-db-instance-identifier shieldops-production-postgres-old \
     --apply-immediately
   aws rds wait db-instance-available --db-instance-identifier shieldops-production-postgres-old

   aws rds modify-db-instance \
     --db-instance-identifier shieldops-production-postgres-restore \
     --new-db-instance-identifier shieldops-production-postgres \
     --apply-immediately
   aws rds wait db-instance-available --db-instance-identifier shieldops-production-postgres
   ```
5. **Restart services**:
   ```bash
   for svc in shieldops-api shieldops-worker; do
     aws ecs update-service --cluster shieldops-production --service $svc --desired-count 6 --force-new-deployment
   done
   ```
6. **Smoke test**: `curl -fsSL https://api.shieldops.io/healthz`.

## Verification
- New instance serving traffic, connections rising to baseline.
- Application healthchecks green.
- Row counts on critical tables match expected values.
- No new errors in logs.

## Cleanup (after verification window — 72 hours)
```bash
aws rds delete-db-instance \
  --db-instance-identifier shieldops-production-postgres-old \
  --skip-final-snapshot \
  --delete-automated-backups
```

## Drill schedule
Quarterly. First Wednesday of the quarter, 14:00 UTC. Drill restores to a non-production identifier and runs schema/row-count validation without cutover.
