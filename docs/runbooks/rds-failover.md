# RDS Multi-AZ Failover

Force a failover of the production PostgreSQL RDS instance from primary to standby.

## When to use
- Primary instance CPU / IO pinned and not recovering.
- Scheduled maintenance that requires AZ migration.
- Testing failover behavior (quarterly drill).
- Engine minor version upgrade where Multi-AZ rolling apply is safer.

## Prerequisites
- AWS SSO `shieldops-production` with `rds-operator` role.
- RDS instance `shieldops-production-postgres` has `MultiAZ=true` (verified).
- Change approved in Jira / change management.
- On-call acknowledged expected ~30-90 second connection blip.

## Expected impact
- 30-90 seconds of dropped connections during failover.
- Worker retries and connection pool reconnect automatically.
- User-visible: brief 5xx spike on API during reconnect; then recovers.

## Steps

1. **Pre-checks**
   ```bash
   aws rds describe-db-instances \
     --db-instance-identifier shieldops-production-postgres \
     --query 'DBInstances[0].{Status:DBInstanceStatus,MultiAZ:MultiAZ,AZ:AvailabilityZone,SecondaryAZ:SecondaryAvailabilityZone,Engine:EngineVersion}'
   ```
   Confirm `Status=available`, `MultiAZ=true`, and note primary/secondary AZs.

2. **Announce in `#incidents`** with start time, expected duration, impact.

3. **Trigger failover**
   ```bash
   aws rds reboot-db-instance \
     --db-instance-identifier shieldops-production-postgres \
     --force-failover
   ```

4. **Watch state transitions**
   ```bash
   watch -n 5 'aws rds describe-db-instances \
     --db-instance-identifier shieldops-production-postgres \
     --query "DBInstances[0].{Status:DBInstanceStatus,AZ:AvailabilityZone}"'
   ```
   Expect: `available` → `rebooting` → `available` (1-2 min).

5. **Verify AZ flipped**
   ```bash
   aws rds describe-events \
     --source-identifier shieldops-production-postgres \
     --source-type db-instance \
     --duration 10 \
     --query 'Events[].{Time:Date,Message:Message}'
   ```
   Look for "Multi-AZ instance failover completed".

6. **Smoke test API**
   ```bash
   curl -fsSL https://api.shieldops.io/healthz
   curl -fsSL https://api.shieldops.io/api/v1/system/db/ping
   ```

## Verification
- RDS `Status=available` with the standby AZ now serving as primary.
- Application logs show reconnect messages (normal).
- CloudWatch: `DatabaseConnections` returns to baseline within 3 minutes.
- No sustained 5xx alarm.
- RDS events log shows failover-complete message.

## Rollback
Failover is bidirectional — run the same command again to swap back. Only do this if AZ imbalance is causing issues.

## Drill schedule
Run quarterly, first Tuesday of the quarter, 10:00 UTC, 15-minute window.
