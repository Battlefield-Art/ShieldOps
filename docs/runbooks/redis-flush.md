# Redis Cache Flush / Eviction Recovery

Recover from Redis cache corruption, poisoned entries, or runaway memory pressure.

## When to use
- Application returning stale or corrupt cached data after a schema change.
- `Evictions` metric sustained > 100/min and key space no longer fitting.
- Incident where a bad deploy wrote poisoned cache entries.
- Session store leakage (security incident).

## Prerequisites
- AWS SSO `shieldops-production` with `cache-operator` role.
- `redis-cli` available, or bastion access to ElastiCache.
- Understanding that cache misses will briefly spike DB load.

## Expected impact
- Cold-cache period: 1-5 minutes of elevated RDS load.
- p95 API latency spikes during warmup.
- User sessions in cache will be invalidated (users re-authenticate).

## Steps

### Option A — Targeted key deletion (preferred)

1. **Identify keys**
   ```bash
   REDIS_HOST=$(terraform -chdir=infrastructure/terraform/aws/production output -raw redis_endpoint)
   redis-cli -h $REDIS_HOST --tls --scan --pattern 'session:*' | head
   ```

2. **Delete in batches** (avoid blocking master)
   ```bash
   redis-cli -h $REDIS_HOST --tls --scan --pattern 'session:*' \
     | xargs -n 100 redis-cli -h $REDIS_HOST --tls UNLINK
   ```

### Option B — Per-database flush

```bash
redis-cli -h $REDIS_HOST --tls -n 0 FLUSHDB ASYNC
```

### Option C — Full flush (last resort)

1. **Pre-announce** in `#incidents` — this invalidates all caches.
2. **Flush**
   ```bash
   redis-cli -h $REDIS_HOST --tls FLUSHALL ASYNC
   ```
3. **Watch RDS load**
   ```bash
   aws cloudwatch get-metric-statistics \
     --namespace AWS/RDS \
     --metric-name DatabaseConnections \
     --dimensions Name=DBInstanceIdentifier,Value=shieldops-production-postgres \
     --start-time $(date -u -v-5M +%Y-%m-%dT%H:%M:%SZ) \
     --end-time $(date -u +%Y-%m-%dT%H:%M:%SZ) \
     --period 60 --statistics Average
   ```

### Option D — Replace node (catastrophic corruption)
Use the AWS console to initiate a Redis replication group replacement. This recreates the cluster with the latest snapshot. Expect 5-10 minutes downtime on the cache layer.

## Verification
- `INFO memory` shows `used_memory` dropped (Option B/C).
- `Evictions` metric returns to 0 within 5 minutes.
- Application `cache_hit_ratio` metric recovers within 5-10 minutes.
- RDS connection count returns to baseline.
- No new application errors.

## Prevention
- Use versioned cache keys (`v2:session:...`) to avoid requiring flushes on schema changes.
- Monitor `Evictions` and `DatabaseMemoryUsagePercentage` on the ops dashboard.
- Scale Redis node type when memory sustained > 75%.
