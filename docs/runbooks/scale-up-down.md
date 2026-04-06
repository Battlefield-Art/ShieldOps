# Manual Scale Up / Down

Manually override ECS service autoscaling and scale RDS / Redis / MSK resources.

## When to use
- Planned load event (launch, demo, scheduled batch).
- Autoscaler is too slow to keep up with a spike.
- Cost optimization window (scale down overnight).
- Load test setup / teardown.

## Prerequisites
- AWS SSO `shieldops-production` with `scale-operator` role.
- Budget approval for scale-ups beyond documented steady state.
- Change ticket for scale-downs below minimums.

## Steady-state reference

| Service | Min | Desired | Max |
|---|---|---|---|
| `shieldops-api` | 4 | 6 | 40 |
| `shieldops-worker` | 2 | 4 | 20 |
| RDS | `db.r6g.xlarge` | — | `db.r6g.8xlarge` |
| Redis | 1 shard × 2 replicas | — | 4 shards × 2 replicas |

## Scale ECS service (manual override)

1. **Suspend autoscaling** (optional — only for sustained override)
   ```bash
   aws application-autoscaling register-scalable-target \
     --service-namespace ecs \
     --resource-id service/shieldops-production/shieldops-api \
     --scalable-dimension ecs:service:DesiredCount \
     --suspended-state '{"DynamicScalingInSuspended":true,"DynamicScalingOutSuspended":true,"ScheduledScalingSuspended":true}'
   ```

2. **Set desired count**
   ```bash
   aws ecs update-service \
     --cluster shieldops-production \
     --service shieldops-api \
     --desired-count 20
   ```

3. **Wait for stable**
   ```bash
   aws ecs wait services-stable \
     --cluster shieldops-production \
     --services shieldops-api
   ```

4. **Resume autoscaling** (when override is no longer needed)
   ```bash
   aws application-autoscaling register-scalable-target \
     --service-namespace ecs \
     --resource-id service/shieldops-production/shieldops-api \
     --scalable-dimension ecs:service:DesiredCount \
     --suspended-state '{"DynamicScalingInSuspended":false,"DynamicScalingOutSuspended":false,"ScheduledScalingSuspended":false}'
   ```

## Scale RDS instance class

> Causes brief connection blip (~60s on Multi-AZ, handled by failover).

```bash
aws rds modify-db-instance \
  --db-instance-identifier shieldops-production-postgres \
  --db-instance-class db.r6g.2xlarge \
  --apply-immediately

aws rds wait db-instance-available \
  --db-instance-identifier shieldops-production-postgres
```

## Scale Redis (add shards)

Driven via Terraform — update `redis_num_shards` in `terraform.tfvars`, then:
```bash
terraform -chdir=infrastructure/terraform/aws/production plan -target=aws_elasticache_replication_group.main
terraform -chdir=infrastructure/terraform/aws/production apply -target=aws_elasticache_replication_group.main
```

## Scale MSK (add brokers)

Via AWS Console → MSK → cluster → Actions → Edit number of brokers. Minimum increment = `number_of_broker_nodes_per_az`. Requires rebalance assignment afterwards.

## Verification
- New ECS tasks reach `RUNNING` and pass target group health checks.
- CloudWatch p95 latency returns to baseline within 5 minutes of scale-up.
- No new alarms.
- After scale-down: CPU/memory still under target threshold (70% CPU, 75% mem).

## Rollback
- ECS: `update-service --desired-count <previous>` then resume autoscaling.
- RDS: re-run `modify-db-instance` with the previous class.
- Redis/MSK: revert Terraform change and re-plan.
