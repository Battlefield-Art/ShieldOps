# Investigate High Error Rate

Triage a 5xx spike in the ShieldOps API.

## When to use
- `shieldops-production-5xx-error-rate` or `shieldops-production-critical-5xx-error-rate` alarm fires.
- User reports API failing with 500 / 502 / 503 / 504.
- Status page shows degraded availability.

## Goal
Within 15 minutes: classify the error (infra vs app vs upstream), scope the blast radius, and engage the right runbook.

## Prerequisites
- AWS SSO `shieldops-production` (read-only is enough for investigation).
- CloudWatch Logs Insights access.
- LangSmith access (agent traces).
- Slack `#incidents`.

## Steps

1. **Declare and communicate**
   - Ack the PagerDuty alert.
   - Post in `#incidents`: "Investigating 5xx spike, checking dashboards now."

2. **Check the operations dashboard**
   [ShieldOps Production — Operations](https://us-east-1.console.aws.amazon.com/cloudwatch/home?region=us-east-1#dashboards:name=shieldops-production-operations)
   Correlate:
   - ALB 5xx curve vs RequestCount (is it a rate spike or share spike?).
   - ECS task count (any tasks flapping?).
   - RDS connections / CPU.
   - Redis evictions / latency.
   - Kafka under-replicated partitions.

3. **Identify error class** via ALB response codes:
   - 502 → backend connection refused (ECS task crash, networking).
   - 503 → no healthy targets (deploy failure, all tasks unhealthy).
   - 504 → upstream timeout (slow DB, slow LLM, slow MCP).
   - 500 → application exception.

4. **CloudWatch Logs Insights** on the API log group (`/ecs/shieldops-api`):
   ```
   fields @timestamp, @message
   | filter @message like /ERROR|CRITICAL|500|502|503|504/
   | sort @timestamp desc
   | limit 100
   ```

5. **Top error classes**
   ```
   fields error_type
   | filter ispresent(error_type)
   | stats count() by error_type
   | sort count desc
   ```

6. **Correlate with deploys**
   ```bash
   aws ecs describe-services --cluster shieldops-production \
     --services shieldops-api \
     --query 'services[0].deployments[].{Status:status,TD:taskDefinition,Created:createdAt}'
   ```
   If a deploy happened in the last hour: consider rollback.

7. **Correlate with upstream dependencies**
   - Anthropic API status: https://status.anthropic.com
   - LangSmith traces for failing runs.
   - RDS slow query log.
   - OPA policy engine latency.

## Decision tree

| Signal | Action |
|---|---|
| Recent deploy + errors started after | [rollback-deployment.md](./rollback-deployment.md) |
| No healthy ECS targets | Check task logs; likely app crash loop. Scale up + restart. |
| RDS connections saturated | [scale-up-down.md](./scale-up-down.md) DB pool; investigate slow queries |
| RDS CPU pinned | [rds-failover.md](./rds-failover.md) if standby is cool |
| Anthropic/LLM upstream degraded | Switch LLM router to Bedrock fallback; announce degradation |
| Redis memory full + evictions | [redis-flush.md](./redis-flush.md) or scale node type |
| Kafka under-replicated | Investigate broker health; do not delete topics |
| Isolated endpoint failing | File bug; deploy fix; no rollback needed |

## Verification (after remediation)
- 5xx rate back under 0.5% for 10 minutes.
- p95 latency back to baseline.
- Alarms transitioned to OK.
- No new errors in logs in the last 5 minutes.

## Post-incident
- Postmortem within 48 hours.
- Update this runbook if the decision tree missed a class.
- File preventive issues for every "why did this happen" answer.
