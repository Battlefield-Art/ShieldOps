# Rollback Deployment

Revert an ECS service to the previous task definition revision when a deployment introduces regressions.

## When to use
- 5xx error rate exceeds baseline +1% for > 5 minutes after deploy.
- p95 latency exceeds baseline +30%.
- New alarms firing correlated with deploy timestamp.
- Explicit rollback request from incident commander.

## Prerequisites
- AWS SSO `shieldops-production` with `deploy` role.
- Known-good task definition revision (check CloudWatch or `aws ecs describe-services`).
- Incident declared in PagerDuty if user impact is occurring.

## Steps

1. **Identify current and previous revisions**
   ```bash
   CLUSTER=shieldops-production
   SVC=shieldops-api  # repeat for worker/dashboard as needed

   CURRENT=$(aws ecs describe-services --cluster $CLUSTER --services $SVC \
     --query 'services[0].taskDefinition' --output text)

   FAMILY=$(echo $CURRENT | awk -F/ '{print $2}' | awk -F: '{print $1}')
   CURRENT_REV=$(echo $CURRENT | awk -F: '{print $NF}')
   PREV_REV=$((CURRENT_REV - 1))

   echo "Current: $CURRENT_REV, Previous: $PREV_REV"
   ```

2. **Verify the previous revision is healthy**
   ```bash
   aws ecs describe-task-definition --task-definition $FAMILY:$PREV_REV \
     --query 'taskDefinition.containerDefinitions[0].image'
   ```

3. **Roll back the service**
   ```bash
   aws ecs update-service \
     --cluster $CLUSTER \
     --service $SVC \
     --task-definition $FAMILY:$PREV_REV \
     --force-new-deployment
   ```

4. **Wait for stabilization**
   ```bash
   aws ecs wait services-stable --cluster $CLUSTER --services $SVC
   ```

5. **Smoke test**
   ```bash
   curl -fsSL https://api.shieldops.io/healthz
   curl -fsSL https://api.shieldops.io/api/v1/system/version | jq .
   ```

## Verification
- ECS service returned to previous revision; runningCount == desiredCount.
- 5xx error rate has returned to baseline within 5 minutes.
- p95 latency within normal range.
- Alarms transitioned back to OK.

## Post-rollback
- File a `fix/` branch with root cause and tests.
- Postmortem within 48 hours (see [post-incident process](../PRODUCTION_LAUNCH_RUNBOOK.md)).
- Update [deploy-new-version.md](./deploy-new-version.md) if the runbook missed a pre-check.
