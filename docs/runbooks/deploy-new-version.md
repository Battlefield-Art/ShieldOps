# Deploy New Version

Deploy a new version of the ShieldOps API / worker / dashboard services to production ECS.

## When to use
- Feature release, bugfix, or security patch reaching the production stage gate.
- Hotfix (fast-path: skip canary, see "Hotfix" section below).

## Prerequisites
- Merged PR to `main`, CI green, tag created (`vX.Y.Z`).
- Access to AWS SSO `shieldops-production` with `deploy` role.
- `aws` CLI v2, `docker`, `jq`, and repo checked out.
- PagerDuty on-call acknowledged deploy window.
- Feature flags configured ahead of rollout (if applicable).

## Steps

1. **Pull latest and verify tag**
   ```bash
   git checkout main && git pull
   git tag --list "v*" | tail -3
   git describe --tags --exact-match
   ```

2. **Build and push images**
   ```bash
   AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
   REGION=us-east-1
   VERSION=$(git describe --tags --exact-match)

   aws ecr get-login-password --region $REGION \
     | docker login --username AWS --password-stdin $AWS_ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com

   for svc in api worker dashboard; do
     docker build -f infrastructure/docker/Dockerfile.$svc \
       -t $AWS_ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/shieldops-$svc:$VERSION .
     docker push $AWS_ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/shieldops-$svc:$VERSION
   done
   ```

3. **Update ECS task definitions**
   ```bash
   for svc in api worker dashboard; do
     aws ecs describe-task-definition \
       --task-definition shieldops-$svc \
       --query taskDefinition > /tmp/$svc-td.json

     jq --arg img "$AWS_ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/shieldops-$svc:$VERSION" \
        '.containerDefinitions[0].image = $img
         | del(.taskDefinitionArn,.revision,.status,.requiresAttributes,.compatibilities,.registeredAt,.registeredBy)' \
        /tmp/$svc-td.json > /tmp/$svc-td-new.json

     aws ecs register-task-definition --cli-input-json file:///tmp/$svc-td-new.json
   done
   ```

4. **Deploy (force new deployment, rolling)**
   ```bash
   CLUSTER=shieldops-production
   for svc in api worker dashboard; do
     aws ecs update-service \
       --cluster $CLUSTER \
       --service shieldops-$svc \
       --task-definition shieldops-$svc \
       --force-new-deployment
   done
   ```

5. **Watch rollout**
   ```bash
   aws ecs wait services-stable --cluster $CLUSTER --services shieldops-api shieldops-worker shieldops-dashboard
   ```

6. **Smoke test**
   ```bash
   curl -fsSL https://api.shieldops.io/healthz
   curl -fsSL https://api.shieldops.io/api/v1/system/version | jq .
   ```

## Verification
- ECS services show `runningCount == desiredCount` and new task definition revision.
- CloudWatch dashboard `shieldops-production-operations`: 5xx rate ≤ baseline, p95 latency ≤ baseline +10%.
- LangSmith: new agent runs succeed with LLM responses.
- No new alarms in the last 15 minutes.

## Hotfix (fast path)
- Skip canary, deploy directly.
- Post in `#incidents` Slack channel with tag, change summary, and rollback plan link.
- Watch dashboard for 30 minutes post-deploy.

## Rollback
See [rollback-deployment.md](./rollback-deployment.md).
