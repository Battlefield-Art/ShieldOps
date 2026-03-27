# ShieldOps AWS CDK Deployment

Production-grade AWS infrastructure for the ShieldOps AI Security Control Plane.

## What Gets Deployed

| Resource | Spec | Purpose |
|----------|------|---------|
| VPC | 3 AZs, public/private/isolated subnets, 3 NAT gateways | Network isolation |
| ECS Fargate (API) | 3 tasks, 2 vCPU / 4 GB each, OPA sidecar | FastAPI server |
| ECS Fargate (Worker) | 2-20 tasks (auto-scaling), 4 vCPU / 8 GB, OPA sidecar | LangGraph agent execution |
| RDS PostgreSQL 16 | r6g.xlarge, Multi-AZ, 100-500 GB, encrypted | Primary database |
| ElastiCache Redis 7.1 | r6g.large, 3-shard cluster mode, Multi-AZ | Caching, queues, sessions |
| MSK Kafka 3.6 | 3 brokers, m5.large, 100 GB each, TLS | Event streaming |
| ALB | HTTPS (ACM cert), health checks, path routing | Load balancing |
| S3 | Dashboard assets + backup (Glacier lifecycle) | Static hosting, backups |
| CloudFront | CDN for dashboard, API pass-through | Global delivery |
| ACM | TLS for ALB + CloudFront | Certificates |
| WAF | Rate limiting (2k/5min), AWS managed rules, IP block list | Security |
| ECR | 3 repos (api, worker, opa) with scan-on-push | Container registry |
| Secrets Manager | DB credentials (auto-generated), app secrets | Secret storage |
| CloudWatch | Dashboard, 6 alarms (CPU, storage, connections, 5xx, latency), SNS topic | Monitoring |
| Route 53 | api. and app. DNS records (optional) | DNS |

## Prerequisites

```bash
# 1. Node.js 18+ (CDK CLI is a Node package)
node --version

# 2. AWS CDK CLI
npm install -g aws-cdk

# 3. AWS CLI configured with credentials
aws sts get-caller-identity

# 4. Python 3.12+
python3 --version

# 5. CDK bootstrap (one-time per account/region)
cdk bootstrap aws://ACCOUNT_ID/us-east-1
```

## Deployment

```bash
cd infrastructure/aws-cdk

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install CDK dependencies
pip install aws-cdk-lib constructs aws-cdk.aws-msk-alpha

# Preview what will be created
cdk diff -c account=123456789012 -c region=us-east-1 -c domain=shieldops.io

# Deploy
cdk deploy -c account=123456789012 -c region=us-east-1 -c domain=shieldops.io

# Deploy without approval prompts (CI/CD)
cdk deploy --require-approval never -c account=123456789012 -c region=us-east-1
```

## Post-Deployment Steps

1. **Update Secrets Manager** with real API keys:
   ```bash
   aws secretsmanager update-secret \
     --secret-id shieldops/app-secrets \
     --secret-string '{
       "ANTHROPIC_API_KEY":"sk-ant-...",
       "LANGSMITH_API_KEY":"ls-...",
       "STRIPE_SECRET_KEY":"sk_live_...",
       "SLACK_BOT_TOKEN":"xoxb-...",
       "PAGERDUTY_API_KEY":"..."
     }'
   ```

2. **Build and push container images**:
   ```bash
   # Authenticate to ECR
   aws ecr get-login-password --region us-east-1 | \
     docker login --username AWS --password-stdin ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com

   # Build and push API image
   docker build -t shieldops/api -f infrastructure/docker/Dockerfile .
   docker tag shieldops/api:latest ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/shieldops/api:latest
   docker push ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/shieldops/api:latest

   # Build and push worker image
   docker build -t shieldops/worker -f infrastructure/docker/Dockerfile.worker .
   docker tag shieldops/worker:latest ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/shieldops/worker:latest
   docker push ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/shieldops/worker:latest

   # OPA image (use upstream)
   docker pull openpolicyagent/opa:latest-static
   docker tag openpolicyagent/opa:latest-static ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/shieldops/opa:latest
   docker push ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/shieldops/opa:latest
   ```

3. **Deploy dashboard to S3 + CloudFront**:
   ```bash
   cd dashboard-ui
   npm run build
   aws s3 sync build/ s3://shieldops-dashboard-ACCOUNT_ID/ --delete
   aws cloudfront create-invalidation --distribution-id DIST_ID --paths "/*"
   ```

4. **Create Route 53 hosted zone** (if not already present):
   ```bash
   aws route53 create-hosted-zone --name shieldops.io --caller-reference $(date +%s)
   # Then re-deploy the CDK stack to create DNS records
   cdk deploy
   ```

5. **Subscribe to alarm notifications**:
   ```bash
   aws sns subscribe \
     --topic-arn arn:aws:sns:us-east-1:ACCOUNT_ID:shieldops-alarms \
     --protocol email \
     --notification-endpoint ops@shieldops.io
   ```

6. **Run database migrations**:
   ```bash
   # Via ECS Exec
   aws ecs execute-command --cluster shieldops \
     --task TASK_ID --container api --interactive \
     --command "alembic upgrade head"
   ```

## Cost Estimates (Monthly, us-east-1)

| Resource | Spec | Estimated Cost |
|----------|------|---------------|
| NAT Gateways | 3x (one per AZ) | $100 |
| ECS Fargate (API) | 3x 2vCPU/4GB | $220 |
| ECS Fargate (Worker) | 2-20x 4vCPU/8GB (avg 4 tasks) | $590 |
| RDS PostgreSQL | r6g.xlarge Multi-AZ, 100GB | $520 |
| ElastiCache Redis | 3 shards x r6g.large + replicas | $470 |
| MSK Kafka | 3x m5.large, 300GB total | $530 |
| ALB | Standard hours + LCU | $30 |
| CloudFront | 100 GB transfer | $15 |
| S3 | Dashboard + backups | $5 |
| WAF | Web ACL + rules | $25 |
| CloudWatch | Logs, metrics, dashboard | $30 |
| Secrets Manager | 2 secrets | $2 |
| ECR | 3 repos, ~5GB | $3 |
| **Total (baseline)** | | **~$2,540/mo** |

Costs scale with worker auto-scaling. At 20 workers: ~$5,500/mo.

## Cleanup

```bash
# Destroy the stack (will prompt for confirmation)
cdk destroy -c account=123456789012 -c region=us-east-1

# Note: Resources with RemovalPolicy.RETAIN (RDS, ECR, S3, MSK) will NOT
# be deleted automatically. Remove them manually if desired:
#   - RDS: delete final snapshot or skip
#   - ECR: delete repos and images
#   - S3: empty buckets first, then delete
#   - MSK: delete cluster
```

## Architecture Diagram

```
                    Internet
                       |
                   CloudFront ---- S3 (Dashboard)
                       |
                      WAF
                       |
                      ALB (HTTPS, ACM cert)
                    /     \
                   /       \
        ECS API (x3)    ECS Worker (x2-20)
        + OPA sidecar   + OPA sidecar
                |             |
        --------+-------------+---------
        |              |              |
    RDS PostgreSQL   Redis Cluster   MSK Kafka
    (Multi-AZ)       (3 shards)      (3 brokers)
```
