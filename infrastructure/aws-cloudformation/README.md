# ShieldOps AWS CloudFormation Deployment

Single-template deployment of the full ShieldOps stack on AWS using ECS Fargate, RDS PostgreSQL, ElastiCache Redis, ALB, S3+CloudFront, and supporting services.

## Architecture

```
                         Internet
                            |
                     [ CloudFront ]
                      /          \
               S3 (Dashboard)   ALB (HTTPS)
                              /     \
                         [ ECS Fargate ]
                         /   |    \    \
                      API  API  Worker Worker
                         \   |   /
                     +----+--+--+----+
                     |    |       |   |
                    RDS  Redis   S3  Secrets
                 (Multi-AZ)         Manager
```

## Resources Created

| Resource | Service | Details |
|----------|---------|---------|
| VPC | Networking | 3 AZs, public + private subnets, NAT Gateway |
| ALB | Load Balancing | Internet-facing, HTTP->HTTPS redirect, path-based routing |
| ECS Cluster | Compute | Fargate launch type, Container Insights |
| API Service | ECS Fargate | Auto-scaled 2-10 tasks, health checks |
| Worker Service | ECS Fargate | Auto-scaled 2-10 tasks |
| RDS PostgreSQL | Database | Multi-AZ, encrypted, auto-backup, Performance Insights |
| ElastiCache Redis | Cache | Replication group, encryption at rest + in transit |
| ECR | Container Registry | API + Dashboard repos, scan-on-push, lifecycle policy |
| S3 | Storage | Artifacts bucket (versioned) + Dashboard bucket |
| CloudFront | CDN | Dashboard static assets + API proxy |
| Secrets Manager | Secrets | Database credentials + API secrets (auto-generated) |
| CloudWatch | Monitoring | Log groups + CPU/storage alarms |
| IAM | Security | Task execution role, task role (least privilege) |
| Security Groups | Network | ALB, ECS, RDS, Redis (deny-by-default) |

## Prerequisites

- AWS CLI v2 configured with appropriate credentials
- An ACM certificate ARN (for HTTPS) in the same region
- Docker images pushed to ECR (or use the CI/CD pipeline)

## Quick Start

```bash
# 1. Validate the template
aws cloudformation validate-template \
  --template-body file://template.yaml

# 2. Deploy (development)
aws cloudformation deploy \
  --template-file template.yaml \
  --stack-name shieldops-dev \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    Environment=development \
    RdsInstanceClass=db.t4g.medium \
    RedisNodeType=cache.t4g.small \
    RdsMultiAz=false \
    ApiDesiredCount=1 \
    WorkerDesiredCount=1

# 3. Deploy (production with HTTPS)
aws cloudformation deploy \
  --template-file template.yaml \
  --stack-name shieldops-prod \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    Environment=production \
    DomainName=shieldops.example.com \
    CertificateArn=arn:aws:acm:us-east-1:123456789012:certificate/abc-123 \
    RdsInstanceClass=db.r6g.xlarge \
    RedisNodeType=cache.r6g.large \
    ApiDesiredCount=3 \
    WorkerDesiredCount=3 \
    ApiMaxCount=20 \
    WorkerMaxCount=20

# 4. View outputs
aws cloudformation describe-stacks \
  --stack-name shieldops-prod \
  --query 'Stacks[0].Outputs' \
  --output table
```

## Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `Environment` | production | development / staging / production |
| `DomainName` | shieldops.example.com | Primary domain name |
| `CertificateArn` | (empty) | ACM certificate for HTTPS |
| `ApiCpu` | 1024 | API task CPU units (256-4096) |
| `ApiMemory` | 2048 | API task memory MiB (512-8192) |
| `WorkerCpu` | 2048 | Worker task CPU units |
| `WorkerMemory` | 4096 | Worker task memory MiB |
| `ApiDesiredCount` | 2 | Initial API replica count |
| `WorkerDesiredCount` | 2 | Initial worker replica count |
| `ApiMaxCount` | 10 | Maximum API replicas (auto scaling) |
| `WorkerMaxCount` | 10 | Maximum worker replicas (auto scaling) |
| `RdsInstanceClass` | db.r6g.large | RDS instance type |
| `RdsAllocatedStorage` | 100 | RDS storage in GiB |
| `RdsMultiAz` | true | Enable Multi-AZ for RDS |
| `RedisNodeType` | cache.r6g.large | ElastiCache node type |
| `RedisNumReplicas` | 1 | Redis read replica count |
| `VpcCidr` | 10.0.0.0/16 | VPC CIDR block |
| `ApiImageTag` | latest | API container image tag |
| `DashboardImageTag` | latest | Dashboard container image tag |

## Outputs

| Output | Description |
|--------|-------------|
| `APIURL` | ShieldOps API endpoint URL |
| `DashboardURL` | Dashboard URL (via CloudFront) |
| `ALBURL` | ALB DNS name |
| `RDSEndpoint` | PostgreSQL connection endpoint |
| `RedisEndpoint` | Redis primary endpoint |
| `ApiECRRepositoryUri` | ECR URI for pushing API images |
| `DashboardECRRepositoryUri` | ECR URI for pushing dashboard images |
| `CloudFrontDomainName` | CloudFront distribution domain |
| `VpcId` | VPC identifier |
| `DatabaseSecretArn` | Secrets Manager ARN for DB credentials |

## Post-Deployment Steps

1. **Push container images** to ECR:
   ```bash
   # Get ECR login
   aws ecr get-login-password --region us-east-1 | \
     docker login --username AWS --password-stdin <account>.dkr.ecr.us-east-1.amazonaws.com

   # Build and push API
   docker build -t shieldops-api -f infrastructure/docker/Dockerfile .
   docker tag shieldops-api:latest <api-ecr-uri>:latest
   docker push <api-ecr-uri>:latest

   # Force new deployment
   aws ecs update-service --cluster <cluster> --service <api-service> --force-new-deployment
   ```

2. **Configure DNS**: Point your domain's CNAME to the ALB DNS name or CloudFront domain.

3. **Add API secrets**: Update the Secrets Manager secret with your Anthropic API key, Slack token, etc.:
   ```bash
   aws secretsmanager update-secret \
     --secret-id production/shieldops/api \
     --secret-string '{"jwt_secret_key":"...","anthropic_api_key":"...","slack_bot_token":"..."}'
   ```

4. **Run database migrations**:
   ```bash
   aws ecs run-task \
     --cluster <cluster> \
     --task-definition <api-task-def> \
     --overrides '{"containerOverrides":[{"name":"api","command":["alembic","upgrade","head"]}]}' \
     --network-configuration '...'
   ```

## Cost Estimates (us-east-1)

| Environment | Monthly Estimate |
|-------------|-----------------|
| Development | ~$250-400 |
| Staging | ~$400-600 |
| Production | ~$800-1,500 |

Primary cost drivers: RDS instance, NAT Gateway, ECS Fargate tasks, ElastiCache.

## Cleanup

```bash
# Delete the stack (RDS snapshot will be retained)
aws cloudformation delete-stack --stack-name shieldops-dev

# Monitor deletion
aws cloudformation wait stack-delete-complete --stack-name shieldops-dev
```

Note: S3 buckets with `DeletionPolicy: Retain` must be emptied and deleted manually.
