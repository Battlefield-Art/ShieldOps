# ShieldOps — Production Deployment Guide

Complete deployment guide for AWS, GCP, Azure, and On-Premises.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Prerequisites](#prerequisites)
3. [AWS Deployment](#aws-deployment)
4. [GCP Deployment](#gcp-deployment)
5. [Azure Deployment](#azure-deployment)
6. [On-Premises Deployment](#on-premises-deployment)
7. [Post-Deployment](#post-deployment)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    Load Balancer / Ingress               │
│              (ALB / Cloud LB / Nginx / Traefik)         │
├─────────────┬──────────────┬────────────────────────────┤
│  Dashboard  │   API Server │    Agent Workers            │
│  (React)    │   (FastAPI)  │    (151 LangGraph agents)  │
│  Static CDN │   3+ replicas│    Auto-scaled pods        │
├─────────────┴──────────────┴────────────────────────────┤
│                    Service Mesh                          │
├──────────┬──────────┬──────────┬────────────┬───────────┤
│ Postgres │  Redis   │  Kafka   │    OPA     │  Vault    │
│ (Primary │ (Cache + │ (Event   │  (Policy   │ (Secrets) │
│  + Read  │  Pub/Sub)│  Stream) │   Engine)  │           │
│  Replica)│          │          │            │           │
└──────────┴──────────┴──────────┴────────────┴───────────┘
```

### Components

| Component | Purpose | Min Specs |
|-----------|---------|-----------|
| **API Server** | FastAPI, 749 endpoints, JWT auth | 2 vCPU, 4GB RAM, 3 replicas |
| **Agent Workers** | 151 LangGraph agents, LLM calls | 4 vCPU, 8GB RAM, auto-scaled |
| **Dashboard** | React SPA, 158 pages | Static files on CDN |
| **PostgreSQL** | Primary database | 4 vCPU, 16GB RAM, 100GB SSD |
| **Redis** | Cache, pub/sub, rate limiting | 2 vCPU, 4GB RAM |
| **Kafka** | Event streaming, telemetry | 3-node cluster, 100GB each |
| **OPA** | Policy evaluation sidecar | 0.5 vCPU, 512MB RAM per pod |
| **Vault** | Secret management | 2 vCPU, 4GB RAM, HA |

### Environment Variables

```bash
# Required
ANTHROPIC_API_KEY=sk-ant-...        # Claude API (primary LLM)
DATABASE_URL=postgresql+asyncpg://user:pass@host:5432/shieldops
REDIS_URL=redis://host:6379/0
KAFKA_BROKERS=broker1:9092,broker2:9092,broker3:9092
OPA_ENDPOINT=http://opa:8181
JWT_SECRET_KEY=<random-256-bit>

# Optional
OPENAI_API_KEY=sk-...               # Fallback LLM
LANGSMITH_API_KEY=ls-...            # Agent tracing
STRIPE_SECRET_KEY=sk_live_...       # Billing
STRIPE_WEBHOOK_SECRET=whsec_...
SLACK_BOT_TOKEN=xoxb-...            # ChatOps
PAGERDUTY_API_KEY=...               # Incident routing
VAULT_ADDR=https://vault:8200
```

---

## AWS Deployment

### Step 1: Infrastructure with Terraform

```bash
cd infrastructure/terraform/aws

# Configure variables
cat > terraform.tfvars << 'EOF'
region              = "us-east-1"
environment         = "production"
vpc_cidr            = "10.0.0.0/16"
db_instance_class   = "db.r6g.xlarge"
db_allocated_storage = 100
redis_node_type     = "cache.r6g.large"
ecs_api_cpu         = 2048
ecs_api_memory      = 4096
ecs_api_count       = 3
ecs_worker_cpu      = 4096
ecs_worker_memory   = 8192
ecs_worker_count    = 2
kafka_broker_count  = 3
kafka_instance_type = "kafka.m5.large"
domain_name         = "shieldops.io"
EOF

terraform init
terraform plan -out=tfplan
terraform apply tfplan
```

**Created resources:**
- VPC with public/private subnets across 3 AZs
- ECS Fargate cluster (API + Worker services)
- RDS PostgreSQL (Multi-AZ, encrypted)
- ElastiCache Redis (cluster mode)
- MSK Kafka (3-broker)
- ALB with TLS termination
- ECR repositories
- IAM roles + security groups
- CloudWatch log groups
- S3 bucket for backups

### Step 2: Build and Push Docker Images

```bash
# Authenticate to ECR
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin \
  <account-id>.dkr.ecr.us-east-1.amazonaws.com

# Build and push API server
docker build -t shieldops-api -f infrastructure/docker/Dockerfile .
docker tag shieldops-api:latest \
  <account-id>.dkr.ecr.us-east-1.amazonaws.com/shieldops-api:latest
docker push <account-id>.dkr.ecr.us-east-1.amazonaws.com/shieldops-api:latest

# Build and push dashboard
cd dashboard-ui
npm ci && npm run build
docker build -t shieldops-dashboard -f Dockerfile.nginx .
docker tag shieldops-dashboard:latest \
  <account-id>.dkr.ecr.us-east-1.amazonaws.com/shieldops-dashboard:latest
docker push <account-id>.dkr.ecr.us-east-1.amazonaws.com/shieldops-dashboard:latest
```

### Step 3: Database Migration

```bash
# Run Alembic migrations against RDS
DATABASE_URL=postgresql+asyncpg://shieldops:$DB_PASSWORD@$RDS_ENDPOINT:5432/shieldops \
  alembic upgrade head
```

### Step 4: Deploy to ECS

```bash
# Update ECS service with new images
aws ecs update-service \
  --cluster shieldops-prod \
  --service shieldops-api \
  --force-new-deployment

aws ecs update-service \
  --cluster shieldops-prod \
  --service shieldops-worker \
  --force-new-deployment

# Verify deployment
aws ecs describe-services \
  --cluster shieldops-prod \
  --services shieldops-api shieldops-worker \
  --query 'services[].{name:serviceName,running:runningCount,desired:desiredCount}'
```

### Step 5: DNS + TLS

```bash
# Request ACM certificate
aws acm request-certificate \
  --domain-name shieldops.io \
  --subject-alternative-names "*.shieldops.io" \
  --validation-method DNS

# Add DNS records in Route 53
aws route53 change-resource-record-sets \
  --hosted-zone-id $ZONE_ID \
  --change-batch '{
    "Changes": [{
      "Action": "CREATE",
      "ResourceRecordSet": {
        "Name": "shieldops.io",
        "Type": "A",
        "AliasTarget": {
          "HostedZoneId": "$ALB_ZONE_ID",
          "DNSName": "$ALB_DNS",
          "EvaluateTargetHealth": true
        }
      }
    }]
  }'
```

### Step 6: CloudFront CDN for Dashboard

```bash
aws cloudfront create-distribution \
  --origin-domain-name $S3_BUCKET.s3.amazonaws.com \
  --default-root-object index.html \
  --viewer-certificate AcmCertificateArn=$ACM_ARN

# Upload dashboard build to S3
aws s3 sync dashboard-ui/dist/ s3://$S3_BUCKET/ --delete
```

### AWS Architecture Diagram

```
Internet → Route 53 → CloudFront (Dashboard)
                    → ALB (API) → ECS Fargate
                                  ├── API (x3)
                                  ├── Workers (x2, auto-scaled)
                                  └── OPA Sidecar
                    → RDS PostgreSQL (Multi-AZ)
                    → ElastiCache Redis
                    → MSK Kafka (3 brokers)
                    → Secrets Manager
                    → CloudWatch (logs + metrics)
                    → S3 (backups + static assets)
```

---

## GCP Deployment

### Step 1: Infrastructure with Terraform

```bash
cd infrastructure/terraform/gcp

cat > terraform.tfvars << 'EOF'
project_id          = "shieldops-prod"
region              = "us-central1"
zone                = "us-central1-a"
gke_node_count      = 3
gke_machine_type    = "e2-standard-4"
cloudsql_tier       = "db-custom-4-16384"
memorystore_size_gb = 4
domain_name         = "shieldops.io"
EOF

terraform init
terraform plan -out=tfplan
terraform apply tfplan
```

**Created resources:**
- VPC with subnets
- GKE Autopilot cluster
- Cloud SQL PostgreSQL (HA)
- Memorystore Redis
- Confluent Kafka (or Pub/Sub)
- Cloud Load Balancer
- Artifact Registry
- Cloud KMS (encryption)
- Cloud Monitoring

### Step 2: Build and Push to Artifact Registry

```bash
# Configure Docker for Artifact Registry
gcloud auth configure-docker us-central1-docker.pkg.dev

# Build and push
docker build -t us-central1-docker.pkg.dev/shieldops-prod/shieldops/api:latest .
docker push us-central1-docker.pkg.dev/shieldops-prod/shieldops/api:latest
```

### Step 3: Deploy to GKE

```bash
# Get cluster credentials
gcloud container clusters get-credentials shieldops-prod \
  --region us-central1

# Apply Kubernetes manifests
kubectl apply -f infrastructure/kubernetes/

# Verify
kubectl get pods -n shieldops
kubectl get svc -n shieldops
```

### Step 4: Cloud SQL + Migrations

```bash
# Connect via Cloud SQL Proxy
cloud-sql-proxy shieldops-prod:us-central1:shieldops-db &

DATABASE_URL=postgresql+asyncpg://shieldops:$DB_PASS@localhost:5432/shieldops \
  alembic upgrade head
```

### Step 5: DNS + TLS (Google-managed)

```bash
# Create managed certificate
kubectl apply -f - << 'EOF'
apiVersion: networking.gke.io/v1
kind: ManagedCertificate
metadata:
  name: shieldops-cert
spec:
  domains:
    - shieldops.io
    - "*.shieldops.io"
EOF

# Configure Cloud DNS
gcloud dns record-sets create shieldops.io \
  --zone=shieldops-zone \
  --type=A \
  --rrdatas=$LOAD_BALANCER_IP
```

### GCP Architecture Diagram

```
Internet → Cloud LB → GKE Autopilot
                       ├── API Deployment (3 replicas)
                       ├── Worker Deployment (auto-scaled)
                       └── OPA Sidecar
           Cloud SQL PostgreSQL (HA)
           Memorystore Redis
           Pub/Sub or Confluent Kafka
           Secret Manager
           Cloud Monitoring + Logging
           Cloud CDN (Dashboard)
```

---

## Azure Deployment

### Step 1: Infrastructure with Terraform

```bash
cd infrastructure/terraform/azure

cat > terraform.tfvars << 'EOF'
resource_group      = "shieldops-prod"
location            = "eastus"
aks_node_count      = 3
aks_vm_size         = "Standard_D4s_v3"
postgres_sku        = "GP_Standard_D4s_v3"
redis_sku           = "Premium"
redis_capacity      = 1
domain_name         = "shieldops.io"
EOF

terraform init
terraform plan -out=tfplan
terraform apply tfplan
```

**Created resources:**
- Resource Group
- AKS cluster
- Azure Database for PostgreSQL Flexible Server
- Azure Cache for Redis
- Azure Event Hubs (Kafka-compatible)
- Application Gateway (with WAF)
- Azure Container Registry
- Key Vault
- Azure Monitor

### Step 2: Build and Push to ACR

```bash
# Login to Azure Container Registry
az acr login --name shieldopsacr

# Build and push
az acr build --registry shieldopsacr \
  --image shieldops-api:latest \
  --file infrastructure/docker/Dockerfile .
```

### Step 3: Deploy to AKS

```bash
# Get AKS credentials
az aks get-credentials \
  --resource-group shieldops-prod \
  --name shieldops-aks

# Apply manifests
kubectl apply -f infrastructure/kubernetes/

# Verify
kubectl get pods -n shieldops
```

### Step 4: Database Migration

```bash
DATABASE_URL=postgresql+asyncpg://shieldops:$DB_PASS@$PG_HOST:5432/shieldops \
  alembic upgrade head
```

### Step 5: DNS + TLS

```bash
# Create DNS zone
az network dns zone create \
  --resource-group shieldops-prod \
  --name shieldops.io

# Add A record pointing to Application Gateway
az network dns record-set a add-record \
  --resource-group shieldops-prod \
  --zone-name shieldops.io \
  --record-set-name @ \
  --ipv4-address $APP_GW_IP
```

### Azure Architecture Diagram

```
Internet → Application Gateway (WAF) → AKS
                                        ├── API (3 replicas)
                                        ├── Workers (auto-scaled)
                                        └── OPA Sidecar
           Azure PostgreSQL Flexible Server
           Azure Cache for Redis
           Azure Event Hubs (Kafka API)
           Key Vault (secrets)
           Azure Monitor + Log Analytics
           Azure CDN (Dashboard)
```

---

## On-Premises Deployment

### Prerequisites

| Component | Minimum Specs |
|-----------|--------------|
| **3 Linux servers** | 8 vCPU, 32GB RAM, 500GB SSD each |
| **1 Load Balancer** | HAProxy, Nginx, or F5 |
| **Docker + Kubernetes** | K3s, RKE2, or kubeadm cluster |
| **PostgreSQL 15+** | Self-hosted or managed |
| **Redis 7+** | Self-hosted |
| **Kafka 3.5+** | Self-hosted (Confluent or Apache) |
| **TLS certificates** | From internal CA or Let's Encrypt |
| **DNS** | Internal DNS or split-horizon |

### Step 1: Install Kubernetes (K3s)

```bash
# On master node
curl -sfL https://get.k3s.io | sh -s - \
  --write-kubeconfig-mode 644 \
  --disable traefik \
  --tls-san $MASTER_IP

# On worker nodes
curl -sfL https://get.k3s.io | K3S_URL=https://$MASTER_IP:6443 \
  K3S_TOKEN=$NODE_TOKEN sh -

# Verify cluster
kubectl get nodes
```

### Step 2: Deploy Dependencies

```bash
# PostgreSQL (via Helm)
helm repo add bitnami https://charts.bitnami.com/bitnami
helm install postgresql bitnami/postgresql \
  --set auth.postgresPassword=$PG_PASS \
  --set auth.database=shieldops \
  --set primary.persistence.size=100Gi \
  --set architecture=replication \
  --namespace shieldops --create-namespace

# Redis
helm install redis bitnami/redis \
  --set auth.password=$REDIS_PASS \
  --set architecture=standalone \
  --namespace shieldops

# Kafka
helm install kafka bitnami/kafka \
  --set replicaCount=3 \
  --set persistence.size=100Gi \
  --namespace shieldops

# OPA
helm install opa opa/opa-kube \
  --namespace shieldops
```

### Step 3: Build Docker Images Locally

```bash
# Build API image
docker build -t shieldops-api:latest \
  -f infrastructure/docker/Dockerfile .

# Build dashboard image
cd dashboard-ui && npm ci && npm run build
cat > Dockerfile.nginx << 'NGINXEOF'
FROM nginx:alpine
COPY dist/ /usr/share/nginx/html/
COPY nginx.conf /etc/nginx/conf.d/default.conf
NGINXEOF
docker build -t shieldops-dashboard:latest -f Dockerfile.nginx .

# Load images into K3s (if no registry)
k3s ctr images import <(docker save shieldops-api:latest)
k3s ctr images import <(docker save shieldops-dashboard:latest)

# OR push to private registry
docker tag shieldops-api:latest registry.internal:5000/shieldops-api:latest
docker push registry.internal:5000/shieldops-api:latest
```

### Step 4: Deploy ShieldOps via Helm

```bash
cd infrastructure/helm

# Create values override
cat > values-onprem.yaml << 'EOF'
replicaCount:
  api: 3
  worker: 2

image:
  repository: registry.internal:5000/shieldops-api
  tag: latest

database:
  host: postgresql.shieldops.svc.cluster.local
  port: 5432
  name: shieldops

redis:
  host: redis-master.shieldops.svc.cluster.local
  port: 6379

kafka:
  brokers: kafka-0.kafka.shieldops.svc.cluster.local:9092

opa:
  endpoint: http://opa.shieldops.svc.cluster.local:8181

ingress:
  enabled: true
  host: shieldops.internal.company.com
  tls:
    secretName: shieldops-tls

resources:
  api:
    requests: { cpu: "2", memory: "4Gi" }
    limits: { cpu: "4", memory: "8Gi" }
  worker:
    requests: { cpu: "4", memory: "8Gi" }
    limits: { cpu: "8", memory: "16Gi" }
EOF

helm install shieldops . -f values-onprem.yaml -n shieldops
```

### Step 5: TLS with Internal CA

```bash
# Generate TLS certificate
openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
  -keyout tls.key -out tls.crt \
  -subj "/CN=shieldops.internal.company.com"

# Create K8s TLS secret
kubectl create secret tls shieldops-tls \
  --cert=tls.crt --key=tls.key \
  -n shieldops
```

### Step 6: Load Balancer (HAProxy)

```bash
# /etc/haproxy/haproxy.cfg
cat > /etc/haproxy/haproxy.cfg << 'EOF'
frontend shieldops
    bind *:443 ssl crt /etc/ssl/shieldops.pem
    default_backend k8s_ingress

backend k8s_ingress
    balance roundrobin
    server node1 $NODE1_IP:80 check
    server node2 $NODE2_IP:80 check
    server node3 $NODE3_IP:80 check
EOF

systemctl restart haproxy
```

### On-Prem Architecture Diagram

```
Users → HAProxy/F5 (TLS) → K3s/RKE2 Cluster
                             ├── API (3 pods)
                             ├── Workers (2+ pods, HPA)
                             ├── Dashboard (2 pods)
                             └── OPA Sidecar
        PostgreSQL (self-hosted, replicated)
        Redis (self-hosted)
        Kafka (3-node cluster)
        Internal DNS
        Prometheus + Grafana (monitoring)
```

---

## Post-Deployment

### Step 1: Verify Health

```bash
# API health check
curl https://shieldops.io/health
# Expected: {"status": "healthy", "version": "1.0.0"}

# Readiness check (DB + Redis + OPA)
curl https://shieldops.io/ready
# Expected: {"status": "ready", "checks": {"database": "ok", "redis": "ok", "opa": "ok"}}

# Agent registry
curl -H "Authorization: Bearer $TOKEN" \
  https://shieldops.io/api/v1/agents
# Expected: 151 agents registered
```

### Step 2: Run Database Migrations

```bash
alembic upgrade head
```

### Step 3: Configure Connectors

```bash
# Set connector credentials via API
curl -X POST https://shieldops.io/api/v1/connectors/crowdstrike/configure \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"client_id": "...", "client_secret": "..."}'

curl -X POST https://shieldops.io/api/v1/connectors/splunk/configure \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"host": "splunk.company.com", "token": "..."}'
```

### Step 4: OPA Policy Deployment

```bash
# Upload Rego policies to OPA
for policy in hipaa pci_dss soc2 gdpr fedramp; do
  curl -X PUT http://opa:8181/v1/policies/$policy \
    -H "Content-Type: text/plain" \
    --data-binary @src/shieldops/policy/opa/${policy}.rego
done
```

### Step 5: Monitoring Setup

```bash
# Import Grafana dashboards
curl -X POST http://grafana:3000/api/dashboards/db \
  -H "Content-Type: application/json" \
  -d @infrastructure/monitoring/grafana/agent-dashboard.json

# Configure Prometheus alerts
kubectl apply -f infrastructure/monitoring/prometheus/
```

### Step 6: Smoke Tests

```bash
# Run production smoke tests
python3 -m pytest tests/integration/ \
  --base-url=https://shieldops.io \
  -k "smoke" -v

# Verify agent execution
curl -X POST https://shieldops.io/api/v1/agentic-mdr/run \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"tenant_id": "prod-tenant"}'
```

### Step 7: Enable Monitoring Alerts

```bash
# PagerDuty integration
curl -X POST https://shieldops.io/api/v1/settings/notifications \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "pagerduty_key": "...",
    "slack_webhook": "...",
    "email_smtp": "smtp.company.com:587"
  }'
```

---

## Security Hardening Checklist

- [ ] TLS 1.3 enforced on all endpoints
- [ ] JWT tokens with RS256 signing (not HS256)
- [ ] API rate limiting enabled (100 req/min default)
- [ ] Network policies restricting pod-to-pod traffic
- [ ] Database connections encrypted (SSL mode=require)
- [ ] Secrets in Vault/Secrets Manager (not env vars in manifests)
- [ ] OPA policies loaded and enforcing
- [ ] Audit logging enabled (immutable)
- [ ] CORS restricted to dashboard domain only
- [ ] Container images scanned for CVEs
- [ ] Non-root container execution
- [ ] Pod Security Standards enforced (restricted)
- [ ] Backup encryption enabled (AES-256-GCM)
- [ ] External penetration test scheduled

---

## Scaling Guide

| Load Level | API Replicas | Worker Pods | Database | Redis |
|------------|-------------|-------------|----------|-------|
| Startup (<100 users) | 2 | 1 | db.r6g.large | cache.r6g.large |
| Growth (100-1K) | 3 | 2-4 | db.r6g.xlarge | cache.r6g.xlarge |
| Scale (1K-10K) | 5 | 4-8 | db.r6g.2xlarge | cache.r6g.2xlarge |
| Enterprise (10K+) | 10+ | 8-20 | db.r6g.4xlarge | cluster mode |

### Auto-scaling Configuration

```yaml
# Kubernetes HPA
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: shieldops-worker
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: shieldops-worker
  minReplicas: 2
  maxReplicas: 20
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
```

---

## Cost Estimates

| Cloud | Startup | Growth | Enterprise |
|-------|---------|--------|------------|
| **AWS** | ~$800/mo | ~$2,500/mo | ~$8,000/mo |
| **GCP** | ~$750/mo | ~$2,300/mo | ~$7,500/mo |
| **Azure** | ~$850/mo | ~$2,600/mo | ~$8,500/mo |
| **On-Prem** | $15K hardware + $500/mo power | Same | Same |

*Excludes Anthropic API costs (~$0.015/1K tokens for Opus)*

---

## Rollback Procedure

```bash
# Kubernetes rollback
kubectl rollout undo deployment/shieldops-api -n shieldops
kubectl rollout undo deployment/shieldops-worker -n shieldops

# Database rollback
alembic downgrade -1

# Verify rollback
kubectl rollout status deployment/shieldops-api -n shieldops
curl https://shieldops.io/health
```
