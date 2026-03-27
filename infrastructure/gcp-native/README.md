# ShieldOps GCP Native Deployment

Deploy ShieldOps to Google Cloud Platform using `gcloud` CLI commands. The script is fully idempotent and safe to re-run.

## Prerequisites

1. **Google Cloud SDK** (gcloud CLI) installed and authenticated
   ```bash
   # Install: https://cloud.google.com/sdk/docs/install
   gcloud auth login
   gcloud auth application-default login
   ```

2. **GCP Project** with billing enabled
   ```bash
   gcloud projects create shieldops-prod --name="ShieldOps Production"
   gcloud beta billing projects link shieldops-prod --billing-account=BILLING_ACCOUNT_ID
   ```

3. **Required IAM roles** for the deploying user/service account:
   - `roles/owner` (or granular: Compute Admin, Container Admin, Cloud SQL Admin, Redis Admin, DNS Admin, Secret Manager Admin, Monitoring Admin, Artifact Registry Admin, Security Admin)

4. **Domain name** with access to update NS records at your registrar

## Resources Created

| Resource | Type | Spec |
|----------|------|------|
| VPC | Private network | Custom subnet, Cloud NAT |
| GKE Autopilot | Kubernetes cluster | Regional, stable channel |
| Cloud SQL | PostgreSQL 15 | HA (regional), 4 vCPU / 16 GB, 100 GB SSD |
| Memorystore | Redis 7.0 | 4 GB, Standard tier (HA) |
| Artifact Registry | Docker repo | Regional |
| Cloud Load Balancer | HTTPS | Managed SSL cert, HTTP redirect |
| Cloud DNS | Managed zone | A record for domain |
| Secret Manager | 12 secrets | Application secrets |
| Cloud Armor | WAF policy | OWASP rules + rate limiting |
| Cloud Monitoring | Dashboard + alerts | CPU, memory, errors, latency |

## Deployment

### Quick Start

```bash
chmod +x deploy.sh

# Deploy with defaults
./deploy.sh --project shieldops-prod --region us-central1 --domain shieldops.example.com

# Or use environment variables
export GCP_PROJECT_ID=shieldops-prod
export GCP_REGION=us-central1
export SHIELDOPS_DOMAIN=shieldops.example.com
./deploy.sh
```

### Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `GCP_PROJECT_ID` | `shieldops-prod` | GCP project ID |
| `GCP_REGION` | `us-central1` | Primary region |
| `SHIELDOPS_DOMAIN` | `shieldops.example.com` | Domain for HTTPS |
| `SHIELDOPS_ENV` | `production` | Environment label |
| `SHIELDOPS_ALERT_EMAIL` | `ops@shieldops.io` | Alert notification email |

### Post-Deployment Steps

1. **Update DNS NS records** at your registrar:
   ```bash
   gcloud dns managed-zones describe shieldops-zone --format="value(nameServers)"
   ```

2. **Set real secret values** (replace placeholders):
   ```bash
   echo -n "sk-ant-..." | gcloud secrets versions add shieldops-anthropic-api-key --data-file=-
   echo -n "your-jwt-secret" | gcloud secrets versions add shieldops-jwt-secret --data-file=-
   # Repeat for all secrets
   ```

3. **Push container image**:
   ```bash
   gcloud auth configure-docker us-central1-docker.pkg.dev
   docker build -t us-central1-docker.pkg.dev/shieldops-prod/shieldops-docker/shieldops:latest .
   docker push us-central1-docker.pkg.dev/shieldops-prod/shieldops-docker/shieldops:latest
   ```

4. **Deploy to GKE**:
   ```bash
   gcloud container clusters get-credentials shieldops-gke --region us-central1
   kubectl apply -f infrastructure/kubernetes/
   ```

## Cost Estimate (Monthly)

| Resource | Spec | Estimated Cost |
|----------|------|---------------|
| GKE Autopilot | ~3 e2-standard-4 equivalent | $200 - $350 |
| Cloud SQL (HA) | db-custom-4-16384, 100 GB | $250 - $350 |
| Memorystore Redis | 4 GB Standard | $175 |
| Cloud Load Balancer | HTTPS + forwarding rules | $25 - $50 |
| Cloud NAT | Gateway + data processing | $30 - $50 |
| Cloud Armor | WAF policy + rules | $5 - $20 |
| Artifact Registry | Storage + egress | $5 - $15 |
| Cloud DNS | Zone + queries | $1 - $5 |
| Secret Manager | 12 secrets | $1 |
| Cloud Monitoring | Dashboards + alerts | $0 (included) |
| **Total** | | **$690 - $1,020/mo** |

Costs vary by traffic volume and actual compute usage. GKE Autopilot scales down to zero during low usage.

## Cleanup

Remove all resources (irreversible):

```bash
PROJECT_ID=shieldops-prod
REGION=us-central1

# Delete in reverse dependency order
gcloud compute forwarding-rules delete shieldops-https-fwd --global --quiet
gcloud compute forwarding-rules delete shieldops-http-fwd --global --quiet
gcloud compute target-https-proxies delete shieldops-https-proxy --quiet
gcloud compute target-http-proxies delete shieldops-http-proxy --quiet
gcloud compute url-maps delete shieldops-url-map --quiet
gcloud compute url-maps delete shieldops-http-redirect --quiet
gcloud compute backend-services delete shieldops-backend-svc --global --quiet
gcloud compute health-checks delete shieldops-hc --quiet
gcloud compute ssl-certificates delete shieldops-cert --global --quiet
gcloud compute addresses delete shieldops-lb-ip --global --quiet
gcloud compute security-policies delete shieldops-waf --quiet

gcloud container clusters delete shieldops-gke --region=${REGION} --quiet
gcloud sql instances delete shieldops-pg --quiet
gcloud redis instances delete shieldops-redis --region=${REGION} --quiet
gcloud artifacts repositories delete shieldops-docker --location=${REGION} --quiet

gcloud dns record-sets delete "shieldops.example.com." --zone=shieldops-zone --type=A --quiet
gcloud dns managed-zones delete shieldops-zone --quiet

# Delete secrets
for s in shieldops-db-password shieldops-anthropic-api-key shieldops-openai-api-key \
         shieldops-redis-url shieldops-kafka-brokers shieldops-opa-endpoint \
         shieldops-langsmith-api-key shieldops-stripe-secret-key shieldops-stripe-webhook-secret \
         shieldops-slack-bot-token shieldops-pagerduty-api-key shieldops-jwt-secret; do
    gcloud secrets delete "$s" --quiet 2>/dev/null
done

# VPC (last — other resources depend on it)
gcloud compute routers nats delete shieldops-nat --router=shieldops-router --region=${REGION} --quiet
gcloud compute routers delete shieldops-router --region=${REGION} --quiet
gcloud compute firewall-rules delete shieldops-allow-internal --quiet
gcloud compute addresses delete shieldops-private-range --global --quiet
gcloud compute networks subnets delete shieldops-subnet --region=${REGION} --quiet
gcloud compute networks delete shieldops-vpc --quiet
```
