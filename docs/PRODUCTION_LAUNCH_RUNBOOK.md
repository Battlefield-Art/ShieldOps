# ShieldOps — Production Launch Runbook

This runbook covers every step from zero to live production deployment.

> **See also:** [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) for multi-cloud (AWS/GCP/Azure/On-Prem) instructions.

**Platform:** 150 LangGraph agents, 1,709 engine modules, 158 dashboard pages, 749 API endpoints.

---

## Prerequisites

| Requirement | Details |
|-------------|---------|
| AWS Account | With ECS, ECR, RDS, ElastiCache, MSK permissions |
| Domain | `shieldops.io` or equivalent |
| Anthropic API Key | Claude API access for agent LLM calls |
| Stripe Account | For billing integration |
| Slack Workspace | Bot token for ChatOps approvals |
| GitHub Repository | With Actions secrets configured |

---

## Phase 1: Infrastructure Provisioning (Day 1)

### 1.1 Terraform Apply

```bash
# Initialize and apply AWS infrastructure
cd infrastructure/terraform/aws
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with real values

terraform init
terraform plan -out=tfplan
terraform apply tfplan
```

This creates: VPC, ECS cluster, RDS PostgreSQL, ElastiCache Redis, MSK Kafka, ALB, ECR repositories, IAM roles, security groups.

### 1.2 DNS Configuration

```
shieldops.io          → ALB DNS name (A record / ALIAS)
api.shieldops.io      → ALB DNS name (API subdomain)
docs.shieldops.io     → CloudFront / Vercel (MkDocs site)
status.shieldops.io   → Statuspage.io CNAME
```

### 1.3 TLS Certificates

```bash
# ACM certificate (auto-validated via DNS)
aws acm request-certificate \
  --domain-name shieldops.io \
  --subject-alternative-names "*.shieldops.io" \
  --validation-method DNS
```

---

## Phase 2: Secrets Configuration (Day 1)

### 2.1 GitHub Actions Secrets

| Secret | Source |
|--------|--------|
| `AWS_DEPLOY_ROLE_ARN` | Terraform output: `deploy_role_arn` |
| `PRODUCTION_HEALTH_URL` | `https://api.shieldops.io/health` |
| `STAGING_HEALTH_URL` | `https://staging-api.shieldops.io/health` |

### 2.2 ECS Task Definition Environment Variables

Key variables (from `.env.production.example`):

```
SHIELDOPS_ENVIRONMENT=production
SHIELDOPS_DATABASE_URL=postgresql+asyncpg://<user>:<pass>@<rds-endpoint>:5432/shieldops
SHIELDOPS_REDIS_URL=redis://<elasticache-endpoint>:6379/0
SHIELDOPS_KAFKA_BROKERS=<msk-bootstrap-brokers>
SHIELDOPS_ANTHROPIC_API_KEY=sk-ant-...
SHIELDOPS_JWT_SECRET_KEY=<generated-256-bit-key>
SHIELDOPS_OPA_ENDPOINT=http://localhost:8181
SHIELDOPS_STRIPE_API_KEY=sk_live_...
SHIELDOPS_SLACK_BOT_TOKEN=xoxb-...
```

---

## Phase 3: Database Setup (Day 1)

### 3.1 Run Migrations

```bash
# Via ECS one-off task or locally with tunnel
alembic upgrade head
```

### 3.2 Create Admin User

```bash
# Via API or management command
curl -X POST https://api.shieldops.io/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@shieldops.io", "password": "...", "name": "Admin", "role": "admin"}'
```

---

## Phase 4: First Deployment (Day 2)

### 4.1 Build and Push Images

```bash
# CI pipeline handles this automatically on merge to main
# Manual fallback:
docker build -f infrastructure/docker/Dockerfile -t shieldops-api .
docker tag shieldops-api:latest <ecr-repo>:sha-$(git rev-parse --short HEAD)
docker push <ecr-repo>:sha-$(git rev-parse --short HEAD)
```

### 4.2 Deploy to Staging

Automatic: merge to `main` → CI passes → CD Staging deploys to ECS staging.

### 4.3 Promote to Production

```bash
# Via GitHub Actions workflow_dispatch
gh workflow run cd-production.yml \
  -f image_tag=sha-abc1234
```

### 4.4 Verify Deployment

```bash
# Health check
curl https://api.shieldops.io/health | jq .

# Expected response:
# { "status": "healthy", "checks": { "database": "healthy", "redis": "healthy", "kafka": "healthy" } }
```

---

## Phase 5: Post-Deploy Verification (Day 2)

### 5.1 Smoke Test

```bash
# Run k6 smoke test against production
k6 run tests/load/smoke-test.js -e API_URL=https://api.shieldops.io/api/v1
```

### 5.2 Agent Verification

```bash
# Trigger a test investigation via API
curl -X POST https://api.shieldops.io/api/v1/agents/investigate \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "smoke-test-001",
    "alert_name": "Smoke Test",
    "severity": "info",
    "environment": "production"
  }'
```

### 5.3 Dashboard Verification

- Open `https://shieldops.io`
- Verify landing page loads (chat-first hero, agent showcase)
- Click "Try Demo" → verify demo mode activates
- Login with admin credentials → verify dashboard loads

---

## Phase 6: Monitoring Setup (Day 3)

### 6.1 Import Grafana Dashboards

```bash
# Upload via Grafana API
curl -X POST https://grafana.internal/api/dashboards/db \
  -H "Authorization: Bearer <grafana-token>" \
  -H "Content-Type: application/json" \
  -d @infrastructure/monitoring/grafana/shieldops-overview.json

curl -X POST https://grafana.internal/api/dashboards/db \
  -H "Authorization: Bearer <grafana-token>" \
  -H "Content-Type: application/json" \
  -d @infrastructure/monitoring/grafana/agent-metrics.json
```

### 6.2 Configure Prometheus

```bash
# Apply recording rules and alert rules
kubectl apply -f infrastructure/monitoring/prometheus/
```

### 6.3 PagerDuty Integration

Configure routing key in Prometheus AlertManager to forward critical alerts.

---

## Phase 7: Security Hardening (Day 3-4)

### 7.1 OPA Policy Deployment

```bash
# Deploy OPA sidecar with policy bundle
kubectl apply -f infrastructure/kubernetes/opa-deployment.yaml
kubectl apply -f infrastructure/kubernetes/opa-policies-configmap.yaml
```

### 7.2 Verify Rate Limiting

```bash
# Send 70 requests in quick succession (default limit: 60/min for viewer)
for i in $(seq 1 70); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -H "Authorization: Bearer <viewer-token>" \
    https://api.shieldops.io/api/v1/investigations
done
# Should see 429 (Too Many Requests) after ~60
```

### 7.3 Verify CORS

```bash
# Should only allow configured origins
curl -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: GET" \
  -X OPTIONS https://api.shieldops.io/api/v1/health
# Should NOT include Access-Control-Allow-Origin: https://evil.com
```

---

## Phase 8: Customer Onboarding (Day 5+)

### 8.1 First Customer Setup

1. Create organization via API
2. Generate API key with appropriate scopes
3. Configure cloud connector (provide AWS role ARN for cross-account access)
4. Run compliance auditor agent against their infrastructure
5. Trigger first investigation on a test alert

### 8.2 Billing Activation

```bash
# Create Stripe subscription via API
curl -X POST https://api.shieldops.io/api/v1/billing/subscribe \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"plan": "professional", "org_id": "org-..."}'
```

---

## Rollback Procedure

### Application Rollback

```bash
# Via GitHub Actions
gh workflow run cd-production.yml -f rollback=true

# Or manual ECS rollback
aws ecs update-service \
  --cluster shieldops-production-cluster \
  --service shieldops-production-service \
  --task-definition shieldops-production-app:<previous-revision> \
  --force-new-deployment
```

### Database Rollback

```bash
# Rollback last migration
alembic downgrade -1
```

---

## Monitoring Checklist (Ongoing)

| Check | Frequency | Alert Threshold |
|-------|-----------|----------------|
| API error rate | Continuous | > 5% for 5 min |
| P95 latency | Continuous | > 2s for 5 min |
| Agent failure rate | Continuous | > 20% for 10 min |
| Agent P95 duration | Continuous | > 120s for 5 min |
| LLM cost rate | Continuous | > $5/min for 15 min |
| Database connections | Every 60s | > 80% pool utilization |
| Redis memory | Every 60s | > 80% max memory |
| Kafka consumer lag | Every 30s | > 10,000 messages |
| OPA policy failures | Continuous | Any failure |
| Disk usage | Every 5 min | > 80% |

---

## Phase 9: AI Security Control Plane Deployment

This phase deploys the AI-specific security controls that protect autonomous agents in production. Each sub-phase is incremental — start in audit/observe mode, validate, then enforce.

---

### Phase 9.1: Agent Firewall (Audit Mode)

**Duration:** 1-2 days

1. **Deploy firewall proxy** (K8s manifest or Docker Compose):
   ```bash
   kubectl apply -f infrastructure/kubernetes/agent-firewall-deployment.yaml
   # Or via Compose:
   docker compose up -d agent-firewall
   ```

2. **Configure monitoring mode:**
   ```bash
   # Set in ECS task definition / K8s ConfigMap / .env
   SHIELDOPS_FIREWALL_MODE=audit
   ```

3. **Install SDK in one AI agent:**
   ```python
   from shieldops.security.agent_behavioral_firewall import AgentBehavioralFirewall
   # Or via callback handler:
   handler = ShieldOpsCallbackHandler(api_key="sk-shieldops-...")
   ```

4. **Verify events flowing:**
   ```bash
   curl -s https://api.shieldops.io/api/v1/agent-firewall/agents/investigation/events | jq '.[-3:]'
   ```

5. **Validate Grafana dashboard** shows intercepted calls, allow/block ratios, and per-agent risk scores.

**Rollback:** Remove SDK callback from the agent, stop the firewall proxy container.

---

### Phase 9.2: NHI Registry Activation

**Duration:** 1 week

1. **Enable NHI scanning:**
   ```bash
   SHIELDOPS_NHI_SCAN_ENABLED=true
   ```

2. **Configure cloud providers** (AWS IAM, GCP Service Accounts, Azure AD App Registrations, Kubernetes ServiceAccounts):
   ```bash
   # Verify connector credentials are configured
   shieldops connectors test --provider aws --scope iam
   shieldops connectors test --provider gcp --scope service-accounts
   shieldops connectors test --provider azure --scope app-registrations
   shieldops connectors test --provider kubernetes --scope service-accounts
   ```

3. **Run initial scan:**
   ```bash
   shieldops nhi scan
   ```

4. **Review discovered identities** in the NHI Registry dashboard (`/dashboard/nhi-registry`).

5. **Address orphaned/over-privileged identities** — disable unused service accounts, rotate stale credentials, scope down IAM roles.

**Rollback:** Disable scanning (`SHIELDOPS_NHI_SCAN_ENABLED=false`). Discovered data is retained for review.

---

### Phase 9.3: MCP Security Gateway

**Duration:** 3-5 days

1. **Deploy MCP gateway proxy:**
   ```bash
   kubectl apply -f infrastructure/kubernetes/mcp-gateway-deployment.yaml
   # Or:
   docker compose up -d mcp-gateway
   ```

2. **Configure in audit mode:**
   ```bash
   SHIELDOPS_MCP_GATEWAY_MODE=audit
   ```

3. **Register MCP server endpoints:**
   ```bash
   curl -X POST https://api.shieldops.io/api/v1/mcp-gateway/servers \
     -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{"name": "internal-tools", "endpoint": "https://mcp.internal/sse"}'
   ```

4. **Review God Key detections** and supply chain scan results in the MCP Security dashboard (`/dashboard/mcp-security`).

**Rollback:** Bypass gateway proxy by pointing agents directly to MCP servers.

---

### Phase 9.4: SOC Brain + Vendor Connectors

**Duration:** 1 week

1. **Configure vendor credentials:**
   ```bash
   # EDR
   SHIELDOPS_EDR_CLIENT_ID=<client-id>
   SHIELDOPS_EDR_CLIENT_SECRET=<client-secret>

   # Microsoft endpoint protection
   SHIELDOPS_DEFENDER_TENANT_ID=<tenant-id>
   SHIELDOPS_DEFENDER_CLIENT_ID=<client-id>
   SHIELDOPS_DEFENDER_CLIENT_SECRET=<client-secret>

   # Wiz
   SHIELDOPS_WIZ_CLIENT_ID=<client-id>
   SHIELDOPS_WIZ_CLIENT_SECRET=<client-secret>
   ```

2. **Enable webhook receivers** for real-time events:
   ```bash
   # Verify webhook endpoints are reachable
   curl -s https://api.shieldops.io/api/v1/webhooks/edr/health
   curl -s https://api.shieldops.io/api/v1/webhooks/defender/health
   curl -s https://api.shieldops.io/api/v1/webhooks/wiz/health
   ```

3. **Verify events flowing through Kafka topics:**
   ```bash
   # Check consumer group lag
   kafka-consumer-groups.sh --bootstrap-server $KAFKA_BROKERS \
     --group shieldops-soc-brain --describe
   ```

4. **Monitor Situations Queue** for first AI-curated situations in the SOC dashboard (`/dashboard/soc-situations`).

5. **Test approval workflow** with a low-risk action to confirm Slack/email notifications fire correctly.

**Rollback:** Disable vendor connectors. SOC Brain continues to operate with manual data input.

---

### Phase 9.5: Switch to Enforce Mode

**Duration:** 2-3 days

> **Prerequisite:** Validate 2+ weeks of audit data show acceptable false positive rate (<5%).

1. **Switch firewall to enforce mode:**
   ```bash
   SHIELDOPS_FIREWALL_MODE=enforce
   ```

2. **Switch MCP gateway to enforce:**
   ```bash
   SHIELDOPS_MCP_GATEWAY_MODE=enforce
   ```

3. **Enable auto-execute for SOC Brain** (confidence > 0.85):
   ```bash
   SHIELDOPS_SOC_BRAIN_AUTO_EXECUTE=true
   SHIELDOPS_SOC_BRAIN_AUTO_EXECUTE_THRESHOLD=0.85
   ```

4. **Monitor for 48 hours**, verify no production impact:
   - Agent success rate remains > 95%
   - No false-positive blocks on legitimate agent actions
   - P95 latency overhead from firewall < 10ms
   - SOC Brain auto-executed actions have 0 rollbacks

**Rollback:** Switch back to audit mode immediately:
```bash
SHIELDOPS_FIREWALL_MODE=audit
SHIELDOPS_MCP_GATEWAY_MODE=audit
SHIELDOPS_SOC_BRAIN_AUTO_EXECUTE=false
```

---

### Phase 9.6: GitOps Activation

**Duration:** 1 day

1. **Enable ArgoCD sync** for AI Security manifests:
   ```bash
   kubectl apply -f infrastructure/kubernetes/argocd-app-ai-security.yaml
   ```

2. **Verify Kustomize overlays** deploy correctly (staging first):
   ```bash
   kustomize build infrastructure/kubernetes/overlays/staging | kubectl apply --dry-run=client -f -
   kustomize build infrastructure/kubernetes/overlays/production | kubectl apply --dry-run=client -f -
   ```

3. **Test OPA policy sync** via GitOps agent:
   ```bash
   shieldops agents run gitops --action sync-policies --target staging
   ```

4. **Enable gitops-sync.yml workflow** in GitHub Actions (remove `workflow_dispatch` guard if present).

**Rollback:** Disable ArgoCD auto-sync, revert to manual `kubectl apply`.

---

## Pre-Launch Checklist — AI Security

- [ ] Agent Firewall proxy deployed and receiving events
- [ ] NHI scan completed, orphaned identities addressed
- [ ] MCP servers registered, God Key risks mitigated
- [ ] EDR/endpoint protection/Wiz webhooks verified
- [ ] SOC Brain creating situations from vendor events
- [ ] Grafana dashboards showing metrics
- [ ] Prometheus alerts firing correctly
- [ ] Kafka topics healthy
- [ ] Redis cache operational
- [ ] OPA policies deployed and evaluating
- [ ] Load testing passed (firewall 1K RPS, p95 < 100ms)
- [ ] Resilience tests passing (circuit breaker, kill switch, degradation)

---

## Platform Metrics at Launch

| Metric | Value |
|--------|-------|
| LangGraph Agents | 50 (all LLM-wired with Claude API) |
| Engine Modules | 1,562+ |
| API Routes | 660+ files |
| Unit Tests | 62,169 passing |
| Integration Tests | 16 files (38+ tests) |
| Load Test Scenarios | 7 (k6) |
| Database Tables | 25 |
| Terraform Files | 38 (AWS + GCP + Azure) |
| K8s Manifests | 15 |
| Helm Templates | 15 |
| CI/CD Workflows | 6 |
| Dashboard Pages | 46+ |
| Documentation Files | 65+ |
