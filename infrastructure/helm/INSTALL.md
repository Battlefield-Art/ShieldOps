# ShieldOps Helm Chart — Install Guide

Deploy ShieldOps (AI Security Control Plane) to any Kubernetes cluster via Helm.
Supports embedded datastores (DuckDB + Redis Streams) for zero-dependency self-
hosted deployments, or external PostgreSQL / Redis / Kafka for production scale.

## Prerequisites

- Kubernetes **1.27+** (tested up to 1.30)
- Helm **3.12+**
- Persistent volume provisioner (for embedded DuckDB storage)
- An LLM API key: Anthropic (recommended), OpenAI, or a cloud-hosted model
  (AWS Bedrock, GCP Vertex, Azure OpenAI)
- Ingress controller (optional, if `ingress.enabled=true`)
- `cert-manager` (optional, for TLS via Let's Encrypt)

## Quick Start (embedded mode)

The default values ship with embedded DuckDB + Redis and no Kafka — ideal for
evaluation, small teams, and air-gapped environments.

```bash
helm install shieldops infrastructure/helm/shieldops \
  -n shieldops --create-namespace \
  --set llm.apiKey=$ANTHROPIC_API_KEY
```

### Verify

```bash
kubectl get pods -n shieldops
kubectl get svc  -n shieldops
kubectl logs -n shieldops deploy/shieldops-api -f
```

You should see the API pod become `Ready`, the worker pod become `Ready`,
and the PVC `shieldops-data` bound to a volume.

### Access the API

```bash
kubectl port-forward -n shieldops svc/shieldops-api 8000:8000
curl http://localhost:8000/health
```

## Production Deployment (external datastores)

```bash
helm install shieldops infrastructure/helm/shieldops \
  -n shieldops --create-namespace \
  --set llm.provider=anthropic \
  --set llm.apiKey=$ANTHROPIC_API_KEY \
  --set database.embedded=false \
  --set database.external.url="postgresql+asyncpg://user:pass@pg-host:5432/shieldops" \
  --set redisCompat.embedded=false \
  --set redisCompat.external.url="redis://redis-host:6379/0" \
  --set kafka.enabled=true \
  --set ingress.enabled=true \
  --set-string ingress.hosts[0].host=shieldops.example.com \
  --set ingestion.maxGbPerDay=50 \
  --set autoscaling.maxReplicas=20
```

## Configure Connectors

After the install completes, configure cloud, EDR, SIEM, and ITSM connectors
via the API:

```bash
# AWS connector
curl -X POST http://localhost:8000/api/v1/connectors/aws \
  -H "Authorization: Bearer $SHIELDOPS_JWT" \
  -d '{"region":"us-east-1","role_arn":"arn:aws:iam::123456789012:role/ShieldOps"}'

# Splunk connector
curl -X POST http://localhost:8000/api/v1/connectors/splunk \
  -H "Authorization: Bearer $SHIELDOPS_JWT" \
  -d '{"host":"splunk.example.com","token":"<HEC token>"}'
```

Supported connectors: AWS, GCP, Azure, Kubernetes, Linux, Windows, CrowdStrike,
Microsoft Defender, Wiz, Splunk, Elastic, Datadog, New Relic, PagerDuty,
OpsGenie, ServiceNow, Jira.

## Air-Gapped Installation

Air-gapped mode disables all outbound telemetry (LangSmith traces, OTel export,
update checks) and prevents any call to cloud-hosted connectors.

1. **Mirror images** to your internal registry:
   ```bash
   for img in shieldops/api:0.1.0 shieldops/dashboard:0.1.0 \
              openpolicyagent/opa:latest-static; do
     docker pull $img
     docker tag  $img registry.internal/$img
     docker push registry.internal/$img
   done
   ```

2. **Install with air-gapped flag**:
   ```bash
   helm install shieldops infrastructure/helm/shieldops \
     -n shieldops --create-namespace \
     --set airGapped=true \
     --set image.repository=registry.internal/shieldops/api \
     --set frontend.image.repository=registry.internal/shieldops/dashboard \
     --set worker.image.repository=registry.internal/shieldops/api \
     --set opa.image.repository=registry.internal/openpolicyagent/opa \
     --set llm.provider=bedrock \
     --set llm.region=us-gov-west-1
   ```

3. **Use an in-VPC LLM**: point `llm.provider` at AWS Bedrock, Vertex AI with
   VPC Service Controls, or Azure OpenAI with Private Link. Direct Anthropic
   calls are blocked when `airGapped=true`.

## Upgrade

```bash
helm upgrade shieldops infrastructure/helm/shieldops \
  -n shieldops \
  --reuse-values \
  --set image.tag=0.2.0
```

Alembic migrations run automatically as a pre-upgrade hook.

## Uninstall

```bash
helm uninstall shieldops -n shieldops
# PVCs are retained by default — delete explicitly if desired:
kubectl delete pvc -n shieldops -l app.kubernetes.io/name=shieldops
```

## Common Values

| Key                              | Default        | Description                              |
|----------------------------------|----------------|------------------------------------------|
| `image.repository`               | `ghcr.io/shieldops/api` | API container image              |
| `image.tag`                      | `latest`       | Image tag                                |
| `replicaCount`                   | `2`            | API replicas                             |
| `llm.provider`                   | `anthropic`    | `anthropic` / `bedrock` / `vertex` / `azure` |
| `llm.apiKey`                     | `""`           | LLM API key                              |
| `database.embedded`              | `true`         | Use embedded DuckDB                      |
| `database.external.url`          | `""`           | External PostgreSQL URL                  |
| `redisCompat.embedded`           | `true`         | Use embedded Redis-compat store          |
| `redisCompat.external.url`       | `""`           | External Redis URL                       |
| `kafka.enabled`                  | `false`        | Deploy Kafka subchart                    |
| `ingestion.maxGbPerDay`          | `5`            | Ingestion cap (GB/day)                   |
| `storage.size`                   | `20Gi`         | PVC size for embedded DB                 |
| `storage.path`                   | `/data`        | Mount path for embedded DB               |
| `airGapped`                      | `false`        | Disable outbound telemetry/SaaS calls    |
| `ingress.enabled`                | `true`         | Create Ingress resource                  |
| `autoscaling.enabled`            | `true`         | Enable API HPA                           |
| `autoscaling.maxReplicas`        | `10`           | Upper bound for HPA                      |

See `infrastructure/helm/shieldops/values.yaml` for the full list.

## Troubleshooting

- **PVC stuck in Pending**: your cluster has no default StorageClass. Set
  `storage.storageClassName` to a valid class or set `storage.enabled=false`
  and use an external database.
- **Migration job fails**: check logs with
  `kubectl logs -n shieldops job/shieldops-migration` — usually indicates
  `database.external.url` is unreachable or credentials are wrong.
- **LLM calls failing**: confirm the secret was created
  (`kubectl get secret -n shieldops shieldops-secrets -o yaml`) and that
  `SHIELDOPS_LLM_API_KEY` is set.
- **Helm template validation**: run
  `./tests/helm/test_helm_template.sh` to validate multiple value permutations.
