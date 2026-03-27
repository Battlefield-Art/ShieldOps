# infrastructure/ — Deployment Infrastructure

## Components
```
infrastructure/
├── docker/
│   ├── Dockerfile          # Multi-stage Python build
│   └── docker-compose.yml  # Local dev stack (DB, Redis, Kafka, OPA)
├── kubernetes/             # 16 K8s manifests
│   ├── deployment.yaml
│   ├── hpa.yaml            # Horizontal Pod Autoscaler
│   ├── ingress.yaml
│   ├── network-policies.yaml
│   ├── pdb.yaml            # Pod Disruption Budget
│   ├── kafka.yaml
│   ├── redis.yaml
│   ├── opa-sidecar.yaml
│   ├── secrets.yaml
│   └── configmaps.yaml
├── terraform/
│   ├── aws/                # AWS modules
│   ├── gcp/                # GCP modules
│   └── azure/              # Azure modules
├── helm/                   # Helm chart for self-hosted
├── monitoring/             # Prometheus rules, Grafana dashboards
└── railway/                # Railway PaaS config
```

## Deployment Targets
- **Docker Compose** — Local development
- **Kubernetes** — Production (16 manifests)
- **Helm** — Self-hosted enterprise deployments
- **Railway** — PaaS deployment
- **Terraform** — Multi-cloud provisioning (AWS/GCP/Azure)

## CI/CD
7 GitHub Actions workflows in `.github/workflows/`:
- `ci.yml` — Lint, typecheck, test (60K+)
- `cd-backend.yml` — Backend deployment
- `cd-dashboard.yml` — Dashboard deployment
- `cd-staging.yml` — Staging environment
- `cd-production.yml` — Production environment
- `gitops-sync.yml` — GitOps reconciliation
- Security scanning integrated into CI
