# Infrastructure — Multi-Cloud Deployment

ShieldOps supports deployment to AWS, GCP, Azure, and On-Premises using native cloud tools.

## Deployment Options

| Method | Cloud | Tool | Directory | Best For |
|--------|-------|------|-----------|----------|
| **AWS CDK** | AWS | Python CDK | `aws-cdk/` | AWS-native, programmatic |
| **AWS CloudFormation** | AWS | YAML template | `aws-cloudformation/` | AWS-native, declarative |
| **Terraform** | AWS/GCP/Azure | HCL | `terraform/` | Multi-cloud, existing Terraform |
| **GCP Native** | GCP | gcloud CLI | `gcp-native/` | GCP-native, scripted |
| **Azure Bicep** | Azure | Bicep + az CLI | `azure-bicep/` | Azure-native, declarative |
| **On-Prem Ansible** | On-Prem | Ansible | `onprem-ansible/` | Bare metal, air-gapped |
| **Helm** | Any K8s | Helm chart | `helm/` | Existing K8s clusters |
| **Docker Compose** | Local | Docker | `docker/` | Development, evaluation |
| **Railway** | PaaS | Railway | `railway/` | Quick PaaS deployment |

## Quick Start by Cloud

### AWS (CDK — recommended)
```bash
cd infrastructure/aws-cdk
pip install -r requirements.txt
cdk bootstrap
cdk deploy --all
```

### AWS (CloudFormation)
```bash
cd infrastructure/aws-cloudformation
aws cloudformation deploy \
  --template-file template.yaml \
  --stack-name shieldops-production \
  --parameter-overrides Environment=production DomainName=shieldops.io \
  --capabilities CAPABILITY_NAMED_IAM
```

### GCP
```bash
cd infrastructure/gcp-native
chmod +x deploy.sh
./deploy.sh --project shieldops-prod --region us-central1
```

### Azure
```bash
cd infrastructure/azure-bicep
chmod +x deploy.sh
./deploy.sh --resource-group shieldops-prod --location eastus
```

### On-Premises
```bash
cd infrastructure/onprem-ansible
ansible-playbook -i inventory.yml playbook.yml
```

### Helm (any K8s cluster)
```bash
helm install shieldops infrastructure/helm/shieldops/ \
  --namespace shieldops --create-namespace \
  --values infrastructure/helm/shieldops/values-production.yaml
```

## Architecture Components

All deployment methods provision:

| Component | Purpose | Production Specs |
|-----------|---------|-----------------|
| API Server | FastAPI, 749 endpoints | 3+ replicas, 2 vCPU, 4GB |
| Agent Workers | 151 LangGraph agents | 2-20 pods (auto-scaled), 4 vCPU, 8GB |
| Dashboard | React SPA, 158 pages | Static CDN |
| PostgreSQL | Primary database | Multi-AZ/HA, 100GB SSD |
| Redis | Cache, rate limiting | Cluster/HA, 4GB |
| Kafka | Event streaming | 3-broker cluster, 100GB each |
| OPA | Policy evaluation | Sidecar per pod |
| Monitoring | Prometheus + Grafana | Dedicated namespace |

## Cost Estimates

| Cloud | Startup (<100 users) | Growth (1K users) | Enterprise (10K+) |
|-------|---------------------|-------------------|-------------------|
| AWS | ~$800/mo | ~$2,500/mo | ~$8,000/mo |
| GCP | ~$750/mo | ~$2,300/mo | ~$7,500/mo |
| Azure | ~$850/mo | ~$2,600/mo | ~$8,500/mo |
| On-Prem | ~$15K hardware + $500/mo | Same hardware | Same hardware |

*Plus Anthropic API costs (~$0.015/1K tokens for Opus)*

## Post-Deployment

After deploying on any platform:

1. Run database migrations: `alembic upgrade head`
2. Upload OPA policies: `scripts/upload-opa-policies.sh`
3. Configure connectors via API
4. Verify: `curl https://your-domain/health`
5. Run smoke tests: `pytest tests/integration/ -k smoke`

See [docs/DEPLOYMENT_GUIDE.md](../docs/DEPLOYMENT_GUIDE.md) for detailed instructions.
