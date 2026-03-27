# ShieldOps Azure Bicep Deployment

Deploy ShieldOps to Microsoft Azure using Bicep templates and Azure CLI.

## Prerequisites

1. **Azure CLI** installed and authenticated
   ```bash
   # Install: https://docs.microsoft.com/cli/azure/install-azure-cli
   az login
   az account set --subscription YOUR_SUBSCRIPTION_ID
   ```

2. **Azure Subscription** with the following resource providers registered:
   - Microsoft.ContainerService (AKS)
   - Microsoft.DBforPostgreSQL
   - Microsoft.Cache (Redis)
   - Microsoft.EventHub
   - Microsoft.ContainerRegistry
   - Microsoft.Network
   - Microsoft.KeyVault
   - Microsoft.OperationalInsights
   - Microsoft.Insights
   - Microsoft.Cdn (Front Door)
   - Microsoft.ManagedIdentity

   The deploy script registers these automatically.

3. **Required permissions**:
   - Contributor role on the subscription (or resource group)
   - User Access Administrator (for role assignments to AKS managed identity)
   - Azure AD read access (to resolve admin object ID)

4. **Bicep CLI** (bundled with Azure CLI 2.20+)
   ```bash
   az bicep version  # should show 0.20+
   az bicep upgrade
   ```

## Resources Created

| Resource | Type | Spec |
|----------|------|------|
| Virtual Network | VNet | 10.0.0.0/16, 4 subnets (AKS, DB, Redis, AppGw) |
| AKS Cluster | Kubernetes | 3 nodes, Standard_D4s_v3, managed identity, AZ spread |
| PostgreSQL | Flexible Server | HA (zone-redundant), GP_Standard_D4s_v3, 128 GB |
| Redis | Premium P1 | TLS-only, allkeys-lru, 1 replica |
| Event Hubs | Standard | Kafka-enabled, 3 hubs (agent-events, security-alerts, telemetry) |
| Container Registry | Premium | Content trust, 30-day retention, AKS pull access |
| Key Vault | Standard | RBAC auth, soft delete, purge protection |
| Application Gateway | WAF_v2 | OWASP 3.2, bot protection, rate limiting |
| Log Analytics | Per-GB | 90-day retention, 10 GB daily cap |
| Application Insights | Web | Connected to Log Analytics |
| Front Door | Standard | CDN for dashboard, HTTPS redirect |
| Metric Alerts | 3 alerts | AKS CPU, AKS memory, PostgreSQL CPU |

## Deployment

### Quick Start

```bash
chmod +x deploy.sh

./deploy.sh \
    --subscription YOUR_SUBSCRIPTION_ID \
    --region eastus2 \
    --env production \
    --domain shieldops.example.com
```

### Configuration

| Flag / Variable | Default | Description |
|----------------|---------|-------------|
| `--subscription` / `AZURE_SUBSCRIPTION_ID` | (current) | Azure subscription ID |
| `--region` / `AZURE_REGION` | `eastus2` | Azure region |
| `--env` / `SHIELDOPS_ENV` | `production` | Environment name |
| `--rg` / `AZURE_RESOURCE_GROUP` | `shieldops-rg` | Resource group name |
| `--domain` / `SHIELDOPS_DOMAIN` | `shieldops.example.com` | Custom domain |

### Deployment Timeline

Typical deployment takes 20-40 minutes:
- VNet + Subnets: ~1 min
- AKS Cluster: ~8-12 min
- PostgreSQL (HA): ~10-15 min
- Redis Premium: ~10-15 min (runs in parallel)
- Event Hubs: ~1 min
- ACR: ~1 min
- Key Vault: ~1 min
- Application Gateway: ~5-8 min
- Front Door: ~2 min
- Monitoring: ~1 min

### Post-Deployment Steps

1. **Set secret values in Key Vault**:
   ```bash
   KV_NAME=shieldops-kv

   az keyvault secret set --vault-name $KV_NAME --name anthropic-api-key --value "sk-ant-..."
   az keyvault secret set --vault-name $KV_NAME --name jwt-secret --value "$(openssl rand -hex 32)"
   az keyvault secret set --vault-name $KV_NAME --name stripe-secret-key --value "sk_live_..."
   # Repeat for remaining secrets
   ```

2. **Push container image to ACR**:
   ```bash
   az acr login --name shieldopsacr
   docker build -t shieldopsacr.azurecr.io/shieldops:latest -f infrastructure/docker/Dockerfile .
   docker push shieldopsacr.azurecr.io/shieldops:latest
   ```

3. **Deploy workloads to AKS**:
   ```bash
   az aks get-credentials --resource-group shieldops-rg --name shieldops-aks
   kubectl apply -f infrastructure/kubernetes/
   ```

4. **Configure DNS**:
   - CNAME `shieldops.example.com` to Front Door endpoint hostname
   - Or A record to Application Gateway public IP (for direct access)

5. **Clean up temp files**:
   ```bash
   rm /tmp/.shieldops-pg-password
   ```

### Validating the Deployment

```bash
# Check AKS
kubectl get nodes
kubectl get pods -A

# Check PostgreSQL connectivity (from AKS pod)
kubectl run pg-test --rm -it --image=postgres:15 -- \
    psql "host=shieldops-pg.postgres.database.azure.com dbname=shieldops user=shieldops_admin sslmode=require"

# Check Redis connectivity
kubectl run redis-test --rm -it --image=redis:7 -- \
    redis-cli -h shieldops-redis.redis.cache.windows.net -p 6380 --tls PING

# Check App Gateway health
az network application-gateway show-backend-health \
    --resource-group shieldops-rg --name shieldops-appgw
```

## Cost Estimate (Monthly)

| Resource | Spec | Estimated Cost |
|----------|------|---------------|
| AKS (3x Standard_D4s_v3) | 4 vCPU, 16 GB each | $440 |
| PostgreSQL Flexible (HA) | GP_Standard_D4s_v3, 128 GB | $450 |
| Redis Premium P1 | 6 GB, 1 replica | $340 |
| Event Hubs Standard | 2 TU, auto-inflate to 10 | $45 - $150 |
| Container Registry Premium | 500 GB included | $170 |
| Application Gateway WAF_v2 | 2 capacity units | $250 |
| Front Door Standard | Per-request pricing | $35 - $80 |
| Key Vault | Standard, ~1K operations/mo | $3 |
| Log Analytics | ~5 GB/day ingestion | $150 |
| Application Insights | Included with Log Analytics | $0 |
| VNet + Public IPs | Standard SKU | $10 |
| **Total** | | **$1,890 - $2,100/mo** |

Costs vary by region and actual usage. Use Azure Pricing Calculator for precise estimates.

### Cost Optimization Tips

- Use Reserved Instances for AKS VMs (1-year: ~35% savings, 3-year: ~55%)
- Use Reserved Capacity for PostgreSQL (1-year: ~30% savings)
- Scale down non-production environments (change node count and SKUs)
- Set up Azure Advisor recommendations for ongoing optimization

## Cleanup

Remove all resources by deleting the resource group:

```bash
# This deletes EVERYTHING in the resource group (irreversible)
az group delete --name shieldops-rg --yes --no-wait

# Purge Key Vault (required due to soft-delete)
az keyvault purge --name shieldops-kv --location eastus2

# Clean up local files
rm /tmp/.shieldops-pg-password
```

To delete individual resources instead:

```bash
RG=shieldops-rg

# Delete in dependency order
az cdn profile delete -g $RG -n shieldops-fd --yes
az network application-gateway delete -g $RG -n shieldops-appgw
az aks delete -g $RG -n shieldops-aks --yes --no-wait
az postgres flexible-server delete -g $RG -n shieldops-pg --yes
az redis delete -g $RG -n shieldops-redis --yes
az eventhubs namespace delete -g $RG -n shieldops-eventhub
az acr delete -g $RG -n shieldopsacr --yes
az keyvault delete -g $RG -n shieldops-kv
az monitor log-analytics workspace delete -g $RG -n shieldops-logs --yes
az network vnet delete -g $RG -n shieldops-vnet
az network public-ip delete -g $RG -n shieldops-appgw-pip
```

## Architecture Diagram

```
                    Internet
                       |
               [Azure Front Door]
                   (CDN/WAF)
                       |
              [Application Gateway]
                  (WAF v2/L7 LB)
                       |
            +----------+----------+
            |     AKS Cluster     |
            |  (3x D4s_v3 nodes)  |
            +----+-----+----+----+
                 |     |    |
    +------------+     |    +------------+
    |                  |                 |
[PostgreSQL]      [Redis P1]      [Event Hubs]
 (HA/ZR)          (Premium)       (Kafka)
    |                  |                 |
    +--------+---------+---------+-------+
             |                   |
        [Key Vault]       [Log Analytics]
        (Secrets)         (Monitoring)
```
