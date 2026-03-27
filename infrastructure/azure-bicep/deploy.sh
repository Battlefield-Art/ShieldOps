#!/usr/bin/env bash
# ShieldOps Azure Bicep Deployment Script
# Deploys all Azure infrastructure via Bicep templates.
# Usage: ./deploy.sh [--subscription SUB_ID] [--region REGION] [--env ENV]
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SUBSCRIPTION="${AZURE_SUBSCRIPTION_ID:-}"
REGION="${AZURE_REGION:-eastus2}"
ENVIRONMENT="${SHIELDOPS_ENV:-production}"
RESOURCE_GROUP="${AZURE_RESOURCE_GROUP:-shieldops-rg}"
DOMAIN="${SHIELDOPS_DOMAIN:-shieldops.example.com}"

BICEP_FILE="$(cd "$(dirname "$0")" && pwd)/main.bicep"

# ---------------------------------------------------------------------------
# Parse CLI flags
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --subscription) SUBSCRIPTION="$2"; shift 2 ;;
        --region)       REGION="$2"; shift 2 ;;
        --env)          ENVIRONMENT="$2"; shift 2 ;;
        --rg)           RESOURCE_GROUP="$2"; shift 2 ;;
        --domain)       DOMAIN="$2"; shift 2 ;;
        *) echo "Unknown flag: $1"; exit 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { echo -e "\033[1;36m[ShieldOps]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
ok()   { echo -e "\033[1;32m[OK]\033[0m $*"; }
err()  { echo -e "\033[1;31m[ERROR]\033[0m $*"; exit 1; }

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
log "Preflight checks..."
command -v az >/dev/null 2>&1 || err "Azure CLI not found. Install: https://docs.microsoft.com/cli/azure/install-azure-cli"

# Login check
ACCOUNT=$(az account show --query "name" -o tsv 2>/dev/null || true)
if [[ -z "${ACCOUNT}" ]]; then
    err "Not logged in. Run: az login"
fi
ok "Logged in as: ${ACCOUNT}"

# Set subscription
if [[ -n "${SUBSCRIPTION}" ]]; then
    az account set --subscription "${SUBSCRIPTION}"
    ok "Subscription set to: ${SUBSCRIPTION}"
fi

CURRENT_SUB=$(az account show --query "id" -o tsv)
ADMIN_OBJECT_ID=$(az ad signed-in-user show --query "id" -o tsv 2>/dev/null || echo "")
if [[ -z "${ADMIN_OBJECT_ID}" ]]; then
    warn "Could not determine signed-in user object ID. You must provide adminObjectId manually."
    read -rp "Enter your AAD Object ID: " ADMIN_OBJECT_ID
fi

log "Subscription: ${CURRENT_SUB}"
log "Admin Object ID: ${ADMIN_OBJECT_ID}"

# ---------------------------------------------------------------------------
# Register resource providers
# ---------------------------------------------------------------------------
log "Registering resource providers..."
PROVIDERS=(
    Microsoft.ContainerService
    Microsoft.DBforPostgreSQL
    Microsoft.Cache
    Microsoft.EventHub
    Microsoft.ContainerRegistry
    Microsoft.Network
    Microsoft.KeyVault
    Microsoft.OperationalInsights
    Microsoft.Insights
    Microsoft.Cdn
    Microsoft.ManagedIdentity
)
for provider in "${PROVIDERS[@]}"; do
    STATE=$(az provider show --namespace "${provider}" --query "registrationState" -o tsv 2>/dev/null || echo "NotRegistered")
    if [[ "${STATE}" != "Registered" ]]; then
        az provider register --namespace "${provider}" --wait >/dev/null 2>&1 &
    fi
done
wait
ok "Resource providers registered"

# ---------------------------------------------------------------------------
# Create Resource Group
# ---------------------------------------------------------------------------
log "Creating resource group: ${RESOURCE_GROUP}"
az group create \
    --name "${RESOURCE_GROUP}" \
    --location "${REGION}" \
    --tags app=shieldops environment="${ENVIRONMENT}" \
    --output none
ok "Resource group ${RESOURCE_GROUP} ready"

# ---------------------------------------------------------------------------
# Generate PostgreSQL password
# ---------------------------------------------------------------------------
PG_PASSWORD_FILE="/tmp/.shieldops-pg-password"
if [[ -f "${PG_PASSWORD_FILE}" ]]; then
    PG_PASSWORD=$(cat "${PG_PASSWORD_FILE}")
    log "Using existing PostgreSQL password from ${PG_PASSWORD_FILE}"
else
    PG_PASSWORD=$(openssl rand -base64 32 | tr -d '=+/' | head -c 32)
    echo -n "${PG_PASSWORD}" > "${PG_PASSWORD_FILE}"
    chmod 600 "${PG_PASSWORD_FILE}"
    log "Generated PostgreSQL password (saved to ${PG_PASSWORD_FILE})"
fi

# ---------------------------------------------------------------------------
# Deploy Bicep template
# ---------------------------------------------------------------------------
log "Deploying Bicep template..."
log "This will create: AKS, PostgreSQL, Redis, Event Hubs, ACR, App Gateway, Key Vault, Log Analytics, VNet, Front Door"
log "Estimated time: 20-40 minutes"
echo ""

DEPLOYMENT_NAME="shieldops-$(date +%Y%m%d-%H%M%S)"

az deployment group create \
    --name "${DEPLOYMENT_NAME}" \
    --resource-group "${RESOURCE_GROUP}" \
    --template-file "${BICEP_FILE}" \
    --parameters \
        location="${REGION}" \
        environment="${ENVIRONMENT}" \
        domainName="${DOMAIN}" \
        postgresAdminPassword="${PG_PASSWORD}" \
        adminObjectId="${ADMIN_OBJECT_ID}" \
    --output table

DEPLOY_STATUS=$?
if [[ ${DEPLOY_STATUS} -ne 0 ]]; then
    err "Deployment failed. Check: az deployment group show --name ${DEPLOYMENT_NAME} --resource-group ${RESOURCE_GROUP}"
fi

ok "Bicep deployment complete"

# ---------------------------------------------------------------------------
# Retrieve outputs
# ---------------------------------------------------------------------------
log "Retrieving deployment outputs..."

AKS_NAME=$(az deployment group show \
    --name "${DEPLOYMENT_NAME}" \
    --resource-group "${RESOURCE_GROUP}" \
    --query "properties.outputs.aksClusterName.value" -o tsv)

ACR_SERVER=$(az deployment group show \
    --name "${DEPLOYMENT_NAME}" \
    --resource-group "${RESOURCE_GROUP}" \
    --query "properties.outputs.acrLoginServer.value" -o tsv)

KV_NAME=$(az deployment group show \
    --name "${DEPLOYMENT_NAME}" \
    --resource-group "${RESOURCE_GROUP}" \
    --query "properties.outputs.keyVaultName.value" -o tsv)

PG_FQDN=$(az deployment group show \
    --name "${DEPLOYMENT_NAME}" \
    --resource-group "${RESOURCE_GROUP}" \
    --query "properties.outputs.postgresFqdn.value" -o tsv)

REDIS_HOST=$(az deployment group show \
    --name "${DEPLOYMENT_NAME}" \
    --resource-group "${RESOURCE_GROUP}" \
    --query "properties.outputs.redisHostName.value" -o tsv)

APPGW_IP=$(az deployment group show \
    --name "${DEPLOYMENT_NAME}" \
    --resource-group "${RESOURCE_GROUP}" \
    --query "properties.outputs.appGatewayPublicIp.value" -o tsv)

FD_HOSTNAME=$(az deployment group show \
    --name "${DEPLOYMENT_NAME}" \
    --resource-group "${RESOURCE_GROUP}" \
    --query "properties.outputs.frontDoorEndpointHostname.value" -o tsv)

# ---------------------------------------------------------------------------
# Configure kubectl
# ---------------------------------------------------------------------------
log "Configuring kubectl for AKS..."
az aks get-credentials \
    --resource-group "${RESOURCE_GROUP}" \
    --name "${AKS_NAME}" \
    --overwrite-existing \
    --output none
ok "kubectl configured for ${AKS_NAME}"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
log "=========================================="
log "  ShieldOps Azure Deployment Complete"
log "=========================================="
echo ""
echo "  Resource Group:   ${RESOURCE_GROUP}"
echo "  Region:           ${REGION}"
echo "  AKS Cluster:      ${AKS_NAME}"
echo "  PostgreSQL:       ${PG_FQDN}"
echo "  Redis:            ${REDIS_HOST}"
echo "  ACR:              ${ACR_SERVER}"
echo "  Key Vault:        ${KV_NAME}"
echo "  App Gateway IP:   ${APPGW_IP}"
echo "  Front Door:       ${FD_HOSTNAME}"
echo ""
log "Next steps:"
echo "  1. Update Key Vault secrets:"
echo "     az keyvault secret set --vault-name ${KV_NAME} --name anthropic-api-key --value 'sk-ant-...'"
echo "  2. Push container image:"
echo "     az acr login --name ${ACR_SERVER%%.*}"
echo "     docker build -t ${ACR_SERVER}/shieldops:latest ."
echo "     docker push ${ACR_SERVER}/shieldops:latest"
echo "  3. Deploy to AKS:"
echo "     kubectl apply -f infrastructure/kubernetes/"
echo "  4. Configure DNS CNAME for ${DOMAIN} -> ${FD_HOSTNAME}"
echo "  5. Delete temp password file: rm ${PG_PASSWORD_FILE}"
echo ""
