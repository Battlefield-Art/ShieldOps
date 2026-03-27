#!/usr/bin/env bash
# ShieldOps GCP Native Deployment Script
# Idempotent — safe to re-run; checks resource existence before creating.
# Usage: ./deploy.sh [--project PROJECT_ID] [--region REGION] [--domain DOMAIN]
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration (override via env vars or CLI flags)
# ---------------------------------------------------------------------------
PROJECT_ID="${GCP_PROJECT_ID:-shieldops-prod}"
REGION="${GCP_REGION:-us-central1}"
ZONE="${GCP_ZONE:-us-central1-a}"
DOMAIN="${SHIELDOPS_DOMAIN:-shieldops.example.com}"
ENV_LABEL="${SHIELDOPS_ENV:-production}"

# Resource names
VPC_NAME="shieldops-vpc"
SUBNET_NAME="shieldops-subnet"
SUBNET_RANGE="10.0.0.0/20"
POD_RANGE="10.4.0.0/14"
SVC_RANGE="10.8.0.0/20"
NAT_ROUTER="shieldops-router"
NAT_NAME="shieldops-nat"

GKE_CLUSTER="shieldops-gke"
GKE_MACHINE="e2-standard-4"
GKE_NODES=3

SQL_INSTANCE="shieldops-pg"
SQL_TIER="db-custom-4-16384"
SQL_DISK_SIZE="100GB"
SQL_DB="shieldops"
SQL_USER="shieldops_app"

REDIS_INSTANCE="shieldops-redis"
REDIS_SIZE=4
REDIS_TIER="STANDARD"

AR_REPO="shieldops-docker"

ARMOR_POLICY="shieldops-waf"
DNS_ZONE="shieldops-zone"

LB_IP_NAME="shieldops-lb-ip"
LB_CERT_NAME="shieldops-cert"
LB_NEG_NAME="shieldops-neg"

DASHBOARD_NAME="ShieldOps Production"

# ---------------------------------------------------------------------------
# Parse CLI flags
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --project) PROJECT_ID="$2"; shift 2 ;;
        --region)  REGION="$2"; shift 2 ;;
        --domain)  DOMAIN="$2"; shift 2 ;;
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

resource_exists() {
    # $1 = gcloud command that returns 0 if resource exists
    eval "$1" &>/dev/null && return 0 || return 1
}

# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------
log "Preflight checks..."
command -v gcloud >/dev/null 2>&1 || err "gcloud CLI not found. Install: https://cloud.google.com/sdk/docs/install"
gcloud auth list --filter=status:ACTIVE --format="value(account)" | head -1 || err "Not authenticated. Run: gcloud auth login"

log "Setting project to ${PROJECT_ID}"
gcloud config set project "${PROJECT_ID}" --quiet

# Enable required APIs
APIS=(
    compute.googleapis.com
    container.googleapis.com
    sqladmin.googleapis.com
    redis.googleapis.com
    artifactregistry.googleapis.com
    dns.googleapis.com
    secretmanager.googleapis.com
    monitoring.googleapis.com
    cloudresourcemanager.googleapis.com
    servicenetworking.googleapis.com
)
log "Enabling APIs..."
gcloud services enable "${APIS[@]}" --quiet
ok "APIs enabled"

# ---------------------------------------------------------------------------
# 1. VPC + Subnet + Cloud NAT
# ---------------------------------------------------------------------------
log "1/10 — VPC Network"
if resource_exists "gcloud compute networks describe ${VPC_NAME} --project=${PROJECT_ID}"; then
    ok "VPC ${VPC_NAME} already exists"
else
    gcloud compute networks create "${VPC_NAME}" \
        --project="${PROJECT_ID}" \
        --subnet-mode=custom \
        --bgp-routing-mode=regional \
        --quiet
    ok "VPC ${VPC_NAME} created"
fi

if resource_exists "gcloud compute networks subnets describe ${SUBNET_NAME} --region=${REGION} --project=${PROJECT_ID}"; then
    ok "Subnet ${SUBNET_NAME} already exists"
else
    gcloud compute networks subnets create "${SUBNET_NAME}" \
        --project="${PROJECT_ID}" \
        --region="${REGION}" \
        --network="${VPC_NAME}" \
        --range="${SUBNET_RANGE}" \
        --secondary-range="pods=${POD_RANGE},services=${SVC_RANGE}" \
        --enable-private-ip-google-access \
        --quiet
    ok "Subnet ${SUBNET_NAME} created"
fi

# Cloud Router + NAT
if resource_exists "gcloud compute routers describe ${NAT_ROUTER} --region=${REGION} --project=${PROJECT_ID}"; then
    ok "Cloud Router ${NAT_ROUTER} already exists"
else
    gcloud compute routers create "${NAT_ROUTER}" \
        --project="${PROJECT_ID}" \
        --region="${REGION}" \
        --network="${VPC_NAME}" \
        --quiet
    ok "Cloud Router ${NAT_ROUTER} created"
fi

if resource_exists "gcloud compute routers nats describe ${NAT_NAME} --router=${NAT_ROUTER} --region=${REGION} --project=${PROJECT_ID}"; then
    ok "Cloud NAT ${NAT_NAME} already exists"
else
    gcloud compute routers nats create "${NAT_NAME}" \
        --project="${PROJECT_ID}" \
        --region="${REGION}" \
        --router="${NAT_ROUTER}" \
        --auto-allocate-nat-external-ips \
        --nat-all-subnet-ip-ranges \
        --quiet
    ok "Cloud NAT ${NAT_NAME} created"
fi

# Firewall — allow internal traffic
FW_INTERNAL="shieldops-allow-internal"
if resource_exists "gcloud compute firewall-rules describe ${FW_INTERNAL} --project=${PROJECT_ID}"; then
    ok "Firewall rule ${FW_INTERNAL} already exists"
else
    gcloud compute firewall-rules create "${FW_INTERNAL}" \
        --project="${PROJECT_ID}" \
        --network="${VPC_NAME}" \
        --allow=tcp,udp,icmp \
        --source-ranges="${SUBNET_RANGE}" \
        --quiet
    ok "Firewall rule ${FW_INTERNAL} created"
fi

# ---------------------------------------------------------------------------
# 2. GKE Autopilot Cluster
# ---------------------------------------------------------------------------
log "2/10 — GKE Autopilot Cluster"
if resource_exists "gcloud container clusters describe ${GKE_CLUSTER} --region=${REGION} --project=${PROJECT_ID}"; then
    ok "GKE cluster ${GKE_CLUSTER} already exists"
else
    gcloud container clusters create-auto "${GKE_CLUSTER}" \
        --project="${PROJECT_ID}" \
        --region="${REGION}" \
        --network="${VPC_NAME}" \
        --subnetwork="${SUBNET_NAME}" \
        --cluster-secondary-range-name="pods" \
        --services-secondary-range-name="services" \
        --enable-private-nodes \
        --enable-master-authorized-networks \
        --master-authorized-networks="0.0.0.0/0" \
        --release-channel=stable \
        --labels="app=shieldops,env=${ENV_LABEL}" \
        --quiet
    ok "GKE cluster ${GKE_CLUSTER} created"
fi

# Get cluster credentials
gcloud container clusters get-credentials "${GKE_CLUSTER}" \
    --region="${REGION}" \
    --project="${PROJECT_ID}" \
    --quiet
ok "kubectl configured for ${GKE_CLUSTER}"

# ---------------------------------------------------------------------------
# 3. Cloud SQL PostgreSQL (HA)
# ---------------------------------------------------------------------------
log "3/10 — Cloud SQL PostgreSQL"

# Allocate private IP range for services networking
PRIVATE_RANGE="shieldops-private-range"
if resource_exists "gcloud compute addresses describe ${PRIVATE_RANGE} --global --project=${PROJECT_ID}"; then
    ok "Private IP range ${PRIVATE_RANGE} already exists"
else
    gcloud compute addresses create "${PRIVATE_RANGE}" \
        --project="${PROJECT_ID}" \
        --global \
        --purpose=VPC_PEERING \
        --prefix-length=16 \
        --network="${VPC_NAME}" \
        --quiet
    gcloud services vpc-peerings connect \
        --service=servicenetworking.googleapis.com \
        --ranges="${PRIVATE_RANGE}" \
        --network="${VPC_NAME}" \
        --project="${PROJECT_ID}" \
        --quiet
    ok "Private service connection established"
fi

if resource_exists "gcloud sql instances describe ${SQL_INSTANCE} --project=${PROJECT_ID}"; then
    ok "Cloud SQL instance ${SQL_INSTANCE} already exists"
else
    SQL_PASSWORD=$(openssl rand -base64 24)
    gcloud sql instances create "${SQL_INSTANCE}" \
        --project="${PROJECT_ID}" \
        --region="${REGION}" \
        --database-version=POSTGRES_15 \
        --tier="${SQL_TIER}" \
        --storage-size="${SQL_DISK_SIZE}" \
        --storage-auto-increase \
        --availability-type=REGIONAL \
        --network="${VPC_NAME}" \
        --no-assign-ip \
        --enable-point-in-time-recovery \
        --backup-start-time="02:00" \
        --maintenance-window-day=SUN \
        --maintenance-window-hour=3 \
        --labels="app=shieldops,env=${ENV_LABEL}" \
        --quiet

    gcloud sql databases create "${SQL_DB}" \
        --instance="${SQL_INSTANCE}" \
        --project="${PROJECT_ID}" \
        --quiet

    gcloud sql users create "${SQL_USER}" \
        --instance="${SQL_INSTANCE}" \
        --password="${SQL_PASSWORD}" \
        --project="${PROJECT_ID}" \
        --quiet

    # Store password in Secret Manager
    echo -n "${SQL_PASSWORD}" | gcloud secrets create "shieldops-db-password" \
        --project="${PROJECT_ID}" \
        --data-file=- \
        --replication-policy=automatic \
        --quiet 2>/dev/null || \
    echo -n "${SQL_PASSWORD}" | gcloud secrets versions add "shieldops-db-password" \
        --project="${PROJECT_ID}" \
        --data-file=- \
        --quiet

    ok "Cloud SQL instance ${SQL_INSTANCE} created (password stored in Secret Manager)"
fi

# ---------------------------------------------------------------------------
# 4. Memorystore Redis
# ---------------------------------------------------------------------------
log "4/10 — Memorystore Redis"
if resource_exists "gcloud redis instances describe ${REDIS_INSTANCE} --region=${REGION} --project=${PROJECT_ID}"; then
    ok "Redis instance ${REDIS_INSTANCE} already exists"
else
    gcloud redis instances create "${REDIS_INSTANCE}" \
        --project="${PROJECT_ID}" \
        --region="${REGION}" \
        --size="${REDIS_SIZE}" \
        --tier="${REDIS_TIER}" \
        --redis-version=redis_7_0 \
        --network="${VPC_NAME}" \
        --connect-mode=PRIVATE_SERVICE_ACCESS \
        --labels="app=shieldops,env=${ENV_LABEL}" \
        --quiet
    ok "Redis instance ${REDIS_INSTANCE} created"
fi

# ---------------------------------------------------------------------------
# 5. Artifact Registry
# ---------------------------------------------------------------------------
log "5/10 — Artifact Registry"
if resource_exists "gcloud artifacts repositories describe ${AR_REPO} --location=${REGION} --project=${PROJECT_ID}"; then
    ok "Artifact Registry ${AR_REPO} already exists"
else
    gcloud artifacts repositories create "${AR_REPO}" \
        --project="${PROJECT_ID}" \
        --location="${REGION}" \
        --repository-format=docker \
        --description="ShieldOps container images" \
        --quiet
    ok "Artifact Registry ${AR_REPO} created"
fi

# ---------------------------------------------------------------------------
# 6. Secret Manager — application secrets
# ---------------------------------------------------------------------------
log "6/10 — Secret Manager"
SECRETS=(
    "shieldops-anthropic-api-key"
    "shieldops-openai-api-key"
    "shieldops-redis-url"
    "shieldops-kafka-brokers"
    "shieldops-opa-endpoint"
    "shieldops-langsmith-api-key"
    "shieldops-stripe-secret-key"
    "shieldops-stripe-webhook-secret"
    "shieldops-slack-bot-token"
    "shieldops-pagerduty-api-key"
    "shieldops-jwt-secret"
)
for secret in "${SECRETS[@]}"; do
    if resource_exists "gcloud secrets describe ${secret} --project=${PROJECT_ID}"; then
        ok "Secret ${secret} already exists"
    else
        echo -n "REPLACE_ME" | gcloud secrets create "${secret}" \
            --project="${PROJECT_ID}" \
            --data-file=- \
            --replication-policy=automatic \
            --labels="app=shieldops" \
            --quiet
        warn "Secret ${secret} created with placeholder — update with real value"
    fi
done

# ---------------------------------------------------------------------------
# 7. Cloud DNS
# ---------------------------------------------------------------------------
log "7/10 — Cloud DNS"
if resource_exists "gcloud dns managed-zones describe ${DNS_ZONE} --project=${PROJECT_ID}"; then
    ok "DNS zone ${DNS_ZONE} already exists"
else
    gcloud dns managed-zones create "${DNS_ZONE}" \
        --project="${PROJECT_ID}" \
        --dns-name="${DOMAIN}." \
        --description="ShieldOps DNS zone" \
        --quiet
    ok "DNS zone ${DNS_ZONE} created"
fi

# ---------------------------------------------------------------------------
# 8. Cloud Load Balancer (HTTPS with managed cert)
# ---------------------------------------------------------------------------
log "8/10 — Cloud Load Balancer"

# Reserve static IP
if resource_exists "gcloud compute addresses describe ${LB_IP_NAME} --global --project=${PROJECT_ID}"; then
    ok "Static IP ${LB_IP_NAME} already exists"
else
    gcloud compute addresses create "${LB_IP_NAME}" \
        --project="${PROJECT_ID}" \
        --global \
        --quiet
    ok "Static IP ${LB_IP_NAME} reserved"
fi

LB_IP=$(gcloud compute addresses describe "${LB_IP_NAME}" --global --project="${PROJECT_ID}" --format="value(address)")
log "Load Balancer IP: ${LB_IP}"

# DNS A record
gcloud dns record-sets create "${DOMAIN}." \
    --project="${PROJECT_ID}" \
    --zone="${DNS_ZONE}" \
    --type=A \
    --ttl=300 \
    --rrdatas="${LB_IP}" \
    --quiet 2>/dev/null || ok "DNS A record already exists"

# Managed SSL certificate
if resource_exists "gcloud compute ssl-certificates describe ${LB_CERT_NAME} --global --project=${PROJECT_ID}"; then
    ok "SSL certificate ${LB_CERT_NAME} already exists"
else
    gcloud compute ssl-certificates create "${LB_CERT_NAME}" \
        --project="${PROJECT_ID}" \
        --domains="${DOMAIN}" \
        --global \
        --quiet
    ok "Managed SSL certificate ${LB_CERT_NAME} created"
fi

# Health check
HC_NAME="shieldops-hc"
if resource_exists "gcloud compute health-checks describe ${HC_NAME} --project=${PROJECT_ID}"; then
    ok "Health check ${HC_NAME} already exists"
else
    gcloud compute health-checks create http "${HC_NAME}" \
        --project="${PROJECT_ID}" \
        --port=8000 \
        --request-path="/health" \
        --check-interval=10s \
        --timeout=5s \
        --healthy-threshold=2 \
        --unhealthy-threshold=3 \
        --quiet
    ok "Health check ${HC_NAME} created"
fi

# Backend service
BS_NAME="shieldops-backend-svc"
if resource_exists "gcloud compute backend-services describe ${BS_NAME} --global --project=${PROJECT_ID}"; then
    ok "Backend service ${BS_NAME} already exists"
else
    gcloud compute backend-services create "${BS_NAME}" \
        --project="${PROJECT_ID}" \
        --global \
        --protocol=HTTP \
        --port-name=http \
        --health-checks="${HC_NAME}" \
        --security-policy="${ARMOR_POLICY}" \
        --timeout=30s \
        --quiet 2>/dev/null || \
    gcloud compute backend-services create "${BS_NAME}" \
        --project="${PROJECT_ID}" \
        --global \
        --protocol=HTTP \
        --port-name=http \
        --health-checks="${HC_NAME}" \
        --timeout=30s \
        --quiet
    ok "Backend service ${BS_NAME} created"
fi

# URL map
URLMAP="shieldops-url-map"
if resource_exists "gcloud compute url-maps describe ${URLMAP} --project=${PROJECT_ID}"; then
    ok "URL map ${URLMAP} already exists"
else
    gcloud compute url-maps create "${URLMAP}" \
        --project="${PROJECT_ID}" \
        --default-service="${BS_NAME}" \
        --quiet
    ok "URL map ${URLMAP} created"
fi

# HTTPS proxy
PROXY="shieldops-https-proxy"
if resource_exists "gcloud compute target-https-proxies describe ${PROXY} --project=${PROJECT_ID}"; then
    ok "HTTPS proxy ${PROXY} already exists"
else
    gcloud compute target-https-proxies create "${PROXY}" \
        --project="${PROJECT_ID}" \
        --url-map="${URLMAP}" \
        --ssl-certificates="${LB_CERT_NAME}" \
        --quiet
    ok "HTTPS proxy ${PROXY} created"
fi

# Forwarding rule
FWD="shieldops-https-fwd"
if resource_exists "gcloud compute forwarding-rules describe ${FWD} --global --project=${PROJECT_ID}"; then
    ok "Forwarding rule ${FWD} already exists"
else
    gcloud compute forwarding-rules create "${FWD}" \
        --project="${PROJECT_ID}" \
        --global \
        --address="${LB_IP_NAME}" \
        --target-https-proxy="${PROXY}" \
        --ports=443 \
        --quiet
    ok "Forwarding rule ${FWD} created"
fi

# HTTP-to-HTTPS redirect
HTTP_URLMAP="shieldops-http-redirect"
HTTP_PROXY="shieldops-http-proxy"
HTTP_FWD="shieldops-http-fwd"
if ! resource_exists "gcloud compute url-maps describe ${HTTP_URLMAP} --project=${PROJECT_ID}"; then
    gcloud compute url-maps import "${HTTP_URLMAP}" \
        --project="${PROJECT_ID}" \
        --source=/dev/stdin --quiet <<YAML
name: ${HTTP_URLMAP}
defaultUrlRedirect:
  httpsRedirect: true
  redirectResponseCode: MOVED_PERMANENTLY_DEFAULT
YAML
    gcloud compute target-http-proxies create "${HTTP_PROXY}" \
        --project="${PROJECT_ID}" \
        --url-map="${HTTP_URLMAP}" \
        --quiet
    gcloud compute forwarding-rules create "${HTTP_FWD}" \
        --project="${PROJECT_ID}" \
        --global \
        --address="${LB_IP_NAME}" \
        --target-http-proxy="${HTTP_PROXY}" \
        --ports=80 \
        --quiet
    ok "HTTP-to-HTTPS redirect configured"
else
    ok "HTTP redirect already exists"
fi

# ---------------------------------------------------------------------------
# 9. Cloud Armor (WAF)
# ---------------------------------------------------------------------------
log "9/10 — Cloud Armor WAF"
if resource_exists "gcloud compute security-policies describe ${ARMOR_POLICY} --project=${PROJECT_ID}"; then
    ok "Cloud Armor policy ${ARMOR_POLICY} already exists"
else
    gcloud compute security-policies create "${ARMOR_POLICY}" \
        --project="${PROJECT_ID}" \
        --description="ShieldOps WAF policy" \
        --quiet

    # OWASP Top 10 rules
    gcloud compute security-policies rules create 1000 \
        --project="${PROJECT_ID}" \
        --security-policy="${ARMOR_POLICY}" \
        --expression="evaluatePreconfiguredExpr('sqli-v33-stable')" \
        --action=deny-403 \
        --description="SQL injection protection" \
        --quiet

    gcloud compute security-policies rules create 1001 \
        --project="${PROJECT_ID}" \
        --security-policy="${ARMOR_POLICY}" \
        --expression="evaluatePreconfiguredExpr('xss-v33-stable')" \
        --action=deny-403 \
        --description="XSS protection" \
        --quiet

    gcloud compute security-policies rules create 1002 \
        --project="${PROJECT_ID}" \
        --security-policy="${ARMOR_POLICY}" \
        --expression="evaluatePreconfiguredExpr('lfi-v33-stable')" \
        --action=deny-403 \
        --description="Local file inclusion protection" \
        --quiet

    gcloud compute security-policies rules create 1003 \
        --project="${PROJECT_ID}" \
        --security-policy="${ARMOR_POLICY}" \
        --expression="evaluatePreconfiguredExpr('rfi-v33-stable')" \
        --action=deny-403 \
        --description="Remote file inclusion protection" \
        --quiet

    gcloud compute security-policies rules create 1004 \
        --project="${PROJECT_ID}" \
        --security-policy="${ARMOR_POLICY}" \
        --expression="evaluatePreconfiguredExpr('rce-v33-stable')" \
        --action=deny-403 \
        --description="Remote code execution protection" \
        --quiet

    # Rate limiting
    gcloud compute security-policies rules create 2000 \
        --project="${PROJECT_ID}" \
        --security-policy="${ARMOR_POLICY}" \
        --expression="true" \
        --action=throttle \
        --rate-limit-threshold-count=100 \
        --rate-limit-threshold-interval-sec=60 \
        --conform-action=allow \
        --exceed-action=deny-429 \
        --enforce-on-key=IP \
        --description="Rate limit 100 req/min per IP" \
        --quiet

    # Geo-blocking (example: block known-bad regions, adjust as needed)
    gcloud compute security-policies rules create 3000 \
        --project="${PROJECT_ID}" \
        --security-policy="${ARMOR_POLICY}" \
        --expression="origin.region_code == 'KP'" \
        --action=deny-403 \
        --description="Geo-block sanctioned regions" \
        --quiet

    # Attach to backend service
    gcloud compute backend-services update "${BS_NAME}" \
        --project="${PROJECT_ID}" \
        --global \
        --security-policy="${ARMOR_POLICY}" \
        --quiet 2>/dev/null || true

    ok "Cloud Armor WAF policy ${ARMOR_POLICY} created with OWASP rules"
fi

# ---------------------------------------------------------------------------
# 10. Cloud Monitoring — Dashboards + Alert Policies
# ---------------------------------------------------------------------------
log "10/10 — Cloud Monitoring"

# Notification channel (email)
NOTIFICATION_EMAIL="${SHIELDOPS_ALERT_EMAIL:-ops@shieldops.io}"
CHANNEL_ID=$(gcloud alpha monitoring channels list \
    --project="${PROJECT_ID}" \
    --filter="type='email' AND labels.email_address='${NOTIFICATION_EMAIL}'" \
    --format="value(name)" 2>/dev/null | head -1)

if [[ -z "${CHANNEL_ID}" ]]; then
    CHANNEL_ID=$(gcloud alpha monitoring channels create \
        --project="${PROJECT_ID}" \
        --display-name="ShieldOps Ops Team" \
        --type=email \
        --channel-labels="email_address=${NOTIFICATION_EMAIL}" \
        --format="value(name)" \
        --quiet 2>/dev/null || echo "")
    if [[ -n "${CHANNEL_ID}" ]]; then
        ok "Notification channel created: ${CHANNEL_ID}"
    else
        warn "Could not create notification channel (alpha API may not be enabled)"
    fi
else
    ok "Notification channel already exists"
fi

# Alert policies via REST API
create_alert_policy() {
    local display_name="$1"
    local filter="$2"
    local threshold="$3"
    local comparison="$4"
    local duration="$5"

    # Check if alert already exists
    EXISTING=$(gcloud alpha monitoring policies list \
        --project="${PROJECT_ID}" \
        --filter="displayName='${display_name}'" \
        --format="value(name)" 2>/dev/null | head -1)

    if [[ -n "${EXISTING}" ]]; then
        ok "Alert policy '${display_name}' already exists"
        return
    fi

    local channel_ref=""
    if [[ -n "${CHANNEL_ID:-}" ]]; then
        channel_ref="\"notificationChannels\": [\"${CHANNEL_ID}\"],"
    fi

    curl -s -X POST \
        "https://monitoring.googleapis.com/v3/projects/${PROJECT_ID}/alertPolicies" \
        -H "Authorization: Bearer $(gcloud auth print-access-token)" \
        -H "Content-Type: application/json" \
        -d "{
            \"displayName\": \"${display_name}\",
            ${channel_ref}
            \"conditions\": [{
                \"displayName\": \"${display_name} condition\",
                \"conditionThreshold\": {
                    \"filter\": \"${filter}\",
                    \"comparison\": \"${comparison}\",
                    \"thresholdValue\": ${threshold},
                    \"duration\": \"${duration}\",
                    \"aggregations\": [{
                        \"alignmentPeriod\": \"60s\",
                        \"perSeriesAligner\": \"ALIGN_RATE\"
                    }]
                }
            }],
            \"combiner\": \"OR\",
            \"enabled\": true
        }" >/dev/null 2>&1 && ok "Alert policy '${display_name}' created" || warn "Could not create alert '${display_name}'"
}

create_alert_policy \
    "ShieldOps - High CPU (GKE)" \
    "resource.type = \"k8s_container\" AND metric.type = \"kubernetes.io/container/cpu/core_usage_time\"" \
    0.8 "COMPARISON_GT" "300s"

create_alert_policy \
    "ShieldOps - High Memory (GKE)" \
    "resource.type = \"k8s_container\" AND metric.type = \"kubernetes.io/container/memory/used_bytes\"" \
    3221225472 "COMPARISON_GT" "300s"

create_alert_policy \
    "ShieldOps - Cloud SQL High CPU" \
    "resource.type = \"cloudsql_database\" AND metric.type = \"cloudsql.googleapis.com/database/cpu/utilization\"" \
    0.85 "COMPARISON_GT" "300s"

create_alert_policy \
    "ShieldOps - Redis High Memory" \
    "resource.type = \"redis_instance\" AND metric.type = \"redis.googleapis.com/stats/memory/usage_ratio\"" \
    0.85 "COMPARISON_GT" "300s"

create_alert_policy \
    "ShieldOps - 5xx Error Rate" \
    "resource.type = \"https_lb_rule\" AND metric.type = \"loadbalancing.googleapis.com/https/request_count\" AND metric.labels.response_code_class = \"500\"" \
    5 "COMPARISON_GT" "60s"

# Dashboard
DASHBOARD_EXISTS=$(gcloud monitoring dashboards list \
    --project="${PROJECT_ID}" \
    --filter="displayName='${DASHBOARD_NAME}'" \
    --format="value(name)" 2>/dev/null | head -1)

if [[ -z "${DASHBOARD_EXISTS}" ]]; then
    gcloud monitoring dashboards create \
        --project="${PROJECT_ID}" \
        --config-from-file=/dev/stdin --quiet <<'DASHBOARD' 2>/dev/null || warn "Dashboard creation requires manual setup"
{
  "displayName": "ShieldOps Production",
  "gridLayout": {
    "columns": 3,
    "widgets": [
      {
        "title": "GKE CPU Usage",
        "xyChart": {
          "dataSets": [{
            "timeSeriesQuery": {
              "timeSeriesFilter": {
                "filter": "resource.type = \"k8s_container\" AND metric.type = \"kubernetes.io/container/cpu/core_usage_time\"",
                "aggregation": {"alignmentPeriod": "60s", "perSeriesAligner": "ALIGN_RATE"}
              }
            }
          }]
        }
      },
      {
        "title": "GKE Memory Usage",
        "xyChart": {
          "dataSets": [{
            "timeSeriesQuery": {
              "timeSeriesFilter": {
                "filter": "resource.type = \"k8s_container\" AND metric.type = \"kubernetes.io/container/memory/used_bytes\"",
                "aggregation": {"alignmentPeriod": "60s", "perSeriesAligner": "ALIGN_MEAN"}
              }
            }
          }]
        }
      },
      {
        "title": "Cloud SQL Connections",
        "xyChart": {
          "dataSets": [{
            "timeSeriesQuery": {
              "timeSeriesFilter": {
                "filter": "resource.type = \"cloudsql_database\" AND metric.type = \"cloudsql.googleapis.com/database/network/connections\"",
                "aggregation": {"alignmentPeriod": "60s", "perSeriesAligner": "ALIGN_MEAN"}
              }
            }
          }]
        }
      },
      {
        "title": "Redis Memory Usage",
        "xyChart": {
          "dataSets": [{
            "timeSeriesQuery": {
              "timeSeriesFilter": {
                "filter": "resource.type = \"redis_instance\" AND metric.type = \"redis.googleapis.com/stats/memory/usage_ratio\"",
                "aggregation": {"alignmentPeriod": "60s", "perSeriesAligner": "ALIGN_MEAN"}
              }
            }
          }]
        }
      },
      {
        "title": "LB Request Count",
        "xyChart": {
          "dataSets": [{
            "timeSeriesQuery": {
              "timeSeriesFilter": {
                "filter": "resource.type = \"https_lb_rule\" AND metric.type = \"loadbalancing.googleapis.com/https/request_count\"",
                "aggregation": {"alignmentPeriod": "60s", "perSeriesAligner": "ALIGN_RATE"}
              }
            }
          }]
        }
      },
      {
        "title": "LB Latency (p99)",
        "xyChart": {
          "dataSets": [{
            "timeSeriesQuery": {
              "timeSeriesFilter": {
                "filter": "resource.type = \"https_lb_rule\" AND metric.type = \"loadbalancing.googleapis.com/https/total_latencies\"",
                "aggregation": {"alignmentPeriod": "60s", "perSeriesAligner": "ALIGN_PERCENTILE_99"}
              }
            }
          }]
        }
      }
    ]
  }
}
DASHBOARD
    ok "Monitoring dashboard created"
else
    ok "Monitoring dashboard already exists"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
log "=========================================="
log "  ShieldOps GCP Deployment Complete"
log "=========================================="
echo ""
echo "  Project:      ${PROJECT_ID}"
echo "  Region:       ${REGION}"
echo "  GKE Cluster:  ${GKE_CLUSTER}"
echo "  Cloud SQL:    ${SQL_INSTANCE}"
echo "  Redis:        ${REDIS_INSTANCE}"
echo "  Registry:     ${REGION}-docker.pkg.dev/${PROJECT_ID}/${AR_REPO}"
echo "  Load Balancer: ${LB_IP}"
echo "  Domain:       ${DOMAIN}"
echo ""
log "Next steps:"
echo "  1. Update DNS NS records at your registrar (see: gcloud dns managed-zones describe ${DNS_ZONE})"
echo "  2. Update Secret Manager values: gcloud secrets versions add <secret-name> --data-file=<file>"
echo "  3. Push container image: docker push ${REGION}-docker.pkg.dev/${PROJECT_ID}/${AR_REPO}/shieldops:latest"
echo "  4. Apply Kubernetes manifests: kubectl apply -f infrastructure/kubernetes/"
echo ""
