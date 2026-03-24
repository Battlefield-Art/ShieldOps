/** NHI (Non-Human Identity) Registry demo fixtures. */

import { recentTimestamp, pastDate } from "../config";

// ---------------------------------------------------------------------------
// NHI Identities (25 identities)
// ---------------------------------------------------------------------------

export const DEMO_NHI_IDENTITIES = [
  { id: "nhi-001", name: "github-actions-deployer", type: "service-account" as const, provider: "github" as const, environment: "production", permissions: ["repo:write", "packages:write", "deployments:write"], riskScore: 72, lastUsed: recentTimestamp(60), createdAt: pastDate(180), owner: "platform-team", hasRotationPolicy: true, rotationDays: 90, credentialAge: 45 },
  { id: "nhi-002", name: "terraform-cloud-sa", type: "service-account" as const, provider: "aws" as const, environment: "production", permissions: ["iam:*", "ec2:*", "s3:*", "rds:*"], riskScore: 95, lastUsed: recentTimestamp(300), createdAt: pastDate(365), owner: "infra-team", hasRotationPolicy: true, rotationDays: 30, credentialAge: 28 },
  { id: "nhi-003", name: "datadog-integration", type: "api-key" as const, provider: "datadog" as const, environment: "production", permissions: ["metrics:read", "logs:read", "traces:read"], riskScore: 35, lastUsed: recentTimestamp(5), createdAt: pastDate(120), owner: "observability-team", hasRotationPolicy: false, rotationDays: null, credentialAge: 120 },
  { id: "nhi-004", name: "slack-bot-shieldops", type: "bot-token" as const, provider: "slack" as const, environment: "production", permissions: ["chat:write", "channels:read", "files:write"], riskScore: 42, lastUsed: recentTimestamp(30), createdAt: pastDate(90), owner: "sre-team", hasRotationPolicy: false, rotationDays: null, credentialAge: 90 },
  { id: "nhi-005", name: "k8s-cluster-admin", type: "service-account" as const, provider: "kubernetes" as const, environment: "production", permissions: ["cluster-admin"], riskScore: 98, lastUsed: recentTimestamp(120), createdAt: pastDate(200), owner: "platform-team", hasRotationPolicy: true, rotationDays: 14, credentialAge: 12 },
  { id: "nhi-006", name: "ci-runner-gcp", type: "service-account" as const, provider: "gcp" as const, environment: "staging", permissions: ["compute.admin", "storage.admin"], riskScore: 78, lastUsed: recentTimestamp(600), createdAt: pastDate(150), owner: "devops-team", hasRotationPolicy: true, rotationDays: 60, credentialAge: 55 },
  { id: "nhi-007", name: "stripe-webhook-signer", type: "api-key" as const, provider: "stripe" as const, environment: "production", permissions: ["webhooks:write"], riskScore: 28, lastUsed: recentTimestamp(10), createdAt: pastDate(60), owner: "billing-team", hasRotationPolicy: true, rotationDays: 90, credentialAge: 58 },
  { id: "nhi-008", name: "azure-devops-pipeline", type: "service-principal" as const, provider: "azure" as const, environment: "production", permissions: ["Contributor", "KeyVaultSecretsUser"], riskScore: 82, lastUsed: recentTimestamp(900), createdAt: pastDate(220), owner: "platform-team", hasRotationPolicy: true, rotationDays: 30, credentialAge: 29 },
  { id: "nhi-009", name: "vault-approle-backend", type: "service-account" as const, provider: "vault" as const, environment: "production", permissions: ["secret/*:read", "auth/*:write"], riskScore: 91, lastUsed: recentTimestamp(15), createdAt: pastDate(300), owner: "security-team", hasRotationPolicy: true, rotationDays: 7, credentialAge: 5 },
  { id: "nhi-010", name: "pagerduty-integration", type: "api-key" as const, provider: "pagerduty" as const, environment: "production", permissions: ["incidents:write", "services:read"], riskScore: 38, lastUsed: recentTimestamp(1800), createdAt: pastDate(95), owner: "sre-team", hasRotationPolicy: false, rotationDays: null, credentialAge: 95 },
  { id: "nhi-011", name: "sentry-dsn-backend", type: "api-key" as const, provider: "sentry" as const, environment: "production", permissions: ["events:write"], riskScore: 22, lastUsed: recentTimestamp(2), createdAt: pastDate(80), owner: "backend-team", hasRotationPolicy: false, rotationDays: null, credentialAge: 80 },
  { id: "nhi-012", name: "argocd-admin", type: "service-account" as const, provider: "kubernetes" as const, environment: "production", permissions: ["applications:*", "clusters:*"], riskScore: 88, lastUsed: recentTimestamp(180), createdAt: pastDate(110), owner: "platform-team", hasRotationPolicy: true, rotationDays: 30, credentialAge: 22 },
  { id: "nhi-013", name: "circleci-deploy-key", type: "ssh-key" as const, provider: "circleci" as const, environment: "staging", permissions: ["repo:read", "repo:write"], riskScore: 65, lastUsed: recentTimestamp(3600), createdAt: pastDate(200), owner: "devops-team", hasRotationPolicy: false, rotationDays: null, credentialAge: 200 },
  { id: "nhi-014", name: "grafana-datasource", type: "api-key" as const, provider: "grafana" as const, environment: "production", permissions: ["datasources:read", "dashboards:read"], riskScore: 18, lastUsed: recentTimestamp(8), createdAt: pastDate(45), owner: "observability-team", hasRotationPolicy: false, rotationDays: null, credentialAge: 45 },
  { id: "nhi-015", name: "aws-lambda-exec-role", type: "iam-role" as const, provider: "aws" as const, environment: "production", permissions: ["s3:GetObject", "dynamodb:Query", "logs:PutLogEvents"], riskScore: 45, lastUsed: recentTimestamp(20), createdAt: pastDate(160), owner: "backend-team", hasRotationPolicy: true, rotationDays: 365, credentialAge: 160 },
  { id: "nhi-016", name: "redis-auth-token", type: "api-key" as const, provider: "redis" as const, environment: "production", permissions: ["all-commands"], riskScore: 55, lastUsed: recentTimestamp(1), createdAt: pastDate(30), owner: "backend-team", hasRotationPolicy: true, rotationDays: 30, credentialAge: 30 },
  { id: "nhi-017", name: "confluence-bot", type: "api-key" as const, provider: "atlassian" as const, environment: "production", permissions: ["space:read", "page:write"], riskScore: 25, lastUsed: recentTimestamp(7200), createdAt: pastDate(140), owner: "engineering-team", hasRotationPolicy: false, rotationDays: null, credentialAge: 140 },
  { id: "nhi-018", name: "snyk-scanner", type: "api-key" as const, provider: "snyk" as const, environment: "production", permissions: ["test:read", "projects:read"], riskScore: 20, lastUsed: recentTimestamp(1800), createdAt: pastDate(100), owner: "security-team", hasRotationPolicy: false, rotationDays: null, credentialAge: 100 },
  { id: "nhi-019", name: "gcp-pubsub-publisher", type: "service-account" as const, provider: "gcp" as const, environment: "production", permissions: ["pubsub.publisher"], riskScore: 40, lastUsed: recentTimestamp(30), createdAt: pastDate(85), owner: "data-team", hasRotationPolicy: true, rotationDays: 90, credentialAge: 70 },
  { id: "nhi-020", name: "docker-registry-sa", type: "service-account" as const, provider: "gcp" as const, environment: "staging", permissions: ["storage.objectViewer", "artifactregistry.reader"], riskScore: 32, lastUsed: recentTimestamp(600), createdAt: pastDate(170), owner: "devops-team", hasRotationPolicy: true, rotationDays: 60, credentialAge: 48 },
  { id: "nhi-021", name: "openai-api-backend", type: "api-key" as const, provider: "openai" as const, environment: "production", permissions: ["models:read", "completions:write"], riskScore: 68, lastUsed: recentTimestamp(3), createdAt: pastDate(60), owner: "ml-team", hasRotationPolicy: true, rotationDays: 30, credentialAge: 25 },
  { id: "nhi-022", name: "anthropic-api-agents", type: "api-key" as const, provider: "anthropic" as const, environment: "production", permissions: ["messages:write"], riskScore: 70, lastUsed: recentTimestamp(1), createdAt: pastDate(45), owner: "ml-team", hasRotationPolicy: true, rotationDays: 30, credentialAge: 20 },
  { id: "nhi-023", name: "postgres-replication", type: "db-credential" as const, provider: "aws" as const, environment: "production", permissions: ["rds:connect", "replication"], riskScore: 85, lastUsed: recentTimestamp(5), createdAt: pastDate(250), owner: "dba-team", hasRotationPolicy: true, rotationDays: 14, credentialAge: 10 },
  { id: "nhi-024", name: "cloudflare-dns-token", type: "api-key" as const, provider: "cloudflare" as const, environment: "production", permissions: ["dns:edit", "zone:read"], riskScore: 60, lastUsed: recentTimestamp(86400), createdAt: pastDate(130), owner: "infra-team", hasRotationPolicy: false, rotationDays: null, credentialAge: 130 },
  { id: "nhi-025", name: "jenkins-deploy-user", type: "service-account" as const, provider: "jenkins" as const, environment: "staging", permissions: ["job:build", "credentials:read"], riskScore: 75, lastUsed: recentTimestamp(14400), createdAt: pastDate(400), owner: "legacy-team", hasRotationPolicy: false, rotationDays: null, credentialAge: 400 },
];

// ---------------------------------------------------------------------------
// Shadow AI Detections (3 detections)
// ---------------------------------------------------------------------------

export const DEMO_SHADOW_AI = [
  {
    id: "shadow-001",
    name: "Unauthorized ChatGPT API usage",
    detectedAt: recentTimestamp(3600),
    source: "network-traffic-analysis",
    endpoint: "api.openai.com",
    callingService: "marketing-analytics",
    estimatedCalls: 2_340,
    riskLevel: "high" as const,
    status: "investigating" as const,
    description: "Marketing analytics service making direct calls to OpenAI API bypassing the approved AI gateway. No security policies applied.",
  },
  {
    id: "shadow-002",
    name: "Unregistered Hugging Face model endpoint",
    detectedAt: recentTimestamp(86400),
    source: "dns-monitoring",
    endpoint: "api-inference.huggingface.co",
    callingService: "research-notebooks",
    estimatedCalls: 890,
    riskLevel: "medium" as const,
    status: "confirmed" as const,
    description: "Research team running inference against Hugging Face models without going through NHI registry or security review.",
  },
  {
    id: "shadow-003",
    name: "Rogue LangChain agent in staging",
    detectedAt: recentTimestamp(172800),
    source: "container-scan",
    endpoint: "internal",
    callingService: "staging-experiments",
    estimatedCalls: 5_100,
    riskLevel: "critical" as const,
    status: "remediated" as const,
    description: "Developer deployed a LangChain agent with unrestricted tool access in staging. Agent had access to production database credentials via shared ConfigMap.",
  },
];

// ---------------------------------------------------------------------------
// Summary Metrics
// ---------------------------------------------------------------------------

export const DEMO_NHI_METRICS = {
  totalIdentities: 25,
  highRisk: 6,
  mediumRisk: 8,
  lowRisk: 11,
  withRotationPolicy: 15,
  overdue: 3,
  shadowAiDetections: 3,
  avgCredentialAgeDays: 98,
  providers: ["aws", "gcp", "azure", "kubernetes", "github", "slack", "vault", "stripe", "datadog", "pagerduty", "openai", "anthropic"],
  riskDistribution: [
    { range: "0-25", count: 4 },
    { range: "26-50", count: 6 },
    { range: "51-75", count: 8 },
    { range: "76-100", count: 7 },
  ],
};
