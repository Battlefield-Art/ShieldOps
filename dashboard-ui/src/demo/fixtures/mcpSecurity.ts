/** MCP (Model Context Protocol) Security demo fixtures. */

import { recentTimestamp } from "../config";

// ---------------------------------------------------------------------------
// MCP Servers (12 servers)
// ---------------------------------------------------------------------------

export const DEMO_MCP_SERVERS = [
  { id: "mcp-001", name: "filesystem-server", version: "1.2.0", status: "healthy" as const, tools: 8, lastScan: recentTimestamp(600), vulnerabilities: 0, trustScore: 95, endpoint: "stdio://mcp-filesystem", owner: "platform-team" },
  { id: "mcp-002", name: "postgres-server", version: "0.9.3", status: "healthy" as const, tools: 12, lastScan: recentTimestamp(900), vulnerabilities: 1, trustScore: 82, endpoint: "stdio://mcp-postgres", owner: "data-team" },
  { id: "mcp-003", name: "github-server", version: "1.0.1", status: "healthy" as const, tools: 15, lastScan: recentTimestamp(300), vulnerabilities: 0, trustScore: 91, endpoint: "sse://github-mcp.internal:8080", owner: "devops-team" },
  { id: "mcp-004", name: "slack-server", version: "0.8.0", status: "healthy" as const, tools: 6, lastScan: recentTimestamp(1200), vulnerabilities: 0, trustScore: 88, endpoint: "stdio://mcp-slack", owner: "sre-team" },
  { id: "mcp-005", name: "kubernetes-server", version: "1.1.0", status: "healthy" as const, tools: 20, lastScan: recentTimestamp(180), vulnerabilities: 2, trustScore: 76, endpoint: "sse://k8s-mcp.internal:8080", owner: "platform-team" },
  { id: "mcp-006", name: "aws-server", version: "0.7.2", status: "degraded" as const, tools: 25, lastScan: recentTimestamp(3600), vulnerabilities: 3, trustScore: 64, endpoint: "sse://aws-mcp.internal:8080", owner: "infra-team" },
  { id: "mcp-007", name: "jira-server", version: "1.0.0", status: "healthy" as const, tools: 9, lastScan: recentTimestamp(1800), vulnerabilities: 0, trustScore: 90, endpoint: "stdio://mcp-jira", owner: "engineering-team" },
  { id: "mcp-008", name: "browserbase-server", version: "0.5.1", status: "healthy" as const, tools: 4, lastScan: recentTimestamp(2400), vulnerabilities: 1, trustScore: 78, endpoint: "sse://browser-mcp.internal:8080", owner: "qa-team" },
  { id: "mcp-009", name: "memory-server", version: "0.6.0", status: "healthy" as const, tools: 5, lastScan: recentTimestamp(600), vulnerabilities: 0, trustScore: 93, endpoint: "stdio://mcp-memory", owner: "ml-team" },
  { id: "mcp-010", name: "puppeteer-server", version: "0.4.2", status: "unhealthy" as const, tools: 7, lastScan: recentTimestamp(7200), vulnerabilities: 4, trustScore: 45, endpoint: "sse://puppeteer-mcp.internal:8080", owner: "qa-team" },
  { id: "mcp-011", name: "elasticsearch-server", version: "0.9.0", status: "healthy" as const, tools: 10, lastScan: recentTimestamp(900), vulnerabilities: 0, trustScore: 87, endpoint: "stdio://mcp-elasticsearch", owner: "observability-team" },
  { id: "mcp-012", name: "custom-internal-server", version: "0.2.0-alpha", status: "degraded" as const, tools: 3, lastScan: recentTimestamp(14400), vulnerabilities: 2, trustScore: 52, endpoint: "sse://custom-mcp.internal:9090", owner: "research-team" },
];

// ---------------------------------------------------------------------------
// God Keys / Overprivileged Risks (3 risks)
// ---------------------------------------------------------------------------

export const DEMO_GOD_KEYS = [
  {
    id: "gk-001",
    serverId: "mcp-005",
    serverName: "kubernetes-server",
    risk: "Cluster-admin equivalent access via MCP tools",
    severity: "critical" as const,
    tools: ["kubectl_apply", "kubectl_delete", "kubectl_exec", "kubectl_patch"],
    recommendation: "Implement least-privilege tool scoping. Restrict kubectl_delete and kubectl_exec to namespaced operations only.",
    detectedAt: recentTimestamp(1800),
  },
  {
    id: "gk-002",
    serverId: "mcp-006",
    serverName: "aws-server",
    risk: "IAM:* permissions exposed through MCP tools",
    severity: "critical" as const,
    tools: ["iam_create_role", "iam_attach_policy", "iam_create_user", "s3_delete_bucket"],
    recommendation: "Remove IAM write permissions from MCP server. Use separate approval workflow for IAM changes.",
    detectedAt: recentTimestamp(3600),
  },
  {
    id: "gk-003",
    serverId: "mcp-002",
    serverName: "postgres-server",
    risk: "Superuser database access without query restrictions",
    severity: "high" as const,
    tools: ["execute_sql", "create_table", "drop_table", "alter_schema"],
    recommendation: "Downgrade to read-only role for query tools. Gate DDL operations behind approval.",
    detectedAt: recentTimestamp(7200),
  },
];

// ---------------------------------------------------------------------------
// Supply Chain Vulnerabilities (8 vulns)
// ---------------------------------------------------------------------------

export const DEMO_SUPPLY_CHAIN = [
  { id: "sc-001", serverId: "mcp-010", package: "@anthropic/mcp-puppeteer", version: "0.4.2", cve: "CVE-2025-1234", severity: "critical" as const, description: "Remote code execution via crafted browser navigation URL", fixVersion: "0.5.0", status: "unpatched" as const },
  { id: "sc-002", serverId: "mcp-006", package: "aws-sdk-mcp", version: "0.7.2", cve: "CVE-2025-2345", severity: "high" as const, description: "SSRF vulnerability in presigned URL generation", fixVersion: "0.7.3", status: "patch-available" as const },
  { id: "sc-003", serverId: "mcp-005", package: "kubernetes-mcp", version: "1.1.0", cve: "CVE-2025-3456", severity: "medium" as const, description: "Information disclosure in error messages leaking namespace secrets", fixVersion: "1.1.1", status: "patch-available" as const },
  { id: "sc-004", serverId: "mcp-012", package: "custom-mcp-core", version: "0.2.0-alpha", cve: null, severity: "high" as const, description: "No input sanitization on tool parameters (internal audit)", fixVersion: null, status: "investigating" as const },
  { id: "sc-005", serverId: "mcp-010", package: "chromium-launcher", version: "115.0.0", cve: "CVE-2025-4567", severity: "critical" as const, description: "Sandbox escape via malicious page content", fixVersion: "116.0.0", status: "unpatched" as const },
  { id: "sc-006", serverId: "mcp-008", package: "browserbase-sdk", version: "0.5.1", cve: "CVE-2025-5678", severity: "medium" as const, description: "Cross-site request forgery in session management", fixVersion: "0.5.2", status: "patch-available" as const },
  { id: "sc-007", serverId: "mcp-006", package: "boto3-wrapper", version: "1.28.0", cve: "CVE-2025-6789", severity: "low" as const, description: "Verbose error logging may expose temporary credentials", fixVersion: "1.28.1", status: "patch-available" as const },
  { id: "sc-008", serverId: "mcp-012", package: "custom-mcp-auth", version: "0.1.0", cve: null, severity: "critical" as const, description: "Hardcoded signing key in authentication module (internal audit)", fixVersion: null, status: "investigating" as const },
];

// ---------------------------------------------------------------------------
// Zero Trust Compliance Records (12 records)
// ---------------------------------------------------------------------------

export const DEMO_ZERO_TRUST = [
  { id: "zt-001", control: "Mutual TLS between agent and MCP server", status: "compliant" as const, serverId: "mcp-001", lastChecked: recentTimestamp(600) },
  { id: "zt-002", control: "Mutual TLS between agent and MCP server", status: "compliant" as const, serverId: "mcp-003", lastChecked: recentTimestamp(600) },
  { id: "zt-003", control: "Mutual TLS between agent and MCP server", status: "non-compliant" as const, serverId: "mcp-012", lastChecked: recentTimestamp(600) },
  { id: "zt-004", control: "Tool-level RBAC enforcement", status: "compliant" as const, serverId: "mcp-001", lastChecked: recentTimestamp(900) },
  { id: "zt-005", control: "Tool-level RBAC enforcement", status: "partial" as const, serverId: "mcp-005", lastChecked: recentTimestamp(900) },
  { id: "zt-006", control: "Tool-level RBAC enforcement", status: "non-compliant" as const, serverId: "mcp-006", lastChecked: recentTimestamp(900) },
  { id: "zt-007", control: "Request signing and verification", status: "compliant" as const, serverId: "mcp-001", lastChecked: recentTimestamp(1200) },
  { id: "zt-008", control: "Request signing and verification", status: "compliant" as const, serverId: "mcp-009", lastChecked: recentTimestamp(1200) },
  { id: "zt-009", control: "Request signing and verification", status: "non-compliant" as const, serverId: "mcp-010", lastChecked: recentTimestamp(1200) },
  { id: "zt-010", control: "Ephemeral credentials (no long-lived tokens)", status: "compliant" as const, serverId: "mcp-009", lastChecked: recentTimestamp(1800) },
  { id: "zt-011", control: "Ephemeral credentials (no long-lived tokens)", status: "non-compliant" as const, serverId: "mcp-006", lastChecked: recentTimestamp(1800) },
  { id: "zt-012", control: "Audit logging for all tool invocations", status: "compliant" as const, serverId: "mcp-001", lastChecked: recentTimestamp(300) },
];

// ---------------------------------------------------------------------------
// Summary Metrics
// ---------------------------------------------------------------------------

export const DEMO_MCP_METRICS = {
  totalServers: 12,
  healthyServers: 8,
  degradedServers: 2,
  unhealthyServers: 1,
  totalTools: 124,
  totalVulnerabilities: 11,
  criticalVulns: 4,
  godKeyRisks: 3,
  avgTrustScore: 78.4,
  zeroTrustCompliance: 0.58,
  topRiskServer: "puppeteer-server",
};
