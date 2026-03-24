/** SOC Brain demo fixtures. */

import { recentTimestamp, pastDate } from "../config";

// ---------------------------------------------------------------------------
// Situations (8 situations)
// ---------------------------------------------------------------------------

export const DEMO_SITUATIONS = [
  { id: "sit-001", title: "Credential stuffing attack on auth-service", severity: "critical" as const, status: "active" as const, createdAt: recentTimestamp(900), updatedAt: recentTimestamp(120), sources: ["CrowdStrike", "Datadog"], evidenceCount: 12, assignee: "soc-agent-001", ttd: 45, description: "Spike of 15k failed logins from 200+ IPs targeting /api/v1/auth/login. Pattern matches known credential stuffing toolkit." },
  { id: "sit-002", title: "Lateral movement detected in staging cluster", severity: "high" as const, status: "investigating" as const, createdAt: recentTimestamp(3600), updatedAt: recentTimestamp(600), sources: ["Defender", "Kubernetes"], evidenceCount: 8, assignee: "soc-agent-002", ttd: 120, description: "Pod-to-pod network traffic from compromised staging-worker-07 to 4 other pods outside normal communication pattern." },
  { id: "sit-003", title: "Data exfiltration attempt via DNS tunneling", severity: "critical" as const, status: "contained" as const, createdAt: recentTimestamp(7200), updatedAt: recentTimestamp(1800), sources: ["CrowdStrike", "Wiz"], evidenceCount: 15, assignee: "soc-agent-001", ttd: 90, description: "Anomalous DNS query volume (50k queries/hr) with high-entropy subdomain names indicating data exfiltration via DNS tunneling." },
  { id: "sit-004", title: "Supply chain compromise in npm dependency", severity: "high" as const, status: "resolved" as const, createdAt: pastDate(2), updatedAt: recentTimestamp(14400), sources: ["Wiz", "Snyk"], evidenceCount: 6, assignee: "soc-agent-003", ttd: 240, description: "Typosquatting package 'lodash-utils-v2' detected in dashboard-ui dependencies. Package contains obfuscated credential harvester." },
  { id: "sit-005", title: "Privileged container escape in production", severity: "critical" as const, status: "active" as const, createdAt: recentTimestamp(1800), updatedAt: recentTimestamp(300), sources: ["Defender", "Kubernetes", "Falco"], evidenceCount: 18, assignee: "soc-agent-001", ttd: 60, description: "Container running as root with hostPID mount attempted nsenter to host namespace. Triggered Falco rule and Microsoft Defender alert." },
  { id: "sit-006", title: "Anomalous IAM role assumption pattern", severity: "medium" as const, status: "investigating" as const, createdAt: recentTimestamp(10800), updatedAt: recentTimestamp(3600), sources: ["CrowdStrike", "CloudTrail"], evidenceCount: 5, assignee: "soc-agent-002", ttd: 300, description: "Service account assuming cross-account IAM role 4x normal frequency. Accessing S3 buckets not in historical baseline." },
  { id: "sit-007", title: "MCP server tool injection detected", severity: "high" as const, status: "contained" as const, createdAt: recentTimestamp(14400), updatedAt: recentTimestamp(7200), sources: ["ShieldOps Firewall", "Agent Logs"], evidenceCount: 9, assignee: "soc-agent-003", ttd: 180, description: "Adversarial prompt injection via MCP tool parameter caused kubernetes-server to execute unintended kubectl exec command." },
  { id: "sit-008", title: "Expired TLS certificate on payment gateway", severity: "low" as const, status: "resolved" as const, createdAt: pastDate(3), updatedAt: pastDate(2), sources: ["Datadog", "PagerDuty"], evidenceCount: 3, assignee: "soc-agent-002", ttd: 30, description: "TLS certificate for payments.example.com expired, causing 502 errors. Auto-renewed via cert-manager within 30 minutes." },
];

// ---------------------------------------------------------------------------
// Evidence Chain (for situation sit-001)
// ---------------------------------------------------------------------------

export const DEMO_EVIDENCE_CHAIN = [
  { id: "ev-001", situationId: "sit-001", type: "alert" as const, source: "CrowdStrike", timestamp: recentTimestamp(900), title: "Brute force detection: 15,247 failed logins in 15 minutes", confidence: 0.96, raw: { rule: "BruteForceAuth", matchCount: 15247, uniqueIPs: 214 } },
  { id: "ev-002", situationId: "sit-001", type: "metric" as const, source: "Datadog", timestamp: recentTimestamp(870), title: "auth-service error rate spike to 94%", confidence: 0.99, raw: { metric: "http.requests.error_rate", value: 0.94, baseline: 0.02 } },
  { id: "ev-003", situationId: "sit-001", type: "log" as const, source: "Splunk", timestamp: recentTimestamp(850), title: "Repeated 401 responses with rotating user-agent strings", confidence: 0.88, raw: { query: "index=auth status=401 | stats count by user_agent", results: 47 } },
  { id: "ev-004", situationId: "sit-001", type: "enrichment" as const, source: "ThreatIntel", timestamp: recentTimestamp(840), title: "73% of source IPs on known botnet blocklist", confidence: 0.92, raw: { matchedIPs: 156, totalIPs: 214, blocklist: "abuse.ch" } },
  { id: "ev-005", situationId: "sit-001", type: "action" as const, source: "ShieldOps", timestamp: recentTimestamp(820), title: "Auto-blocked 214 IPs via WAF rule", confidence: 1.0, raw: { action: "waf_block", ipsBlocked: 214, rule: "auto-credential-stuffing-001" } },
  { id: "ev-006", situationId: "sit-001", type: "action" as const, source: "ShieldOps", timestamp: recentTimestamp(780), title: "Rate limit enforced: 5 req/min per IP on /auth/login", confidence: 1.0, raw: { action: "rate_limit", endpoint: "/api/v1/auth/login", limit: "5/min" } },
];

// ---------------------------------------------------------------------------
// Approval Queue (5 pending approvals)
// ---------------------------------------------------------------------------

export const DEMO_APPROVAL_QUEUE = [
  { id: "appr-001", situationId: "sit-001", action: "Quarantine auth-service pod auth-7b4f9c-2x8kp", severity: "high" as const, requestedAt: recentTimestamp(600), requestedBy: "soc-agent-001", approvers: ["security-lead", "sre-oncall"], status: "pending" as const, expiresAt: recentTimestamp(-1800) },
  { id: "appr-002", situationId: "sit-005", action: "Kill privileged container prod-worker-03-abc", severity: "critical" as const, requestedAt: recentTimestamp(300), requestedBy: "soc-agent-001", approvers: ["security-lead"], status: "pending" as const, expiresAt: recentTimestamp(-900) },
  { id: "appr-003", situationId: "sit-002", action: "Isolate network namespace for staging-worker-07", severity: "high" as const, requestedAt: recentTimestamp(1200), requestedBy: "soc-agent-002", approvers: ["security-lead", "platform-lead"], status: "pending" as const, expiresAt: recentTimestamp(-3600) },
  { id: "appr-004", situationId: "sit-006", action: "Revoke temporary IAM session tokens for cross-account role", severity: "medium" as const, requestedAt: recentTimestamp(3600), requestedBy: "soc-agent-002", approvers: ["iam-admin"], status: "pending" as const, expiresAt: recentTimestamp(-7200) },
  { id: "appr-005", situationId: "sit-001", action: "Enable CAPTCHA challenge on /api/v1/auth/login", severity: "medium" as const, requestedAt: recentTimestamp(480), requestedBy: "soc-agent-001", approvers: ["product-lead"], status: "pending" as const, expiresAt: recentTimestamp(-3600) },
];

// ---------------------------------------------------------------------------
// Summary Metrics
// ---------------------------------------------------------------------------

export const DEMO_SOC_METRICS = {
  activeSituations: 3,
  totalSituations: 8,
  avgTimeToDetect: 133,
  avgTimeToContain: 420,
  evidenceProcessed: 76,
  pendingApprovals: 5,
  resolvedLast7d: 3,
  criticalActive: 2,
  connectedVendors: ["CrowdStrike", "Defender", "Wiz", "Datadog", "Splunk"],
  situationsBySeverity: { critical: 3, high: 3, medium: 1, low: 1 },
};
