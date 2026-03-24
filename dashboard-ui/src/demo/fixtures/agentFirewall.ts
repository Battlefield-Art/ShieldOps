/** Agent Firewall demo fixtures. */

import { recentTimestamp } from "../config";

// ---------------------------------------------------------------------------
// Firewall Agents (8 agents with circuit breaker states)
// ---------------------------------------------------------------------------

export const DEMO_FIREWALL_AGENTS = [
  { id: "fw-agent-001", name: "order-service-agent", app: "order-service", status: "active" as const, circuitBreaker: "closed" as const, interceptedCalls: 12_450, blockedCalls: 23, lastSeen: recentTimestamp(10) },
  { id: "fw-agent-002", name: "payment-agent", app: "payment-service", status: "active" as const, circuitBreaker: "closed" as const, interceptedCalls: 8_320, blockedCalls: 7, lastSeen: recentTimestamp(5) },
  { id: "fw-agent-003", name: "search-agent", app: "search-service", status: "active" as const, circuitBreaker: "closed" as const, interceptedCalls: 34_100, blockedCalls: 112, lastSeen: recentTimestamp(3) },
  { id: "fw-agent-004", name: "deploy-bot", app: "ci-cd-pipeline", status: "active" as const, circuitBreaker: "half-open" as const, interceptedCalls: 5_620, blockedCalls: 89, lastSeen: recentTimestamp(45) },
  { id: "fw-agent-005", name: "data-pipeline-agent", app: "etl-service", status: "active" as const, circuitBreaker: "closed" as const, interceptedCalls: 21_000, blockedCalls: 15, lastSeen: recentTimestamp(8) },
  { id: "fw-agent-006", name: "customer-support-bot", app: "support-portal", status: "active" as const, circuitBreaker: "closed" as const, interceptedCalls: 45_600, blockedCalls: 201, lastSeen: recentTimestamp(2) },
  { id: "fw-agent-007", name: "legacy-cron-agent", app: "batch-jobs", status: "degraded" as const, circuitBreaker: "open" as const, interceptedCalls: 1_230, blockedCalls: 340, lastSeen: recentTimestamp(600) },
  { id: "fw-agent-008", name: "monitoring-agent", app: "observability", status: "active" as const, circuitBreaker: "closed" as const, interceptedCalls: 67_800, blockedCalls: 4, lastSeen: recentTimestamp(1) },
];

// ---------------------------------------------------------------------------
// Anomaly Events (15 events)
// ---------------------------------------------------------------------------

export const DEMO_FIREWALL_ANOMALIES = [
  { id: "anom-001", agentId: "fw-agent-003", type: "prompt-injection" as const, severity: "critical" as const, description: "Detected prompt injection attempt in search query input", timestamp: recentTimestamp(120), blocked: true },
  { id: "anom-002", agentId: "fw-agent-007", type: "excessive-calls" as const, severity: "high" as const, description: "Agent exceeded 500 calls/min rate limit", timestamp: recentTimestamp(300), blocked: true },
  { id: "anom-003", agentId: "fw-agent-004", type: "unauthorized-tool" as const, severity: "high" as const, description: "Agent attempted to call kubectl delete without approval", timestamp: recentTimestamp(600), blocked: true },
  { id: "anom-004", agentId: "fw-agent-006", type: "data-exfiltration" as const, severity: "critical" as const, description: "PII detected in outbound API call payload", timestamp: recentTimestamp(900), blocked: true },
  { id: "anom-005", agentId: "fw-agent-002", type: "scope-escalation" as const, severity: "medium" as const, description: "Agent requested access to production database outside defined scope", timestamp: recentTimestamp(1200), blocked: false },
  { id: "anom-006", agentId: "fw-agent-001", type: "prompt-injection" as const, severity: "high" as const, description: "Indirect prompt injection via order notes field", timestamp: recentTimestamp(1800), blocked: true },
  { id: "anom-007", agentId: "fw-agent-003", type: "hallucination" as const, severity: "medium" as const, description: "Agent returned fabricated API endpoint in response", timestamp: recentTimestamp(2400), blocked: false },
  { id: "anom-008", agentId: "fw-agent-005", type: "excessive-calls" as const, severity: "low" as const, description: "Burst of 200 calls in 10 seconds during batch processing", timestamp: recentTimestamp(3000), blocked: false },
  { id: "anom-009", agentId: "fw-agent-007", type: "unauthorized-tool" as const, severity: "critical" as const, description: "Agent attempted rm -rf on mounted volume", timestamp: recentTimestamp(3600), blocked: true },
  { id: "anom-010", agentId: "fw-agent-004", type: "scope-escalation" as const, severity: "high" as const, description: "Deployment agent tried to modify IAM roles", timestamp: recentTimestamp(4200), blocked: true },
  { id: "anom-011", agentId: "fw-agent-006", type: "prompt-injection" as const, severity: "medium" as const, description: "Customer input contained encoded instruction override", timestamp: recentTimestamp(5400), blocked: true },
  { id: "anom-012", agentId: "fw-agent-008", type: "hallucination" as const, severity: "low" as const, description: "Monitoring agent reported non-existent service as degraded", timestamp: recentTimestamp(7200), blocked: false },
  { id: "anom-013", agentId: "fw-agent-002", type: "data-exfiltration" as const, severity: "high" as const, description: "Credit card number detected in LLM context window", timestamp: recentTimestamp(9000), blocked: true },
  { id: "anom-014", agentId: "fw-agent-001", type: "excessive-calls" as const, severity: "medium" as const, description: "Retry loop detected: 50 identical calls in 30 seconds", timestamp: recentTimestamp(10800), blocked: true },
  { id: "anom-015", agentId: "fw-agent-005", type: "unauthorized-tool" as const, severity: "high" as const, description: "ETL agent attempted to write to audit log table directly", timestamp: recentTimestamp(14400), blocked: true },
];

// ---------------------------------------------------------------------------
// Policies (8 policies)
// ---------------------------------------------------------------------------

export const DEMO_FIREWALL_POLICIES = [
  { id: "pol-001", name: "Block Prompt Injection", type: "input-validation" as const, status: "active" as const, agentsApplied: 8, lastTriggered: recentTimestamp(120), description: "Detect and block prompt injection patterns in agent inputs" },
  { id: "pol-002", name: "Rate Limit (500/min)", type: "rate-limit" as const, status: "active" as const, agentsApplied: 8, lastTriggered: recentTimestamp(300), description: "Enforce maximum 500 calls per minute per agent" },
  { id: "pol-003", name: "PII Egress Filter", type: "data-protection" as const, status: "active" as const, agentsApplied: 6, lastTriggered: recentTimestamp(900), description: "Block outbound calls containing PII (SSN, CC, email)" },
  { id: "pol-004", name: "Tool Allowlist", type: "authorization" as const, status: "active" as const, agentsApplied: 8, lastTriggered: recentTimestamp(600), description: "Only allow pre-approved tool calls per agent role" },
  { id: "pol-005", name: "Scope Boundary", type: "authorization" as const, status: "active" as const, agentsApplied: 5, lastTriggered: recentTimestamp(1200), description: "Prevent agents from accessing resources outside their scope" },
  { id: "pol-006", name: "Destructive Op Gate", type: "safety" as const, status: "active" as const, agentsApplied: 4, lastTriggered: recentTimestamp(3600), description: "Require human approval for delete/drop/terminate operations" },
  { id: "pol-007", name: "Hallucination Guard", type: "output-validation" as const, status: "active" as const, agentsApplied: 3, lastTriggered: recentTimestamp(2400), description: "Validate agent outputs against known-good schemas" },
  { id: "pol-008", name: "After-Hours Lockdown", type: "temporal" as const, status: "inactive" as const, agentsApplied: 0, lastTriggered: null, description: "Restrict enforce-mode actions outside business hours" },
];

// ---------------------------------------------------------------------------
// Audit Log (25 entries)
// ---------------------------------------------------------------------------

export const DEMO_FIREWALL_AUDIT_LOG = Array.from({ length: 25 }, (_, i) => ({
  id: `audit-fw-${String(i + 1).padStart(3, "0")}`,
  timestamp: recentTimestamp(i * 420),
  agentId: DEMO_FIREWALL_AGENTS[i % 8].id,
  agentName: DEMO_FIREWALL_AGENTS[i % 8].name,
  action: (["tool_call", "api_request", "data_access", "config_change", "escalation"] as const)[i % 5],
  tool: ["kubectl.get_pods", "pg.query", "s3.put_object", "slack.post_message", "http.request", "redis.get", "vault.read_secret"][i % 7],
  decision: i % 4 === 0 ? ("blocked" as const) : ("allowed" as const),
  policyId: i % 4 === 0 ? DEMO_FIREWALL_POLICIES[i % 8].id : null,
  latencyMs: Math.round(2 + Math.random() * 18),
  metadata: { ip: `10.0.${Math.floor(i / 5)}.${(i * 7) % 256}`, region: (["us-east-1", "eu-west-1", "ap-southeast-1"] as const)[i % 3] },
}));

// ---------------------------------------------------------------------------
// Summary Metrics
// ---------------------------------------------------------------------------

export const DEMO_FIREWALL_METRICS = {
  totalInterceptedCalls: 195_120,
  totalBlockedCalls: 791,
  blockRate: 0.41,
  activeAgents: 7,
  degradedAgents: 1,
  activePolicies: 7,
  avgLatencyMs: 8.3,
  topAnomalyType: "prompt-injection" as const,
  callsTrend: [12_400, 13_100, 11_800, 14_200, 15_600, 13_900, 14_800],
  blockedTrend: [45, 67, 52, 89, 112, 78, 95],
};
