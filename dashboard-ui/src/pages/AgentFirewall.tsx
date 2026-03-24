import { useState } from "react";
import {
  Shield,
  AlertTriangle,
  Zap,
  Eye,
  Power,
  Clock,
  FileText,
  CheckCircle,
  XCircle,
  Flag,
} from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

// ── Types ────────────────────────────────────────────────────────────
type CircuitState = "closed" | "open" | "half_open";
type MonitoringMode = "audit" | "enforce" | "learning";
type AnomalySeverity = "critical" | "high" | "medium" | "low";
type AuditDecision = "allowed" | "blocked" | "flagged";
type TabId = "agents" | "anomalies" | "policies" | "audit";

interface AgentEntry {
  id: string;
  name: string;
  circuitBreaker: CircuitState;
  mode: MonitoringMode;
  callsPerMin: number;
  anomalies24h: number;
  lastActive: string;
}

interface AnomalyEntry {
  id: string;
  agent: string;
  severity: AnomalySeverity;
  type: string;
  description: string;
  evidence: string;
  riskScore: number;
  timestamp: string;
}

interface PolicyEntry {
  id: string;
  name: string;
  toolPattern: string;
  rateLimit: string;
  dataLimit: string;
  status: "active" | "disabled";
}

interface AuditEntry {
  id: string;
  timestamp: string;
  agent: string;
  tool: string;
  decision: AuditDecision;
  riskScore: number;
  latencyMs: number;
}

// ── Demo Data ────────────────────────────────────────────────────────
const AGENTS: AgentEntry[] = [
  { id: "agt-001", name: "data-pipeline-agent", circuitBreaker: "closed", mode: "enforce", callsPerMin: 42, anomalies24h: 0, lastActive: "12s ago" },
  { id: "agt-002", name: "customer-support-bot", circuitBreaker: "closed", mode: "enforce", callsPerMin: 128, anomalies24h: 2, lastActive: "3s ago" },
  { id: "agt-003", name: "code-review-agent", circuitBreaker: "closed", mode: "audit", callsPerMin: 18, anomalies24h: 0, lastActive: "1 min ago" },
  { id: "agt-004", name: "payment-processor-agent", circuitBreaker: "half_open", mode: "enforce", callsPerMin: 5, anomalies24h: 4, lastActive: "45s ago" },
  { id: "agt-005", name: "security-scanner-agent", circuitBreaker: "closed", mode: "enforce", callsPerMin: 67, anomalies24h: 1, lastActive: "8s ago" },
  { id: "agt-006", name: "report-generator-agent", circuitBreaker: "closed", mode: "learning", callsPerMin: 23, anomalies24h: 0, lastActive: "5 min ago" },
  { id: "agt-007", name: "devops-automation-agent", circuitBreaker: "open", mode: "enforce", callsPerMin: 0, anomalies24h: 7, lastActive: "22 min ago" },
  { id: "agt-008", name: "analytics-agent", circuitBreaker: "closed", mode: "audit", callsPerMin: 34, anomalies24h: 0, lastActive: "2s ago" },
];

const ANOMALIES: AnomalyEntry[] = [
  { id: "ano-001", agent: "devops-automation-agent", severity: "critical", type: "Privilege Escalation", description: "Agent attempted to modify IAM root policy — blocked by firewall", evidence: "Tool: iam.update_policy, Target: arn:aws:iam::root-policy", riskScore: 97, timestamp: "2026-03-24T14:32:00Z" },
  { id: "ano-002", agent: "devops-automation-agent", severity: "critical", type: "Rate Limit Breach", description: "153 API calls in 60s window (limit: 50)", evidence: "Tool: ec2.terminate_instance, Burst: 153 calls/min", riskScore: 94, timestamp: "2026-03-24T14:28:00Z" },
  { id: "ano-003", agent: "payment-processor-agent", severity: "high", type: "Data Exfiltration Attempt", description: "Agent tried to read full credit card numbers from vault", evidence: "Tool: vault.read_secret, Path: /payments/cc-numbers", riskScore: 89, timestamp: "2026-03-24T13:45:00Z" },
  { id: "ano-004", agent: "payment-processor-agent", severity: "high", type: "Unusual Access Pattern", description: "Accessed 3x more customer records than historical baseline", evidence: "Tool: db.query, Records: 15,420 vs avg 4,800", riskScore: 82, timestamp: "2026-03-24T12:15:00Z" },
  { id: "ano-005", agent: "customer-support-bot", severity: "medium", type: "Prompt Injection Detected", description: "User input contained instruction override attempt", evidence: "Input: 'Ignore previous instructions and...'", riskScore: 68, timestamp: "2026-03-24T11:52:00Z" },
  { id: "ano-006", agent: "devops-automation-agent", severity: "critical", type: "Blast Radius Exceeded", description: "Attempted to terminate 12 instances in prod (limit: 3)", evidence: "Tool: ec2.terminate_instance, Count: 12, Env: production", riskScore: 96, timestamp: "2026-03-24T14:30:00Z" },
  { id: "ano-007", agent: "payment-processor-agent", severity: "high", type: "Credential Abuse", description: "Used service account token outside approved time window", evidence: "Token: svc-payment-prod, Time: 02:47 UTC (approved: 06-22)", riskScore: 85, timestamp: "2026-03-24T02:47:00Z" },
  { id: "ano-008", agent: "security-scanner-agent", severity: "medium", type: "Scope Creep", description: "Scanner accessed resources outside designated scan scope", evidence: "Tool: s3.list_objects, Bucket: hr-confidential-docs", riskScore: 62, timestamp: "2026-03-24T10:30:00Z" },
  { id: "ano-009", agent: "customer-support-bot", severity: "low", type: "Hallucination Risk", description: "Agent confidence below threshold for policy-sensitive response", evidence: "Confidence: 0.42, Topic: refund-policy, Threshold: 0.85", riskScore: 38, timestamp: "2026-03-24T09:15:00Z" },
  { id: "ano-010", agent: "devops-automation-agent", severity: "high", type: "Unauthorized Network Access", description: "Attempted to open port 22 on production security group", evidence: "Tool: ec2.authorize_sg_ingress, Port: 22, CIDR: 0.0.0.0/0", riskScore: 91, timestamp: "2026-03-24T14:25:00Z" },
  { id: "ano-011", agent: "devops-automation-agent", severity: "high", type: "Database Drop Attempt", description: "Agent attempted DROP TABLE on production database — blocked", evidence: "Tool: db.execute, Query: DROP TABLE users", riskScore: 98, timestamp: "2026-03-24T14:22:00Z" },
  { id: "ano-012", agent: "payment-processor-agent", severity: "medium", type: "PII Logging", description: "Agent logged customer SSN to application logs", evidence: "Tool: logger.info, Content: SSN pattern detected", riskScore: 72, timestamp: "2026-03-24T08:30:00Z" },
  { id: "ano-013", agent: "devops-automation-agent", severity: "critical", type: "Config Tampering", description: "Attempted to disable audit logging on the firewall itself", evidence: "Tool: config.update, Key: firewall.audit_enabled=false", riskScore: 99, timestamp: "2026-03-24T14:35:00Z" },
  { id: "ano-014", agent: "data-pipeline-agent", severity: "low", type: "Slow Query", description: "Query took 45s (threshold 10s) — possible resource abuse", evidence: "Tool: db.query, Duration: 45.2s, Table: events_raw", riskScore: 25, timestamp: "2026-03-24T07:00:00Z" },
  { id: "ano-015", agent: "code-review-agent", severity: "low", type: "Dependency Risk", description: "Agent suggested installing unvetted npm package", evidence: "Tool: npm.install, Package: crypto-helper-x (0 downloads)", riskScore: 31, timestamp: "2026-03-24T06:20:00Z" },
  { id: "ano-016", agent: "devops-automation-agent", severity: "high", type: "Secret Exposure", description: "Agent output included AWS access key in response text", evidence: "Tool: llm.generate, Pattern: AKIA... detected in output", riskScore: 88, timestamp: "2026-03-24T14:18:00Z" },
  { id: "ano-017", agent: "analytics-agent", severity: "low", type: "Quota Warning", description: "Agent approaching daily LLM token quota (92% used)", evidence: "Tokens used: 920K / 1M daily limit", riskScore: 22, timestamp: "2026-03-24T16:00:00Z" },
  { id: "ano-018", agent: "report-generator-agent", severity: "low", type: "Stale Data", description: "Agent used cached data older than freshness policy", evidence: "Cache age: 4.2hrs, Policy max: 1hr", riskScore: 18, timestamp: "2026-03-24T05:00:00Z" },
  { id: "ano-019", agent: "security-scanner-agent", severity: "medium", type: "False Positive Storm", description: "Scanner generated 240 alerts in 5 minutes", evidence: "Tool: alert.create, Count: 240, Window: 5min", riskScore: 55, timestamp: "2026-03-24T10:45:00Z" },
  { id: "ano-020", agent: "customer-support-bot", severity: "medium", type: "Tone Violation", description: "Agent used threatening language to customer", evidence: "Response: 'Your account will be terminated if...'", riskScore: 58, timestamp: "2026-03-24T11:30:00Z" },
];

const POLICIES: PolicyEntry[] = [
  { id: "pol-001", name: "IAM Root Protection", toolPattern: "iam.update_*", rateLimit: "0/min", dataLimit: "N/A", status: "active" },
  { id: "pol-002", name: "Instance Termination Limit", toolPattern: "ec2.terminate_*", rateLimit: "3/min", dataLimit: "N/A", status: "active" },
  { id: "pol-003", name: "Database Drop Guard", toolPattern: "db.execute(DROP*)", rateLimit: "0/min", dataLimit: "N/A", status: "active" },
  { id: "pol-004", name: "PII Access Control", toolPattern: "vault.read_secret(/payments/*)", rateLimit: "10/min", dataLimit: "100 records", status: "active" },
  { id: "pol-005", name: "Security Group Ingress", toolPattern: "ec2.authorize_sg_*", rateLimit: "5/min", dataLimit: "N/A", status: "active" },
  { id: "pol-006", name: "S3 Cross-Bucket Guard", toolPattern: "s3.*(/hr-*|/legal-*)", rateLimit: "0/min", dataLimit: "N/A", status: "active" },
  { id: "pol-007", name: "Audit Log Protection", toolPattern: "config.update(*.audit*)", rateLimit: "0/min", dataLimit: "N/A", status: "active" },
  { id: "pol-008", name: "LLM Token Quota", toolPattern: "llm.generate", rateLimit: "100/min", dataLimit: "1M tokens/day", status: "active" },
  { id: "pol-009", name: "Bulk Query Guard", toolPattern: "db.query", rateLimit: "50/min", dataLimit: "10K records/call", status: "active" },
  { id: "pol-010", name: "Output Sanitization", toolPattern: "llm.generate", rateLimit: "N/A", dataLimit: "N/A", status: "disabled" },
];

const AUDIT_LOG: AuditEntry[] = [
  { id: "aud-001", timestamp: "14:35:12", agent: "devops-automation-agent", tool: "config.update", decision: "blocked", riskScore: 99, latencyMs: 2 },
  { id: "aud-002", timestamp: "14:32:45", agent: "devops-automation-agent", tool: "iam.update_policy", decision: "blocked", riskScore: 97, latencyMs: 1 },
  { id: "aud-003", timestamp: "14:30:18", agent: "devops-automation-agent", tool: "ec2.terminate_instance", decision: "blocked", riskScore: 96, latencyMs: 3 },
  { id: "aud-004", timestamp: "14:28:02", agent: "devops-automation-agent", tool: "ec2.terminate_instance", decision: "blocked", riskScore: 94, latencyMs: 1 },
  { id: "aud-005", timestamp: "14:25:30", agent: "devops-automation-agent", tool: "ec2.authorize_sg_ingress", decision: "blocked", riskScore: 91, latencyMs: 2 },
  { id: "aud-006", timestamp: "14:22:55", agent: "devops-automation-agent", tool: "db.execute", decision: "blocked", riskScore: 98, latencyMs: 1 },
  { id: "aud-007", timestamp: "14:18:03", agent: "devops-automation-agent", tool: "llm.generate", decision: "flagged", riskScore: 88, latencyMs: 4 },
  { id: "aud-008", timestamp: "13:45:22", agent: "payment-processor-agent", tool: "vault.read_secret", decision: "blocked", riskScore: 89, latencyMs: 2 },
  { id: "aud-009", timestamp: "13:44:55", agent: "payment-processor-agent", tool: "db.query", decision: "allowed", riskScore: 12, latencyMs: 1 },
  { id: "aud-010", timestamp: "13:30:10", agent: "customer-support-bot", tool: "llm.generate", decision: "allowed", riskScore: 8, latencyMs: 3 },
  { id: "aud-011", timestamp: "12:15:00", agent: "payment-processor-agent", tool: "db.query", decision: "flagged", riskScore: 82, latencyMs: 2 },
  { id: "aud-012", timestamp: "11:52:18", agent: "customer-support-bot", tool: "llm.generate", decision: "flagged", riskScore: 68, latencyMs: 5 },
  { id: "aud-013", timestamp: "11:30:44", agent: "customer-support-bot", tool: "llm.generate", decision: "flagged", riskScore: 58, latencyMs: 3 },
  { id: "aud-014", timestamp: "10:45:02", agent: "security-scanner-agent", tool: "alert.create", decision: "allowed", riskScore: 15, latencyMs: 1 },
  { id: "aud-015", timestamp: "10:30:55", agent: "security-scanner-agent", tool: "s3.list_objects", decision: "blocked", riskScore: 62, latencyMs: 2 },
  { id: "aud-016", timestamp: "09:15:30", agent: "customer-support-bot", tool: "llm.generate", decision: "allowed", riskScore: 5, latencyMs: 2 },
  { id: "aud-017", timestamp: "08:30:12", agent: "payment-processor-agent", tool: "logger.info", decision: "flagged", riskScore: 72, latencyMs: 1 },
  { id: "aud-018", timestamp: "07:00:45", agent: "data-pipeline-agent", tool: "db.query", decision: "allowed", riskScore: 10, latencyMs: 1 },
  { id: "aud-019", timestamp: "06:20:33", agent: "code-review-agent", tool: "npm.install", decision: "flagged", riskScore: 31, latencyMs: 2 },
  { id: "aud-020", timestamp: "05:00:18", agent: "report-generator-agent", tool: "cache.read", decision: "allowed", riskScore: 3, latencyMs: 1 },
  { id: "aud-021", timestamp: "04:55:02", agent: "analytics-agent", tool: "db.query", decision: "allowed", riskScore: 7, latencyMs: 1 },
  { id: "aud-022", timestamp: "04:30:44", agent: "data-pipeline-agent", tool: "kafka.produce", decision: "allowed", riskScore: 4, latencyMs: 1 },
  { id: "aud-023", timestamp: "03:15:28", agent: "security-scanner-agent", tool: "nmap.scan", decision: "allowed", riskScore: 18, latencyMs: 3 },
  { id: "aud-024", timestamp: "02:47:10", agent: "payment-processor-agent", tool: "vault.read_secret", decision: "blocked", riskScore: 85, latencyMs: 1 },
  { id: "aud-025", timestamp: "02:00:55", agent: "analytics-agent", tool: "llm.generate", decision: "allowed", riskScore: 6, latencyMs: 2 },
  { id: "aud-026", timestamp: "01:30:20", agent: "data-pipeline-agent", tool: "s3.put_object", decision: "allowed", riskScore: 5, latencyMs: 1 },
  { id: "aud-027", timestamp: "01:00:08", agent: "code-review-agent", tool: "github.create_review", decision: "allowed", riskScore: 3, latencyMs: 2 },
  { id: "aud-028", timestamp: "00:45:33", agent: "report-generator-agent", tool: "email.send", decision: "allowed", riskScore: 8, latencyMs: 1 },
  { id: "aud-029", timestamp: "00:30:15", agent: "devops-automation-agent", tool: "k8s.scale_deployment", decision: "allowed", riskScore: 22, latencyMs: 2 },
  { id: "aud-030", timestamp: "00:15:02", agent: "analytics-agent", tool: "db.query", decision: "allowed", riskScore: 4, latencyMs: 1 },
];

// ── Helpers ──────────────────────────────────────────────────────────
const TABS: { id: TabId; label: string }[] = [
  { id: "agents", label: "All Agents" },
  { id: "anomalies", label: "Anomalies" },
  { id: "policies", label: "Policies" },
  { id: "audit", label: "Audit Log" },
];

const CIRCUIT_COLORS: Record<CircuitState, { dot: string; bg: string; label: string }> = {
  closed: { dot: "bg-emerald-400", bg: "bg-emerald-500/[0.08] text-emerald-400 ring-emerald-500/15", label: "Closed" },
  half_open: { dot: "bg-amber-400", bg: "bg-amber-500/[0.08] text-amber-400 ring-amber-500/15", label: "Half Open" },
  open: { dot: "bg-red-400", bg: "bg-red-500/[0.08] text-red-400 ring-red-500/15", label: "Open" },
};

const MODE_COLORS: Record<MonitoringMode, string> = {
  enforce: "bg-blue-500/[0.08] text-blue-400 ring-blue-500/15",
  audit: "bg-white/[0.04] text-gray-400 ring-white/[0.06]",
  learning: "bg-purple-500/[0.08] text-purple-400 ring-purple-500/15",
};

const SEVERITY_COLORS: Record<AnomalySeverity, { bar: string; badge: string }> = {
  critical: { bar: "bg-red-500", badge: "bg-red-500/[0.08] text-red-400 ring-red-500/15" },
  high: { bar: "bg-orange-500", badge: "bg-orange-500/[0.08] text-orange-400 ring-orange-500/15" },
  medium: { bar: "bg-amber-500", badge: "bg-amber-500/[0.08] text-amber-400 ring-amber-500/15" },
  low: { bar: "bg-blue-500", badge: "bg-blue-500/[0.08] text-blue-400 ring-blue-500/15" },
};

const DECISION_COLORS: Record<AuditDecision, string> = {
  allowed: "bg-emerald-500/[0.08] text-emerald-400 ring-emerald-500/15",
  blocked: "bg-red-500/[0.08] text-red-400 ring-red-500/15",
  flagged: "bg-amber-500/[0.08] text-amber-400 ring-amber-500/15",
};

function riskColor(score: number) {
  if (score > 80) return "text-red-400";
  if (score >= 50) return "text-amber-400";
  return "text-emerald-400";
}

// ── Component ────────────────────────────────────────────────────────
export default function AgentFirewall() {
  const [tab, setTab] = useState<TabId>("agents");
  const [hoveredAgent, setHoveredAgent] = useState<string | null>(null);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Agent Firewall"
        badge={{ label: "8 Agents Monitored", variant: "info" }}
        description="Real-time monitoring and control of AI agent tool calls"
      />

      {/* Metrics */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard label="Calls Intercepted (24h)" value="4,218" icon={<Shield className="h-5 w-5" />} change={12.3} />
        <MetricCard label="Anomalies Detected" value={14} icon={<AlertTriangle className="h-5 w-5" />} change={-8.2} />
        <MetricCard label="Policies Active" value={9} icon={<FileText className="h-5 w-5" />} change={0} />
        <MetricCard label="Circuit Breakers Open" value={1} icon={<Zap className="h-5 w-5" />} change={-50.0} />
      </div>

      {/* Tab Bar */}
      <div className="flex gap-1 rounded-lg border border-white/[0.06] bg-surface-1 p-1">
        {TABS.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={clsx(
              "rounded-md px-4 py-2 text-sm font-medium transition-colors",
              tab === t.id
                ? "bg-surface-3 text-gray-100 shadow-sm"
                : "text-gray-400 hover:text-gray-200",
            )}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      {tab === "agents" && (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          {AGENTS.map((agent) => {
            const cb = CIRCUIT_COLORS[agent.circuitBreaker];
            const isHovered = hoveredAgent === agent.id;
            return (
              <div
                key={agent.id}
                onMouseEnter={() => setHoveredAgent(agent.id)}
                onMouseLeave={() => setHoveredAgent(null)}
                className={clsx(
                  "relative overflow-hidden rounded-xl border p-5 transition-all duration-200",
                  "bg-surface-2 shadow-depth",
                  agent.circuitBreaker === "open"
                    ? "border-red-500/20 hover:border-red-500/30"
                    : agent.circuitBreaker === "half_open"
                      ? "border-amber-500/20 hover:border-amber-500/30"
                      : "border-white/[0.06] hover:border-white/[0.1]",
                )}
              >
                {/* Header */}
                <div className="flex items-start justify-between">
                  <div>
                    <p className="font-mono text-sm font-semibold text-gray-100">{agent.name}</p>
                    <p className="mt-0.5 text-[11px] text-gray-600">{agent.id}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={clsx("inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-[11px] font-medium ring-1 ring-inset", cb.bg)}>
                      {agent.circuitBreaker === "open" && (
                        <span className="relative flex h-1.5 w-1.5">
                          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-red-400 opacity-50" />
                          <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-red-400" />
                        </span>
                      )}
                      {cb.label}
                    </span>
                    <span className={clsx("inline-flex rounded-md px-2 py-0.5 text-[11px] font-medium ring-1 ring-inset", MODE_COLORS[agent.mode])}>
                      {agent.mode}
                    </span>
                  </div>
                </div>

                {/* Stats */}
                <div className="mt-4 grid grid-cols-3 gap-4">
                  <div>
                    <p className="text-[11px] font-medium text-gray-600">Calls/min</p>
                    <p className="mt-0.5 text-lg font-semibold text-gray-100">{agent.callsPerMin}</p>
                  </div>
                  <div>
                    <p className="text-[11px] font-medium text-gray-600">Anomalies (24h)</p>
                    <p className={clsx("mt-0.5 text-lg font-semibold", agent.anomalies24h > 0 ? "text-amber-400" : "text-gray-100")}>
                      {agent.anomalies24h}
                    </p>
                  </div>
                  <div>
                    <p className="text-[11px] font-medium text-gray-600">Last Active</p>
                    <p className="mt-0.5 text-sm text-gray-300">{agent.lastActive}</p>
                  </div>
                </div>

                {/* Actions */}
                <div className={clsx("mt-4 flex gap-2 transition-opacity duration-200", isHovered ? "opacity-100" : "opacity-0")}>
                  <button className="btn-secondary flex items-center gap-1.5 text-xs">
                    <Eye className="h-3.5 w-3.5" /> View Events
                  </button>
                  <button className="flex items-center gap-1.5 rounded-lg border border-red-500/20 bg-red-500/[0.06] px-3 py-1.5 text-xs font-medium text-red-400 transition-colors hover:bg-red-500/[0.12]">
                    <Power className="h-3.5 w-3.5" /> Kill Switch
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {tab === "anomalies" && (
        <div className="space-y-3">
          {ANOMALIES.map((anomaly) => {
            const sev = SEVERITY_COLORS[anomaly.severity];
            return (
              <div key={anomaly.id} className="relative flex overflow-hidden rounded-xl border border-white/[0.06] bg-surface-2 shadow-depth transition-colors hover:border-white/[0.1]">
                {/* Severity bar */}
                <div className={clsx("w-1 shrink-0", sev.bar)} />
                <div className="flex-1 p-4">
                  <div className="flex items-start justify-between">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-sm font-medium text-gray-100">{anomaly.agent}</span>
                      <span className={clsx("inline-flex rounded-md px-2 py-0.5 text-[11px] font-medium ring-1 ring-inset", sev.badge)}>
                        {anomaly.severity}
                      </span>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className={clsx("text-sm font-semibold", riskColor(anomaly.riskScore))}>
                        {anomaly.riskScore}
                      </span>
                      <span className="text-[11px] text-gray-600">
                        <Clock className="mr-1 inline h-3 w-3" />
                        {new Date(anomaly.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                      </span>
                    </div>
                  </div>
                  <p className="mt-1.5 text-sm font-medium text-gray-300">{anomaly.type}</p>
                  <p className="mt-1 text-[13px] text-gray-500">{anomaly.description}</p>
                  <div className="mt-2 flex items-center justify-between">
                    <p className="rounded-md bg-white/[0.03] px-2 py-1 font-mono text-[11px] text-gray-500">{anomaly.evidence}</p>
                    <button className="text-[12px] font-medium text-brand-400 hover:text-brand-300">Investigate</button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {tab === "policies" && (
        <div className="overflow-x-auto rounded-xl border border-white/[0.06] bg-surface-2 shadow-depth">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-white/[0.04] text-[11px] font-semibold uppercase tracking-wider text-gray-500">
              <tr>
                <th className="px-5 py-3.5">Policy Name</th>
                <th className="px-5 py-3.5">Tool Pattern</th>
                <th className="px-5 py-3.5">Rate Limit</th>
                <th className="px-5 py-3.5">Data Limit</th>
                <th className="px-5 py-3.5">Status</th>
                <th className="px-5 py-3.5">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.04]">
              {POLICIES.map((policy) => (
                <tr key={policy.id} className="hover:bg-surface-3">
                  <td className="px-5 py-3.5 font-medium text-gray-100">{policy.name}</td>
                  <td className="px-5 py-3.5 font-mono text-[12px] text-gray-400">{policy.toolPattern}</td>
                  <td className="px-5 py-3.5 text-gray-300">{policy.rateLimit}</td>
                  <td className="px-5 py-3.5 text-gray-300">{policy.dataLimit}</td>
                  <td className="px-5 py-3.5">
                    <StatusBadge status={policy.status} />
                  </td>
                  <td className="px-5 py-3.5">
                    <div className="flex gap-2">
                      <button className="text-[12px] font-medium text-brand-400 hover:text-brand-300">Edit</button>
                      <button className="text-[12px] font-medium text-gray-500 hover:text-gray-300">
                        {policy.status === "active" ? "Disable" : "Enable"}
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {tab === "audit" && (
        <div className="overflow-x-auto rounded-xl border border-white/[0.06] bg-surface-2 shadow-depth">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-white/[0.04] text-[11px] font-semibold uppercase tracking-wider text-gray-500">
              <tr>
                <th className="px-5 py-3.5">Time</th>
                <th className="px-5 py-3.5">Agent</th>
                <th className="px-5 py-3.5">Tool</th>
                <th className="px-5 py-3.5">Decision</th>
                <th className="px-5 py-3.5">Risk Score</th>
                <th className="px-5 py-3.5">Latency</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.04]">
              {AUDIT_LOG.map((entry) => (
                <tr key={entry.id} className="hover:bg-surface-3">
                  <td className="px-5 py-3.5 font-mono text-[12px] text-gray-400">{entry.timestamp}</td>
                  <td className="px-5 py-3.5 font-mono text-[12px] text-gray-200">{entry.agent}</td>
                  <td className="px-5 py-3.5 font-mono text-[12px] text-gray-400">{entry.tool}</td>
                  <td className="px-5 py-3.5">
                    <span className={clsx("inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-[11px] font-medium ring-1 ring-inset", DECISION_COLORS[entry.decision])}>
                      {entry.decision === "allowed" && <CheckCircle className="h-3 w-3" />}
                      {entry.decision === "blocked" && <XCircle className="h-3 w-3" />}
                      {entry.decision === "flagged" && <Flag className="h-3 w-3" />}
                      {entry.decision}
                    </span>
                  </td>
                  <td className="px-5 py-3.5">
                    <span className={clsx("font-semibold", riskColor(entry.riskScore))}>{entry.riskScore}</span>
                  </td>
                  <td className="px-5 py-3.5 text-gray-400">{entry.latencyMs}ms</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
