import { useState, useMemo } from "react";
import {
  KeyRound,
  AlertTriangle,
  Eye,
  ShieldOff,
  Bot,
  Server,
  GitBranch,
  Globe,
  Key,
  Plug,
  Search,
  UserX,
  Ban,
  ClipboardPlus,
} from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

// ── Types ────────────────────────────────────────────────────────────
type NHIType = "service_account" | "ai_agent" | "ci_cd" | "oauth_app" | "api_key" | "mcp_connection";
type NHIStatus = "active" | "dormant" | "orphaned" | "shadow" | "compromised";
type Provider = "AWS" | "GCP" | "Azure" | "K8s" | "GitHub";
type RiskLevel = "critical" | "high" | "medium" | "low";

interface NHI {
  id: string;
  name: string;
  type: NHIType;
  provider: Provider;
  riskScore: number;
  status: NHIStatus;
  owner: string | null;
  lastActive: string;
  permissions: number;
}

interface ShadowAI {
  id: string;
  provider: string;
  callingService: string;
  detectionSource: string;
  requestCount: number;
  estimatedCost: string;
  status: "detected" | "investigating" | "confirmed";
}

// ── Demo Data ────────────────────────────────────────────────────────
const NHIS: NHI[] = [
  { id: "nhi-001", name: "svc-prod-deployer", type: "service_account", provider: "AWS", riskScore: 92, status: "active", owner: "platform-team", lastActive: "2 min ago", permissions: 47 },
  { id: "nhi-002", name: "gke-workload-identity", type: "service_account", provider: "GCP", riskScore: 34, status: "active", owner: "infra-team", lastActive: "5 min ago", permissions: 12 },
  { id: "nhi-003", name: "k8s-cluster-admin", type: "service_account", provider: "K8s", riskScore: 88, status: "active", owner: null, lastActive: "1 hr ago", permissions: 64 },
  { id: "nhi-004", name: "azure-function-msi", type: "service_account", provider: "Azure", riskScore: 22, status: "active", owner: "backend-team", lastActive: "15 min ago", permissions: 8 },
  { id: "nhi-005", name: "legacy-batch-runner", type: "service_account", provider: "AWS", riskScore: 76, status: "dormant", owner: null, lastActive: "90 days ago", permissions: 38 },
  { id: "nhi-006", name: "svc-monitoring-ro", type: "service_account", provider: "GCP", riskScore: 15, status: "active", owner: "sre-team", lastActive: "30s ago", permissions: 5 },
  { id: "nhi-007", name: "terraform-ci-role", type: "service_account", provider: "AWS", riskScore: 81, status: "active", owner: "devops", lastActive: "10 min ago", permissions: 52 },
  { id: "nhi-008", name: "gke-node-pool-sa", type: "service_account", provider: "GCP", riskScore: 28, status: "active", owner: "infra-team", lastActive: "1 min ago", permissions: 9 },
  { id: "nhi-009", name: "shieldops-investigation-agent", type: "ai_agent", provider: "AWS", riskScore: 45, status: "active", owner: "platform-team", lastActive: "8s ago", permissions: 18 },
  { id: "nhi-010", name: "shieldops-remediation-agent", type: "ai_agent", provider: "K8s", riskScore: 62, status: "active", owner: "platform-team", lastActive: "1 min ago", permissions: 24 },
  { id: "nhi-011", name: "customer-support-bot", type: "ai_agent", provider: "AWS", riskScore: 38, status: "active", owner: "cx-team", lastActive: "3s ago", permissions: 11 },
  { id: "nhi-012", name: "code-review-agent", type: "ai_agent", provider: "GitHub", riskScore: 25, status: "active", owner: "engineering", lastActive: "12 min ago", permissions: 7 },
  { id: "nhi-013", name: "github-actions-runner", type: "ci_cd", provider: "GitHub", riskScore: 55, status: "active", owner: "devops", lastActive: "4 min ago", permissions: 31 },
  { id: "nhi-014", name: "gitlab-deploy-token", type: "ci_cd", provider: "K8s", riskScore: 68, status: "active", owner: null, lastActive: "2 hr ago", permissions: 29 },
  { id: "nhi-015", name: "argocd-sync-sa", type: "ci_cd", provider: "K8s", riskScore: 42, status: "active", owner: "gitops-team", lastActive: "6 min ago", permissions: 15 },
  { id: "nhi-016", name: "slack-app-shieldops", type: "oauth_app", provider: "AWS", riskScore: 18, status: "active", owner: "platform-team", lastActive: "1 min ago", permissions: 6 },
  { id: "nhi-017", name: "jira-integration", type: "oauth_app", provider: "AWS", riskScore: 12, status: "active", owner: "engineering", lastActive: "20 min ago", permissions: 4 },
  { id: "nhi-018", name: "datadog-ingest-key", type: "oauth_app", provider: "AWS", riskScore: 24, status: "active", owner: "sre-team", lastActive: "10s ago", permissions: 3 },
  { id: "nhi-019", name: "deprecated-pagerduty-app", type: "oauth_app", provider: "AWS", riskScore: 71, status: "orphaned", owner: null, lastActive: "180 days ago", permissions: 14 },
  { id: "nhi-020", name: "stripe-webhook-key", type: "api_key", provider: "AWS", riskScore: 35, status: "active", owner: "billing-team", lastActive: "5 min ago", permissions: 2 },
  { id: "nhi-021", name: "sendgrid-api-key", type: "api_key", provider: "AWS", riskScore: 19, status: "active", owner: "comms-team", lastActive: "1 hr ago", permissions: 3 },
  { id: "nhi-022", name: "legacy-admin-key", type: "api_key", provider: "AWS", riskScore: 95, status: "compromised", owner: null, lastActive: "5 min ago", permissions: 89 },
  { id: "nhi-023", name: "postgres-mcp-server", type: "mcp_connection", provider: "K8s", riskScore: 58, status: "active", owner: "platform-team", lastActive: "2 min ago", permissions: 22 },
  { id: "nhi-024", name: "github-mcp-server", type: "mcp_connection", provider: "GitHub", riskScore: 41, status: "active", owner: "engineering", lastActive: "8 min ago", permissions: 16 },
  { id: "nhi-025", name: "vault-mcp-server", type: "mcp_connection", provider: "K8s", riskScore: 73, status: "active", owner: "security-team", lastActive: "1 min ago", permissions: 34 },
];

const SHADOW_AI: ShadowAI[] = [
  { id: "sai-001", provider: "OpenAI", callingService: "marketing-analytics-svc", detectionSource: "DNS monitoring", requestCount: 12480, estimatedCost: "$847.20", status: "detected" },
  { id: "sai-002", provider: "Anthropic", callingService: "data-pipeline-worker", detectionSource: "Proxy logs", requestCount: 3200, estimatedCost: "$256.00", status: "investigating" },
  { id: "sai-003", provider: "Azure OpenAI", callingService: "internal-chatbot-v2", detectionSource: "Billing anomaly", requestCount: 8750, estimatedCost: "$1,312.50", status: "confirmed" },
];

// ── Helpers ──────────────────────────────────────────────────────────
const TYPE_CONFIG: Record<NHIType, { icon: typeof Server; label: string; color: string }> = {
  service_account: { icon: Server, label: "Service Account", color: "bg-blue-500/[0.08] text-blue-400 ring-blue-500/15" },
  ai_agent: { icon: Bot, label: "AI Agent", color: "bg-purple-500/[0.08] text-purple-400 ring-purple-500/15" },
  ci_cd: { icon: GitBranch, label: "CI/CD", color: "bg-cyan-500/[0.08] text-cyan-400 ring-cyan-500/15" },
  oauth_app: { icon: Globe, label: "OAuth App", color: "bg-emerald-500/[0.08] text-emerald-400 ring-emerald-500/15" },
  api_key: { icon: Key, label: "API Key", color: "bg-amber-500/[0.08] text-amber-400 ring-amber-500/15" },
  mcp_connection: { icon: Plug, label: "MCP Connection", color: "bg-rose-500/[0.08] text-rose-400 ring-rose-500/15" },
};

const STATUS_STYLES: Record<NHIStatus, string> = {
  active: "bg-emerald-500/[0.08] text-emerald-400 ring-emerald-500/15",
  dormant: "bg-white/[0.04] text-gray-400 ring-white/[0.06]",
  orphaned: "bg-amber-500/[0.08] text-amber-400 ring-amber-500/15",
  shadow: "bg-purple-500/[0.08] text-purple-400 ring-purple-500/15",
  compromised: "bg-red-500/[0.08] text-red-400 ring-red-500/15",
};

const PROVIDER_COLORS: Record<Provider, string> = {
  AWS: "bg-orange-500/[0.08] text-orange-400 ring-orange-500/15",
  GCP: "bg-blue-500/[0.08] text-blue-400 ring-blue-500/15",
  Azure: "bg-sky-500/[0.08] text-sky-400 ring-sky-500/15",
  K8s: "bg-indigo-500/[0.08] text-indigo-400 ring-indigo-500/15",
  GitHub: "bg-white/[0.04] text-gray-300 ring-white/[0.06]",
};

function riskGauge(score: number) {
  if (score > 70) return { color: "text-red-400", bg: "bg-red-500", track: "bg-red-500/20" };
  if (score >= 30) return { color: "text-amber-400", bg: "bg-amber-500", track: "bg-amber-500/20" };
  return { color: "text-emerald-400", bg: "bg-emerald-500", track: "bg-emerald-500/20" };
}

function riskLevel(score: number): RiskLevel {
  if (score > 80) return "critical";
  if (score > 60) return "high";
  if (score >= 30) return "medium";
  return "low";
}

// ── Component ────────────────────────────────────────────────────────
export default function NHIRegistry() {
  const [typeFilter, setTypeFilter] = useState<string>("All");
  const [riskFilter, setRiskFilter] = useState<string>("All");
  const [providerFilter, setProviderFilter] = useState<string>("All");
  const [searchQuery, setSearchQuery] = useState("");

  const filtered = useMemo(() => {
    return NHIS.filter((nhi) => {
      if (typeFilter !== "All" && TYPE_CONFIG[nhi.type].label !== typeFilter) return false;
      if (riskFilter !== "All" && riskLevel(nhi.riskScore) !== riskFilter.toLowerCase()) return false;
      if (providerFilter !== "All" && nhi.provider !== providerFilter) return false;
      if (searchQuery && !nhi.name.toLowerCase().includes(searchQuery.toLowerCase())) return false;
      return true;
    });
  }, [typeFilter, riskFilter, providerFilter, searchQuery]);

  const orphanedCount = NHIS.filter((n) => n.status === "orphaned" || n.owner === null).length;
  const overPrivileged = NHIS.filter((n) => n.permissions > 30).length;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Non-Human Identities"
        badge={{ label: `${NHIS.length} Total`, variant: "info" }}
        description="Inventory and risk dashboard for all non-human identities across your infrastructure"
      />

      {/* Metrics */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard label="Total NHIs" value={NHIS.length} icon={<KeyRound className="h-5 w-5" />} change={8.0} />
        <MetricCard label="Orphaned" value={orphanedCount} icon={<UserX className="h-5 w-5" />} change={-16.7} />
        <MetricCard label="Over-Privileged" value={overPrivileged} icon={<ShieldOff className="h-5 w-5" />} change={-10.0} />
        <MetricCard label="Shadow AI Detected" value={SHADOW_AI.length} icon={<AlertTriangle className="h-5 w-5" />} change={50.0} />
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3 rounded-xl border border-white/[0.06] bg-surface-2 p-4 shadow-depth">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-600" />
          <input
            type="text"
            placeholder="Search by name..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="rounded-lg border border-white/[0.06] bg-surface-1 py-2 pl-9 pr-4 text-sm text-gray-200 placeholder-gray-600 outline-none transition-colors focus:border-brand-400/30"
          />
        </div>
        <select
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
          className="rounded-lg border border-white/[0.06] bg-surface-1 px-3 py-2 text-sm text-gray-300 outline-none"
        >
          <option>All</option>
          <option>Service Account</option>
          <option>AI Agent</option>
          <option>CI/CD</option>
          <option>OAuth App</option>
          <option>API Key</option>
          <option>MCP Connection</option>
        </select>
        <select
          value={riskFilter}
          onChange={(e) => setRiskFilter(e.target.value)}
          className="rounded-lg border border-white/[0.06] bg-surface-1 px-3 py-2 text-sm text-gray-300 outline-none"
        >
          <option>All</option>
          <option>Critical</option>
          <option>High</option>
          <option>Medium</option>
          <option>Low</option>
        </select>
        <select
          value={providerFilter}
          onChange={(e) => setProviderFilter(e.target.value)}
          className="rounded-lg border border-white/[0.06] bg-surface-1 px-3 py-2 text-sm text-gray-300 outline-none"
        >
          <option>All</option>
          <option>AWS</option>
          <option>GCP</option>
          <option>Azure</option>
          <option>K8s</option>
          <option>GitHub</option>
        </select>
        <span className="text-[12px] text-gray-600">{filtered.length} results</span>
      </div>

      {/* NHI Grid */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
        {filtered.map((nhi) => {
          const typeConf = TYPE_CONFIG[nhi.type];
          const gauge = riskGauge(nhi.riskScore);
          const TypeIcon = typeConf.icon;
          return (
            <div
              key={nhi.id}
              className={clsx(
                "overflow-hidden rounded-xl border p-5 transition-all duration-200",
                "bg-surface-2 shadow-depth hover-lift",
                nhi.status === "compromised"
                  ? "border-red-500/20 hover:border-red-500/30"
                  : "border-white/[0.06] hover:border-white/[0.1]",
              )}
            >
              {/* Header */}
              <div className="flex items-start justify-between">
                <div className="min-w-0 flex-1">
                  <p className="truncate font-mono text-sm font-semibold text-gray-100">{nhi.name}</p>
                  <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                    <span className={clsx("inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-[11px] font-medium ring-1 ring-inset", typeConf.color)}>
                      <TypeIcon className="h-3 w-3" /> {typeConf.label}
                    </span>
                    <span className={clsx("inline-flex rounded-md px-2 py-0.5 text-[11px] font-medium ring-1 ring-inset", PROVIDER_COLORS[nhi.provider])}>
                      {nhi.provider}
                    </span>
                  </div>
                </div>
                <span className={clsx("inline-flex rounded-md px-2 py-0.5 text-[11px] font-medium ring-1 ring-inset", STATUS_STYLES[nhi.status])}>
                  {nhi.status === "compromised" && (
                    <span className="relative mr-1 flex h-1.5 w-1.5">
                      <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-red-400 opacity-50" />
                      <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-red-400" />
                    </span>
                  )}
                  {nhi.status}
                </span>
              </div>

              {/* Risk gauge */}
              <div className="mt-4">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-medium text-gray-600">Risk Score</span>
                  <span className={clsx("text-sm font-bold", gauge.color)}>{nhi.riskScore}</span>
                </div>
                <div className={clsx("mt-1.5 h-1.5 w-full overflow-hidden rounded-full", gauge.track)}>
                  <div className={clsx("h-full rounded-full transition-all", gauge.bg)} style={{ width: `${nhi.riskScore}%` }} />
                </div>
              </div>

              {/* Details */}
              <div className="mt-3 grid grid-cols-3 gap-2 text-[12px]">
                <div>
                  <p className="text-gray-600">Owner</p>
                  <p className={clsx("mt-0.5 font-medium", nhi.owner ? "text-gray-300" : "text-red-400")}>
                    {nhi.owner ?? "Unowned"}
                  </p>
                </div>
                <div>
                  <p className="text-gray-600">Last Active</p>
                  <p className="mt-0.5 text-gray-300">{nhi.lastActive}</p>
                </div>
                <div>
                  <p className="text-gray-600">Permissions</p>
                  <p className={clsx("mt-0.5 font-medium", nhi.permissions > 30 ? "text-amber-400" : "text-gray-300")}>
                    {nhi.permissions}
                  </p>
                </div>
              </div>

              {/* Footer */}
              <div className="mt-4 border-t border-white/[0.04] pt-3">
                <button className="text-[12px] font-medium text-brand-400 hover:text-brand-300">
                  <Eye className="mr-1 inline h-3 w-3" /> View Details
                </button>
              </div>
            </div>
          );
        })}
      </div>

      {/* Shadow AI Section */}
      <div className="rounded-xl border border-amber-500/20 bg-surface-2 p-6 shadow-depth">
        <div className="mb-4 flex items-center gap-2">
          <AlertTriangle className="h-5 w-5 text-amber-400" />
          <h2 className="text-lg font-semibold text-gray-100">Shadow AI Detections</h2>
          <span className="inline-flex rounded-md bg-amber-500/[0.08] px-2 py-0.5 text-[11px] font-medium text-amber-400 ring-1 ring-inset ring-amber-500/15">
            {SHADOW_AI.length} found
          </span>
        </div>
        <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
          {SHADOW_AI.map((sai) => (
            <div
              key={sai.id}
              className="rounded-lg border border-amber-500/10 bg-surface-1 p-4 transition-colors hover:border-amber-500/20"
            >
              <div className="flex items-center justify-between">
                <span className="text-sm font-semibold text-gray-100">{sai.provider}</span>
                <StatusBadge status={sai.status} />
              </div>
              <p className="mt-2 font-mono text-[12px] text-gray-400">{sai.callingService}</p>
              <div className="mt-3 space-y-1.5 text-[12px]">
                <div className="flex justify-between">
                  <span className="text-gray-600">Detection</span>
                  <span className="text-gray-300">{sai.detectionSource}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">Requests</span>
                  <span className="text-gray-300">{sai.requestCount.toLocaleString()}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">Est. Cost</span>
                  <span className="font-medium text-amber-400">{sai.estimatedCost}</span>
                </div>
              </div>
              <div className="mt-4 flex gap-2">
                <button className="flex items-center gap-1 rounded-lg border border-brand-400/20 bg-brand-500/[0.06] px-3 py-1.5 text-[11px] font-medium text-brand-400 transition-colors hover:bg-brand-500/[0.12]">
                  <ClipboardPlus className="h-3 w-3" /> Register
                </button>
                <button className="flex items-center gap-1 rounded-lg border border-red-500/20 bg-red-500/[0.06] px-3 py-1.5 text-[11px] font-medium text-red-400 transition-colors hover:bg-red-500/[0.12]">
                  <Ban className="h-3 w-3" /> Block
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
