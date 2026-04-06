import { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
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
  RefreshCw,
  Inbox,
  Loader2,
} from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
import LoadingSpinner from "../components/LoadingSpinner";
import { get, ApiError } from "../api/client";
import { useAuth } from "../hooks/useAuth";

// ── API types (match src/shieldops/api/routes/nhi_registry.py) ───────
interface NHIIdentity {
  id?: string;
  identity_id?: string;
  name: string;
  nhi_type: string;
  provider: string;
  status: string;
  owner: string | null;
  risk_score: number;
  permissions: string[] | number;
  last_activity?: string | null;
}

interface IdentityListResponse {
  identities: NHIIdentity[];
  total: number;
}

interface NHIMetrics {
  total_identities: number;
  by_type: Record<string, number>;
  by_risk: Record<string, number>;
  orphaned_count: number;
  over_privileged_count: number;
  shadow_ai_count: number;
  unique_providers: number;
  unique_owners: number;
  avg_risk_score: number;
}

interface ShadowAIRecord {
  id?: string;
  provider: string;
  calling_service?: string;
  detection_source?: string;
  request_count?: number;
  estimated_cost?: number | string;
  status: string;
}

interface ShadowAIResponse {
  shadow_ai_agents: ShadowAIRecord[];
  total: number;
}

// ── Display helpers ──────────────────────────────────────────────────
type DisplayType = "service_account" | "ai_agent" | "ci_cd" | "oauth_app" | "api_key" | "mcp_connection" | "other";

function normalizeType(t: string): DisplayType {
  const k = (t || "").toLowerCase();
  if (k.includes("service") || k === "sa") return "service_account";
  if (k.includes("ai") || k.includes("agent")) return "ai_agent";
  if (k.includes("ci") || k.includes("cd")) return "ci_cd";
  if (k.includes("oauth")) return "oauth_app";
  if (k.includes("api") || k.includes("key")) return "api_key";
  if (k.includes("mcp")) return "mcp_connection";
  return "other";
}

const TYPE_CONFIG: Record<DisplayType, { icon: typeof Server; label: string; color: string }> = {
  service_account: { icon: Server, label: "Service Account", color: "bg-blue-500/[0.08] text-blue-400 ring-blue-500/15" },
  ai_agent: { icon: Bot, label: "AI Agent", color: "bg-indigo-500/[0.08] text-indigo-300 ring-indigo-500/15" },
  ci_cd: { icon: GitBranch, label: "CI/CD", color: "bg-cyan-500/[0.08] text-cyan-400 ring-cyan-500/15" },
  oauth_app: { icon: Globe, label: "OAuth App", color: "bg-emerald-500/[0.08] text-emerald-400 ring-emerald-500/15" },
  api_key: { icon: Key, label: "API Key", color: "bg-amber-500/[0.08] text-amber-400 ring-amber-500/15" },
  mcp_connection: { icon: Plug, label: "MCP Connection", color: "bg-rose-500/[0.08] text-rose-400 ring-rose-500/15" },
  other: { icon: KeyRound, label: "Other", color: "bg-white/[0.04] text-gray-300 ring-white/[0.06]" },
};

const STATUS_STYLES: Record<string, string> = {
  active: "bg-emerald-500/[0.08] text-emerald-400 ring-emerald-500/15",
  dormant: "bg-white/[0.04] text-gray-400 ring-white/[0.06]",
  orphaned: "bg-amber-500/[0.08] text-amber-400 ring-amber-500/15",
  shadow: "bg-indigo-500/[0.08] text-indigo-300 ring-indigo-500/15",
  compromised: "bg-red-500/[0.08] text-red-400 ring-red-500/15",
};

function providerBadge(provider: string): string {
  const p = (provider || "").toLowerCase();
  if (p.includes("aws")) return "bg-orange-500/[0.08] text-orange-400 ring-orange-500/15";
  if (p.includes("gcp") || p.includes("google")) return "bg-blue-500/[0.08] text-blue-400 ring-blue-500/15";
  if (p.includes("azure")) return "bg-sky-500/[0.08] text-sky-400 ring-sky-500/15";
  if (p.includes("k8s") || p.includes("kube")) return "bg-indigo-500/[0.08] text-indigo-400 ring-indigo-500/15";
  if (p.includes("git")) return "bg-white/[0.04] text-gray-300 ring-white/[0.06]";
  return "bg-white/[0.04] text-gray-300 ring-white/[0.06]";
}

function riskGauge(score: number) {
  // Normalize: API returns 0–1, UI uses 0–100
  const pct = score <= 1 ? score * 100 : score;
  if (pct > 70) return { color: "text-red-400", bg: "bg-red-500", track: "bg-red-500/20", pct };
  if (pct >= 30) return { color: "text-amber-400", bg: "bg-amber-500", track: "bg-amber-500/20", pct };
  return { color: "text-emerald-400", bg: "bg-emerald-500", track: "bg-emerald-500/20", pct };
}

function riskLevelFromScore(score: number): "critical" | "high" | "medium" | "low" {
  const pct = score <= 1 ? score * 100 : score;
  if (pct > 80) return "critical";
  if (pct > 60) return "high";
  if (pct >= 30) return "medium";
  return "low";
}

function permissionCount(perms: NHIIdentity["permissions"]): number {
  if (Array.isArray(perms)) return perms.length;
  if (typeof perms === "number") return perms;
  return 0;
}

function formatLastActive(iso: string | null | undefined): string {
  if (!iso) return "Never";
  const d = new Date(iso);
  const diff = Date.now() - d.getTime();
  if (diff < 60_000) return "Just now";
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)} min ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)} hr ago`;
  return `${Math.floor(diff / 86_400_000)} days ago`;
}

// ── Component ────────────────────────────────────────────────────────
export default function NHIRegistry() {
  const { isAuthenticated, orgId } = useAuth();
  const [typeFilter, setTypeFilter] = useState<string>("All");
  const [riskFilter, setRiskFilter] = useState<string>("All");
  const [providerFilter, setProviderFilter] = useState<string>("All");
  const [searchQuery, setSearchQuery] = useState("");

  // Metrics
  const {
    data: metrics,
    isLoading: metricsLoading,
    error: metricsError,
    refetch: refetchMetrics,
    isFetching: metricsFetching,
  } = useQuery<NHIMetrics>({
    queryKey: ["nhi", "metrics", orgId],
    queryFn: () => get<NHIMetrics>("/nhi/metrics"),
    refetchInterval: 30_000,
    enabled: isAuthenticated,
    retry: (failureCount, err) => {
      if (err instanceof ApiError && (err.status === 401 || err.status === 403)) return false;
      return failureCount < 2;
    },
  });

  // Identities list
  const {
    data: identitiesResp,
    isLoading: identitiesLoading,
    error: identitiesError,
    refetch: refetchIdentities,
  } = useQuery<IdentityListResponse>({
    queryKey: ["nhi", "identities", orgId],
    queryFn: () => get<IdentityListResponse>("/nhi/identities?limit=200"),
    refetchInterval: 30_000,
    enabled: isAuthenticated,
    retry: (failureCount, err) => {
      if (err instanceof ApiError && (err.status === 401 || err.status === 403)) return false;
      return failureCount < 2;
    },
  });

  // Shadow AI
  const { data: shadowResp } = useQuery<ShadowAIResponse>({
    queryKey: ["nhi", "shadow", orgId],
    queryFn: () => get<ShadowAIResponse>("/nhi/shadow-ai?limit=20"),
    refetchInterval: 60_000,
    enabled: isAuthenticated,
    retry: (failureCount, err) => {
      if (err instanceof ApiError && (err.status === 401 || err.status === 403 || err.status === 501))
        return false;
      return failureCount < 1;
    },
  });

  const identities = identitiesResp?.identities ?? [];
  const shadowAi = shadowResp?.shadow_ai_agents ?? [];

  const filtered = useMemo(() => {
    return identities.filter((nhi) => {
      const dtype = normalizeType(nhi.nhi_type);
      if (typeFilter !== "All" && TYPE_CONFIG[dtype].label !== typeFilter) return false;
      if (riskFilter !== "All" && riskLevelFromScore(nhi.risk_score) !== riskFilter.toLowerCase()) return false;
      if (providerFilter !== "All" && !(nhi.provider || "").toLowerCase().includes(providerFilter.toLowerCase()))
        return false;
      if (searchQuery && !nhi.name.toLowerCase().includes(searchQuery.toLowerCase())) return false;
      return true;
    });
  }, [identities, typeFilter, riskFilter, providerFilter, searchQuery]);

  const handleRefresh = () => {
    refetchMetrics();
    refetchIdentities();
  };

  // ── Auth gate ──────────────────────────────────────────────────────
  if (!isAuthenticated) {
    return (
      <div className="space-y-6">
        <PageHeader title="Non-Human Identities" description="Inventory and risk dashboard for NHIs across your infrastructure" />
        <EmptyCard
          icon={<KeyRound className="h-10 w-10 text-gray-600" />}
          title="Sign in to view NHI registry"
          body="The NHI Registry is scoped to your organization. Please sign in to continue."
        />
      </div>
    );
  }

  // ── Initial loading ────────────────────────────────────────────────
  if (metricsLoading && !metrics) {
    return (
      <div className="space-y-6">
        <PageHeader title="Non-Human Identities" description="Inventory and risk dashboard for NHIs across your infrastructure" />
        <div className="flex flex-col items-center justify-center rounded-xl border border-white/[0.06] bg-surface-2 py-20">
          <LoadingSpinner size="lg" />
          <p className="mt-4 text-sm text-gray-400">Loading NHI registry…</p>
        </div>
      </div>
    );
  }

  // ── Error state ────────────────────────────────────────────────────
  if (metricsError && !metrics) {
    const message = metricsError instanceof ApiError ? metricsError.message : "Unable to reach the NHI registry API.";
    const notConfigured = metricsError instanceof ApiError && metricsError.status === 501;
    return (
      <div className="space-y-6">
        <PageHeader title="Non-Human Identities" description="Inventory and risk dashboard for NHIs across your infrastructure" />
        <EmptyCard
          icon={<AlertTriangle className="h-10 w-10 text-amber-500/60" />}
          title={notConfigured ? "NHI Registry not configured" : "Unable to load NHI data"}
          body={
            notConfigured
              ? "Connect a cloud provider in Settings → Integrations to begin discovering non-human identities."
              : message
          }
          action={
            !notConfigured && (
              <button onClick={handleRefresh} className="btn-secondary text-xs mt-4">
                <RefreshCw className="h-3.5 w-3.5" /> Retry
              </button>
            )
          }
        />
      </div>
    );
  }

  const total = metrics?.total_identities ?? identities.length;
  const orphaned = metrics?.orphaned_count ?? 0;
  const overPriv = metrics?.over_privileged_count ?? 0;
  const shadowCount = metrics?.shadow_ai_count ?? shadowAi.length;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Non-Human Identities"
        badge={{ label: `${total.toLocaleString()} total`, variant: "info" }}
        description="Inventory and risk dashboard for non-human identities across your infrastructure"
        action={{
          label: "Refresh",
          onClick: handleRefresh,
          icon: <RefreshCw className={clsx("h-4 w-4", metricsFetching && "animate-spin")} />,
          loading: metricsFetching,
        }}
      />

      {/* Metrics */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard label="Total NHIs" value={total.toLocaleString()} icon={<KeyRound className="h-5 w-5" />} />
        <MetricCard label="Orphaned" value={orphaned.toLocaleString()} icon={<UserX className="h-5 w-5" />} />
        <MetricCard label="Over-Privileged" value={overPriv.toLocaleString()} icon={<ShieldOff className="h-5 w-5" />} />
        <MetricCard label="Shadow AI Detected" value={shadowCount.toLocaleString()} icon={<AlertTriangle className="h-5 w-5" />} />
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

      {/* Identities grid */}
      {identitiesLoading && identities.length === 0 ? (
        <div className="flex items-center justify-center rounded-xl border border-white/[0.06] bg-surface-2 py-12">
          <Loader2 className="h-5 w-5 animate-spin text-gray-500" />
          <span className="ml-2 text-xs text-gray-500">Loading identities…</span>
        </div>
      ) : identitiesError && identities.length === 0 ? (
        <EmptyCard
          icon={<AlertTriangle className="h-10 w-10 text-amber-500/60" />}
          title="Unable to load identities"
          body={identitiesError instanceof ApiError ? identitiesError.message : "Identity list request failed."}
          action={
            <button onClick={() => refetchIdentities()} className="btn-secondary text-xs mt-4">
              <RefreshCw className="h-3.5 w-3.5" /> Retry
            </button>
          }
        />
      ) : filtered.length === 0 ? (
        <EmptyCard
          icon={<Inbox className="h-10 w-10 text-gray-600" />}
          title="No identities match your filters"
          body="Try clearing filters, or trigger an NHI discovery scan from the Settings page."
        />
      ) : (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
          {filtered.map((nhi) => {
            const dtype = normalizeType(nhi.nhi_type);
            const typeConf = TYPE_CONFIG[dtype];
            const gauge = riskGauge(nhi.risk_score);
            const TypeIcon = typeConf.icon;
            const perms = permissionCount(nhi.permissions);
            const statusKey = (nhi.status || "active").toLowerCase();
            const key = nhi.identity_id ?? nhi.id ?? nhi.name;
            return (
              <div
                key={key}
                className={clsx(
                  "overflow-hidden rounded-xl border p-5 transition-all duration-200",
                  "bg-surface-2 shadow-depth hover-lift",
                  statusKey === "compromised"
                    ? "border-red-500/20 hover:border-red-500/30"
                    : "border-white/[0.06] hover:border-white/[0.1]",
                )}
              >
                <div className="flex items-start justify-between">
                  <div className="min-w-0 flex-1">
                    <p className="truncate font-mono text-sm font-semibold text-gray-100">{nhi.name}</p>
                    <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                      <span className={clsx("inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-[11px] font-medium ring-1 ring-inset", typeConf.color)}>
                        <TypeIcon className="h-3 w-3" /> {typeConf.label}
                      </span>
                      <span className={clsx("inline-flex rounded-md px-2 py-0.5 text-[11px] font-medium ring-1 ring-inset", providerBadge(nhi.provider))}>
                        {nhi.provider || "unknown"}
                      </span>
                    </div>
                  </div>
                  <span className={clsx("inline-flex rounded-md px-2 py-0.5 text-[11px] font-medium ring-1 ring-inset", STATUS_STYLES[statusKey] ?? STATUS_STYLES.active)}>
                    {statusKey}
                  </span>
                </div>

                <div className="mt-4">
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] font-medium text-gray-600">Risk Score</span>
                    <span className={clsx("text-sm font-bold", gauge.color)}>{gauge.pct.toFixed(0)}</span>
                  </div>
                  <div className={clsx("mt-1.5 h-1.5 w-full overflow-hidden rounded-full", gauge.track)}>
                    <div className={clsx("h-full rounded-full transition-all", gauge.bg)} style={{ width: `${gauge.pct}%` }} />
                  </div>
                </div>

                <div className="mt-3 grid grid-cols-3 gap-2 text-[12px]">
                  <div>
                    <p className="text-gray-600">Owner</p>
                    <p className={clsx("mt-0.5 font-medium", nhi.owner ? "text-gray-300" : "text-red-400")}>
                      {nhi.owner ?? "Unowned"}
                    </p>
                  </div>
                  <div>
                    <p className="text-gray-600">Last Active</p>
                    <p className="mt-0.5 text-gray-300">{formatLastActive(nhi.last_activity)}</p>
                  </div>
                  <div>
                    <p className="text-gray-600">Permissions</p>
                    <p className={clsx("mt-0.5 font-medium", perms > 30 ? "text-amber-400" : "text-gray-300")}>
                      {perms}
                    </p>
                  </div>
                </div>

                <div className="mt-4 border-t border-white/[0.04] pt-3">
                  <button className="text-[12px] font-medium text-brand-400 hover:text-brand-300">
                    <Eye className="mr-1 inline h-3 w-3" /> View Details
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Shadow AI Section */}
      {shadowAi.length > 0 && (
        <div className="rounded-xl border border-amber-500/20 bg-surface-2 p-6 shadow-depth">
          <div className="mb-4 flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-amber-400" />
            <h2 className="text-lg font-semibold text-gray-100">Shadow AI Detections</h2>
            <span className="inline-flex rounded-md bg-amber-500/[0.08] px-2 py-0.5 text-[11px] font-medium text-amber-400 ring-1 ring-inset ring-amber-500/15">
              {shadowAi.length} found
            </span>
          </div>
          <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
            {shadowAi.map((sai, i) => {
              const cost =
                typeof sai.estimated_cost === "number"
                  ? `$${sai.estimated_cost.toFixed(2)}`
                  : sai.estimated_cost ?? "—";
              return (
                <div
                  key={sai.id ?? `${sai.provider}-${i}`}
                  className="rounded-lg border border-amber-500/10 bg-surface-1 p-4 transition-colors hover:border-amber-500/20"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-semibold text-gray-100">{sai.provider}</span>
                    <StatusBadge status={sai.status} />
                  </div>
                  <p className="mt-2 font-mono text-[12px] text-gray-400">{sai.calling_service ?? "unknown"}</p>
                  <div className="mt-3 space-y-1.5 text-[12px]">
                    <div className="flex justify-between">
                      <span className="text-gray-600">Detection</span>
                      <span className="text-gray-300">{sai.detection_source ?? "—"}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-600">Requests</span>
                      <span className="text-gray-300">{(sai.request_count ?? 0).toLocaleString()}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-600">Est. Cost</span>
                      <span className="font-medium text-amber-400">{cost}</span>
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
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Sub-components ────────────────────────────────────────────────────

function EmptyCard({
  icon,
  title,
  body,
  action,
}: {
  icon: React.ReactNode;
  title: string;
  body: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center rounded-xl border border-white/[0.06] bg-surface-2 py-16 text-center">
      {icon}
      <p className="mt-3 text-sm font-medium text-gray-300">{title}</p>
      <p className="mt-1 max-w-md px-4 text-xs text-gray-600">{body}</p>
      {action}
    </div>
  );
}
