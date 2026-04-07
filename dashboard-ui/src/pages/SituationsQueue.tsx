import { useState, useEffect, useCallback } from "react";
import { Link } from "react-router-dom";
import {
  Target,
  Clock,
  CheckCircle2,
  AlertTriangle,
  Shield,
  Eye,
  Zap,
  MonitorSmartphone,
  Cloud,
  Server,
  ChevronRight,
  RefreshCw,
  Loader2,
  Inbox,
} from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
import LoadingSpinner from "../components/LoadingSpinner";
import useSituations, {
  useSituationMetrics,
  type Situation,
  type TimeRange,
} from "../hooks/useSituations";

/* ---- Severity helpers ------------------------------------------------- */

const SEVERITY_LINE: Record<string, string> = {
  critical: "bg-red-500",
  high: "bg-amber-500",
  medium: "bg-yellow-500",
  low: "bg-blue-500",
  info: "bg-gray-500",
};

const SEVERITY_BADGE: Record<string, string> = {
  critical: "bg-red-500/10 text-red-400 ring-red-500/20",
  high: "bg-amber-500/10 text-amber-400 ring-amber-500/20",
  medium: "bg-yellow-500/10 text-yellow-400 ring-yellow-500/20",
  low: "bg-blue-500/10 text-blue-400 ring-blue-500/20",
  info: "bg-gray-500/10 text-gray-400 ring-gray-500/20",
};

const VENDOR_COLORS: Record<string, string> = {
  CrowdStrike: "bg-red-500/10 text-red-300 ring-red-500/15",
  Defender: "bg-blue-500/10 text-blue-300 ring-blue-500/15",
  Wiz: "bg-cyan-500/10 text-cyan-300 ring-cyan-500/15",
  Internal: "bg-gray-500/10 text-gray-300 ring-gray-500/15",
};

const MITRE_BADGE = "bg-purple-500/10 text-purple-300 ring-purple-500/15";

/* ---- Filter constants ------------------------------------------------- */

const SEVERITY_TABS = ["All", "Critical", "High", "Medium", "Low"] as const;
type SeverityTab = (typeof SEVERITY_TABS)[number];

const STATUS_OPTIONS = [
  "All Statuses",
  "new",
  "investigating",
  "containing",
  "remediating",
  "remediated",
  "resolved",
  "closed",
];

const TIME_RANGE_OPTIONS: { label: string; value: TimeRange | "" }[] = [
  { label: "All Time", value: "" },
  { label: "Last 1h", value: "1h" },
  { label: "Last 24h", value: "24h" },
  { label: "Last 7d", value: "7d" },
  { label: "Last 30d", value: "30d" },
];

const AGENT_TYPE_OPTIONS = [
  "All Agents",
  "soc_analyst",
  "threat_hunter",
  "identity_graph",
  "data_loss_prevention",
  "cloud_posture",
  "compliance_auditor",
  "incident_response",
  "vulnerability_manager",
  "agent_firewall",
];

/* ---- Auto-refresh countdown ------------------------------------------- */

const REFRESH_INTERVAL_SEC = 30;

function useAutoRefreshCountdown(refetch: () => void) {
  const [secondsUntilRefresh, setSecondsUntilRefresh] = useState(REFRESH_INTERVAL_SEC);

  useEffect(() => {
    const timer = setInterval(() => {
      setSecondsUntilRefresh((prev) => {
        if (prev <= 1) {
          return REFRESH_INTERVAL_SEC;
        }
        return prev - 1;
      });
    }, 1000);
    return () => clearInterval(timer);
  }, [refetch]);

  return secondsUntilRefresh;
}

/* ---- Main Component --------------------------------------------------- */

export default function SituationsQueue() {
  const [severityFilter, setSeverityFilter] = useState<SeverityTab>("All");
  const [statusFilter, setStatusFilter] = useState("All Statuses");
  const [agentFilter, setAgentFilter] = useState("All Agents");
  const [timeRange, setTimeRange] = useState<TimeRange | "">("");
  const [manualRefreshing, setManualRefreshing] = useState(false);

  // Build API filters
  const apiFilters = {
    severity: severityFilter !== "All" ? severityFilter.toLowerCase() : undefined,
    status: statusFilter !== "All Statuses" ? statusFilter : undefined,
    agent_name: agentFilter !== "All Agents" ? agentFilter : undefined,
    time_range: timeRange || undefined,
  };

  const { situations, total, loading, error, refetch, isDemo } =
    useSituations(apiFilters);
  const { metrics } = useSituationMetrics();
  const secondsUntilRefresh = useAutoRefreshCountdown(refetch);

  const handleRefresh = useCallback(() => {
    setManualRefreshing(true);
    refetch();
    setTimeout(() => setManualRefreshing(false), 1000);
  }, [refetch]);

  // Count by severity from current results
  const criticalCount = situations.filter((s) => s.severity === "critical").length;
  const highCount = situations.filter((s) => s.severity === "high").length;

  const isInitialLoad = loading && situations.length === 0;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Situations Queue"
        badge={{
          label: isDemo
            ? `${total} active (demo)`
            : `${total} active`,
          variant: criticalCount > 0 ? "error" : total > 0 ? "warning" : "success",
        }}
        action={{
          label: "Sweep Now",
          onClick: handleRefresh,
          icon: (
            <RefreshCw
              className={clsx("h-4 w-4", manualRefreshing && "animate-spin")}
            />
          ),
          loading: manualRefreshing,
        }}
      />

      {/* Metrics Row */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard
          label="Active Situations"
          value={metrics?.active_situations ?? total}
          icon={<Target className="h-5 w-5" />}
        />
        <MetricCard
          label="Avg MTTR"
          value={
            metrics?.avg_mttr_ms
              ? `${Math.round(metrics.avg_mttr_ms / 60000)}m`
              : "34m"
          }
          icon={<Clock className="h-5 w-5" />}
          change={-18.2}
        />
        <MetricCard
          label="Auto-Resolved %"
          value={
            metrics?.auto_resolved_pct !== undefined
              ? `${metrics.auto_resolved_pct}%`
              : "62%"
          }
          icon={<CheckCircle2 className="h-5 w-5" />}
          change={8.4}
        />
        <MetricCard
          label="Actions Pending"
          value={metrics?.actions_pending ?? criticalCount + highCount}
          icon={<AlertTriangle className="h-5 w-5" />}
        />
      </div>

      {/* Filter Bar */}
      <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
        {/* Left: Severity tabs */}
        <div className="flex gap-1 rounded-lg bg-surface-1 p-1">
          {SEVERITY_TABS.map((tab) => {
            const count =
              tab === "All"
                ? situations.length
                : situations.filter(
                    (s) => s.severity === tab.toLowerCase(),
                  ).length;
            return (
              <button
                key={tab}
                onClick={() => setSeverityFilter(tab)}
                className={clsx(
                  "rounded-md px-3 py-1.5 text-xs font-medium transition-colors",
                  severityFilter === tab
                    ? "bg-surface-3 text-gray-50 shadow-sm"
                    : "text-gray-400 hover:text-gray-200",
                )}
              >
                {tab}
                <span className="ml-1.5 text-[10px] text-gray-500">
                  {count}
                </span>
              </button>
            );
          })}
        </div>

        {/* Right: dropdowns */}
        <div className="flex flex-wrap items-center gap-2">
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="rounded-lg border border-white/[0.06] bg-surface-2 px-3 py-1.5 text-xs text-gray-300 outline-none focus:border-brand-500/30"
          >
            {STATUS_OPTIONS.map((opt) => (
              <option key={opt} value={opt}>
                {opt === "All Statuses" ? opt : opt.replace(/_/g, " ")}
              </option>
            ))}
          </select>

          <select
            value={agentFilter}
            onChange={(e) => setAgentFilter(e.target.value)}
            className="rounded-lg border border-white/[0.06] bg-surface-2 px-3 py-1.5 text-xs text-gray-300 outline-none focus:border-brand-500/30"
          >
            {AGENT_TYPE_OPTIONS.map((opt) => (
              <option key={opt} value={opt}>
                {opt === "All Agents"
                  ? opt
                  : opt.replace(/_/g, " ")}
              </option>
            ))}
          </select>

          <select
            value={timeRange}
            onChange={(e) => setTimeRange(e.target.value as TimeRange | "")}
            className="rounded-lg border border-white/[0.06] bg-surface-2 px-3 py-1.5 text-xs text-gray-300 outline-none focus:border-brand-500/30"
          >
            {TIME_RANGE_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>

          {/* Auto-refresh indicator */}
          <span className="hidden text-[10px] text-gray-600 sm:inline-flex items-center gap-1">
            <span
              className="inline-block h-1.5 w-1.5 rounded-full bg-emerald-500/60 animate-pulse"
            />
            refresh in {secondsUntilRefresh}s
          </span>
        </div>
      </div>

      {/* Loading state */}
      {isInitialLoad && (
        <div className="flex flex-col items-center justify-center rounded-xl border border-white/[0.06] bg-surface-2 py-20">
          <LoadingSpinner size="lg" />
          <p className="mt-4 text-sm text-gray-400">Loading situations...</p>
        </div>
      )}

      {/* Situation Cards */}
      {!isInitialLoad && (
        <div className="space-y-3">
          {situations.map((sit) => (
            <SituationCard key={sit.id} situation={sit} />
          ))}

          {/* Empty state */}
          {situations.length === 0 && !loading && (
            <div className="flex flex-col items-center justify-center rounded-xl border border-white/[0.06] bg-surface-2 py-16">
              {error && !isDemo ? (
                <>
                  <AlertTriangle className="h-10 w-10 text-amber-500/50" />
                  <p className="mt-3 text-sm font-medium text-gray-400">
                    Unable to load situations
                  </p>
                  <p className="mt-1 text-xs text-gray-600">
                    {error}
                  </p>
                  <button
                    onClick={handleRefresh}
                    className="mt-4 btn-secondary text-xs"
                  >
                    <RefreshCw className="h-3.5 w-3.5" />
                    Retry
                  </button>
                </>
              ) : (
                <>
                  <Inbox className="h-10 w-10 text-gray-600" />
                  <p className="mt-3 text-sm font-medium text-gray-400">
                    No situations match your filters
                  </p>
                  <p className="mt-1 text-xs text-gray-600">
                    Adjust severity, status, or agent filters to see results
                  </p>
                </>
              )}
            </div>
          )}

          {/* Inline loading indicator during poll refresh */}
          {loading && situations.length > 0 && (
            <div className="flex items-center justify-center py-2">
              <Loader2 className="h-4 w-4 animate-spin text-gray-500" />
              <span className="ml-2 text-xs text-gray-500">Refreshing...</span>
            </div>
          )}
        </div>
      )}

      {/* Demo banner */}
      {isDemo && (
        <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 px-4 py-2 text-xs text-amber-400">
          Showing demo data -- connect to the ShieldOps API for live situations.
        </div>
      )}
    </div>
  );
}

/* ---- Situation Card Component ----------------------------------------- */

function SituationCard({ situation: sit }: { situation: Situation }) {
  return (
    <div className="group relative flex overflow-hidden rounded-xl border border-white/[0.06] bg-surface-2 shadow-depth transition-all duration-200 hover:border-white/[0.1] hover:bg-surface-3">
      {/* Severity indicator line */}
      <div
        className={clsx("w-1 shrink-0", SEVERITY_LINE[sit.severity] || "bg-gray-500")}
      />

      <div className="flex flex-1 flex-col gap-3 p-5 sm:flex-row sm:items-start sm:justify-between">
        {/* Left content */}
        <div className="min-w-0 flex-1 space-y-2.5">
          <div className="flex flex-wrap items-center gap-2">
            <Link
              to={`/app/situations/${sit.id}`}
              className="text-sm font-semibold text-gray-50 hover:text-brand-400 transition-colors"
            >
              {sit.title}
            </Link>
            <span
              className={clsx(
                "inline-flex rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase ring-1 ring-inset",
                SEVERITY_BADGE[sit.severity] || SEVERITY_BADGE.info,
              )}
            >
              {sit.severity}
            </span>
            <StatusBadge status={sit.status} />
          </div>

          <p className="text-xs leading-relaxed text-gray-400 line-clamp-2">
            {sit.description}
          </p>

          {/* Tags */}
          <div className="flex flex-wrap items-center gap-1.5">
            {/* Agent badge */}
            {sit.agent_name && (
              <span className="inline-flex items-center gap-1 rounded-md bg-brand-500/10 px-1.5 py-0.5 text-[10px] font-medium text-brand-300 ring-1 ring-inset ring-brand-500/15">
                {sit.agent_name.replace(/_/g, " ")}
              </span>
            )}
            {sit.vendors.map((v) => (
              <span
                key={v}
                className={clsx(
                  "inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[10px] font-medium ring-1 ring-inset",
                  VENDOR_COLORS[v] || VENDOR_COLORS.Internal,
                )}
              >
                {v === "CrowdStrike" && <Shield className="h-2.5 w-2.5" />}
                {v === "Defender" && (
                  <MonitorSmartphone className="h-2.5 w-2.5" />
                )}
                {v === "Wiz" && <Cloud className="h-2.5 w-2.5" />}
                {v}
              </span>
            ))}
            {sit.mitre_techniques.map((t) => (
              <span
                key={t}
                className={clsx(
                  "inline-flex rounded-md px-1.5 py-0.5 text-[10px] font-medium ring-1 ring-inset",
                  MITRE_BADGE,
                )}
              >
                {t}
              </span>
            ))}
          </div>
        </div>

        {/* Right stats + actions */}
        <div className="flex shrink-0 flex-col items-end gap-3 sm:ml-6">
          <div className="flex items-center gap-4 text-[11px] text-gray-500">
            <span className="flex items-center gap-1">
              <Server className="h-3 w-3" />
              {sit.affected_assets} assets
            </span>
            <span className="flex items-center gap-1">
              <Zap className="h-3 w-3" />
              {sit.correlated_events} events
            </span>
            <span className="flex items-center gap-1">
              <Clock className="h-3 w-3" />
              {sit.time_open}
            </span>
          </div>

          <div className="flex items-center gap-2">
            {sit.primary_action && (
              <button className="flex items-center gap-1.5 rounded-lg bg-brand-600/80 px-3 py-1.5 text-[11px] font-semibold text-white shadow-sm transition-colors hover:bg-brand-500">
                <Zap className="h-3 w-3" />
                {sit.primary_action}
              </button>
            )}
            <Link
              to={`/app/situations/${sit.id}`}
              className="flex items-center gap-1 rounded-lg border border-white/[0.06] bg-surface-1 px-3 py-1.5 text-[11px] font-medium text-gray-300 transition-colors hover:border-white/[0.1] hover:text-gray-50"
            >
              <Eye className="h-3 w-3" />
              View
              <ChevronRight className="h-3 w-3" />
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
