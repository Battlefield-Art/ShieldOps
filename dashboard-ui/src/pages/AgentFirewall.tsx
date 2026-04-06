import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Shield,
  AlertTriangle,
  Zap,
  CheckCircle,
  XCircle,
  Flag,
  Inbox,
  RefreshCw,
  Loader2,
} from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import LoadingSpinner from "../components/LoadingSpinner";
import { get, ApiError } from "../api/client";
import { useAuth } from "../hooks/useAuth";

// ── API types (match src/shieldops/api/routes/firewall_dashboard.py) ─
interface ToolRiskSummary {
  tool_name: string;
  count: number;
  avg_risk: number;
}

interface DashboardStats {
  total_evaluations: number;
  blocked_count: number;
  allowed_count: number;
  review_count: number;
  top_risky_tools: ToolRiskSummary[];
  evaluations_per_hour: Record<string, number>;
}

type Decision = "allow" | "deny" | "review";

interface StreamEntry {
  tool_name: string;
  decision: Decision | string;
  risk_score: number;
  caller: string;
  timestamp: number;
}

interface StreamResponse {
  evaluations: StreamEntry[];
  total: number;
  page: number;
  limit: number;
}

type TabId = "stream" | "tools" | "hourly";

const TABS: { id: TabId; label: string }[] = [
  { id: "stream", label: "Evaluation Stream" },
  { id: "tools", label: "Top Risky Tools" },
  { id: "hourly", label: "Hourly Volume" },
];

const DECISION_COLORS: Record<string, string> = {
  allow: "bg-emerald-500/[0.08] text-emerald-400 ring-emerald-500/15",
  deny: "bg-red-500/[0.08] text-red-400 ring-red-500/15",
  review: "bg-amber-500/[0.08] text-amber-400 ring-amber-500/15",
};

function riskColor(score: number) {
  if (score > 0.8) return "text-red-400";
  if (score >= 0.5) return "text-amber-400";
  return "text-emerald-400";
}

function formatTimestamp(ts: number): string {
  if (!ts) return "—";
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export default function AgentFirewall() {
  const [tab, setTab] = useState<TabId>("stream");
  const { isAuthenticated, orgId } = useAuth();

  const {
    data: stats,
    isLoading: statsLoading,
    error: statsError,
    refetch: refetchStats,
    isFetching: statsFetching,
  } = useQuery<DashboardStats>({
    queryKey: ["firewall", "dashboard", "stats", orgId],
    queryFn: () => get<DashboardStats>("/firewall/dashboard/stats"),
    refetchInterval: 15_000,
    enabled: isAuthenticated,
    retry: (failureCount, err) => {
      if (err instanceof ApiError && (err.status === 401 || err.status === 403)) return false;
      return failureCount < 2;
    },
  });

  const {
    data: stream,
    isLoading: streamLoading,
    error: streamError,
    refetch: refetchStream,
  } = useQuery<StreamResponse>({
    queryKey: ["firewall", "dashboard", "stream", orgId],
    queryFn: () => get<StreamResponse>("/firewall/dashboard/stream?page=1&limit=50"),
    refetchInterval: 15_000,
    enabled: isAuthenticated,
    retry: (failureCount, err) => {
      if (err instanceof ApiError && (err.status === 401 || err.status === 403)) return false;
      return failureCount < 2;
    },
  });

  const handleRefresh = () => {
    refetchStats();
    refetchStream();
  };

  // ── Auth gate ──────────────────────────────────────────────────────
  if (!isAuthenticated) {
    return (
      <div className="space-y-6">
        <PageHeader title="Agent Firewall" description="Real-time monitoring of AI agent tool calls" />
        <EmptyCard
          icon={<Shield className="h-10 w-10 text-gray-600" />}
          title="Sign in to view firewall activity"
          body="The Agent Firewall dashboard is scoped to your organization. Please sign in to continue."
        />
      </div>
    );
  }

  // ── Initial loading ────────────────────────────────────────────────
  if (statsLoading && !stats) {
    return (
      <div className="space-y-6">
        <PageHeader title="Agent Firewall" description="Real-time monitoring of AI agent tool calls" />
        <div className="flex flex-col items-center justify-center rounded-xl border border-white/[0.06] bg-surface-2 py-20">
          <LoadingSpinner size="lg" />
          <p className="mt-4 text-sm text-gray-400">Loading firewall stats…</p>
        </div>
      </div>
    );
  }

  // ── Error state ────────────────────────────────────────────────────
  if (statsError && !stats) {
    const message =
      statsError instanceof ApiError
        ? statsError.message
        : "Unable to reach the firewall API.";
    return (
      <div className="space-y-6">
        <PageHeader title="Agent Firewall" description="Real-time monitoring of AI agent tool calls" />
        <EmptyCard
          icon={<AlertTriangle className="h-10 w-10 text-amber-500/60" />}
          title="Unable to load firewall data"
          body={message}
          action={
            <button onClick={handleRefresh} className="btn-secondary text-xs mt-4">
              <RefreshCw className="h-3.5 w-3.5" /> Retry
            </button>
          }
        />
      </div>
    );
  }

  const total = stats?.total_evaluations ?? 0;
  const blocked = stats?.blocked_count ?? 0;
  const allowed = stats?.allowed_count ?? 0;
  const review = stats?.review_count ?? 0;
  const blockRate = total > 0 ? ((blocked / total) * 100).toFixed(1) : "0.0";

  return (
    <div className="space-y-6">
      <PageHeader
        title="Agent Firewall"
        badge={{
          label: `${total.toLocaleString()} evaluations`,
          variant: blocked > 0 ? "warning" : "info",
        }}
        description="Real-time monitoring and control of AI agent tool calls"
        action={{
          label: "Refresh",
          onClick: handleRefresh,
          icon: <RefreshCw className={clsx("h-4 w-4", statsFetching && "animate-spin")} />,
          loading: statsFetching,
        }}
      />

      {/* Metrics */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard
          label="Total Evaluations"
          value={total.toLocaleString()}
          icon={<Shield className="h-5 w-5" />}
        />
        <MetricCard
          label="Blocked"
          value={blocked.toLocaleString()}
          icon={<XCircle className="h-5 w-5" />}
        />
        <MetricCard
          label="Allowed"
          value={allowed.toLocaleString()}
          icon={<CheckCircle className="h-5 w-5" />}
        />
        <MetricCard
          label="Block Rate"
          value={`${blockRate}%`}
          icon={<Zap className="h-5 w-5" />}
        />
      </div>

      {review > 0 && (
        <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 px-4 py-2 text-xs text-amber-400">
          {review.toLocaleString()} evaluations pending human review.
        </div>
      )}

      {/* Tabs */}
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

      {/* Stream tab */}
      {tab === "stream" && (
        <StreamPanel
          stream={stream}
          loading={streamLoading}
          error={streamError}
          onRetry={refetchStream}
        />
      )}

      {/* Tools tab */}
      {tab === "tools" && <ToolsPanel tools={stats?.top_risky_tools ?? []} />}

      {/* Hourly volume tab */}
      {tab === "hourly" && (
        <HourlyPanel hourly={stats?.evaluations_per_hour ?? {}} />
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

function StreamPanel({
  stream,
  loading,
  error,
  onRetry,
}: {
  stream: StreamResponse | undefined;
  loading: boolean;
  error: unknown;
  onRetry: () => void;
}) {
  if (loading && !stream) {
    return (
      <div className="flex items-center justify-center rounded-xl border border-white/[0.06] bg-surface-2 py-12">
        <Loader2 className="h-5 w-5 animate-spin text-gray-500" />
        <span className="ml-2 text-xs text-gray-500">Loading stream…</span>
      </div>
    );
  }

  if (error && !stream) {
    const message = error instanceof ApiError ? error.message : "Unable to load stream.";
    return (
      <EmptyCard
        icon={<AlertTriangle className="h-10 w-10 text-amber-500/60" />}
        title="Unable to load evaluation stream"
        body={message}
        action={
          <button onClick={onRetry} className="btn-secondary text-xs mt-4">
            <RefreshCw className="h-3.5 w-3.5" /> Retry
          </button>
        }
      />
    );
  }

  const entries = stream?.evaluations ?? [];
  if (entries.length === 0) {
    return (
      <EmptyCard
        icon={<Inbox className="h-10 w-10 text-gray-600" />}
        title="No evaluations recorded yet"
        body="Once your agents start making tool calls, they'll appear here in real time."
      />
    );
  }

  return (
    <div className="overflow-x-auto rounded-xl border border-white/[0.06] bg-surface-2 shadow-depth">
      <table className="w-full text-left text-sm">
        <thead className="border-b border-white/[0.04] text-[11px] font-semibold uppercase tracking-wider text-gray-500">
          <tr>
            <th className="px-5 py-3.5">Time</th>
            <th className="px-5 py-3.5">Caller</th>
            <th className="px-5 py-3.5">Tool</th>
            <th className="px-5 py-3.5">Decision</th>
            <th className="px-5 py-3.5">Risk Score</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-white/[0.04]">
          {entries.map((entry, i) => (
            <tr key={`${entry.timestamp}-${i}`} className="hover:bg-surface-3">
              <td className="px-5 py-3 font-mono text-[12px] text-gray-400">
                {formatTimestamp(entry.timestamp)}
              </td>
              <td className="px-5 py-3 font-mono text-[12px] text-gray-200">
                {entry.caller || "—"}
              </td>
              <td className="px-5 py-3 font-mono text-[12px] text-gray-400">
                {entry.tool_name}
              </td>
              <td className="px-5 py-3">
                <span
                  className={clsx(
                    "inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-[11px] font-medium ring-1 ring-inset",
                    DECISION_COLORS[entry.decision] ?? DECISION_COLORS.allow,
                  )}
                >
                  {entry.decision === "allow" && <CheckCircle className="h-3 w-3" />}
                  {entry.decision === "deny" && <XCircle className="h-3 w-3" />}
                  {entry.decision === "review" && <Flag className="h-3 w-3" />}
                  {entry.decision}
                </span>
              </td>
              <td className="px-5 py-3">
                <span className={clsx("font-semibold", riskColor(entry.risk_score))}>
                  {entry.risk_score.toFixed(3)}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ToolsPanel({ tools }: { tools: ToolRiskSummary[] }) {
  if (tools.length === 0) {
    return (
      <EmptyCard
        icon={<Inbox className="h-10 w-10 text-gray-600" />}
        title="No tool activity yet"
        body="Risk rankings will appear once agents begin calling tools through the firewall."
      />
    );
  }
  return (
    <div className="overflow-x-auto rounded-xl border border-white/[0.06] bg-surface-2 shadow-depth">
      <table className="w-full text-left text-sm">
        <thead className="border-b border-white/[0.04] text-[11px] font-semibold uppercase tracking-wider text-gray-500">
          <tr>
            <th className="px-5 py-3.5">Tool</th>
            <th className="px-5 py-3.5">Calls</th>
            <th className="px-5 py-3.5">Avg Risk</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-white/[0.04]">
          {tools.map((t) => (
            <tr key={t.tool_name} className="hover:bg-surface-3">
              <td className="px-5 py-3.5 font-mono text-[12px] text-gray-200">{t.tool_name}</td>
              <td className="px-5 py-3.5 text-gray-300">{t.count.toLocaleString()}</td>
              <td className="px-5 py-3.5">
                <span className={clsx("font-semibold", riskColor(t.avg_risk))}>
                  {t.avg_risk.toFixed(3)}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function HourlyPanel({ hourly }: { hourly: Record<string, number> }) {
  const entries = Object.entries(hourly).sort(([a], [b]) => b.localeCompare(a));
  if (entries.length === 0) {
    return (
      <EmptyCard
        icon={<Inbox className="h-10 w-10 text-gray-600" />}
        title="No hourly data yet"
        body="Evaluation volume histograms will appear once firewall traffic is recorded."
      />
    );
  }
  const max = Math.max(...entries.map(([, v]) => v), 1);
  return (
    <div className="space-y-2 rounded-xl border border-white/[0.06] bg-surface-2 p-5 shadow-depth">
      {entries.map(([hour, count]) => (
        <div key={hour} className="flex items-center gap-3">
          <span className="w-40 shrink-0 font-mono text-[11px] text-gray-500">{hour}</span>
          <div className="flex-1 overflow-hidden rounded-full bg-white/[0.04]">
            <div
              className="h-2 rounded-full bg-brand-500/70"
              style={{ width: `${(count / max) * 100}%` }}
            />
          </div>
          <span className="w-16 text-right font-mono text-[11px] text-gray-300">
            {count.toLocaleString()}
          </span>
        </div>
      ))}
    </div>
  );
}
