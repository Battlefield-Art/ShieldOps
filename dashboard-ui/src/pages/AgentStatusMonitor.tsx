import { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  CheckCircle,
  AlertTriangle,
  Loader2,
  Moon,
  RefreshCw,
  ChevronDown,
  ChevronRight,
  Plug,
} from "lucide-react";
import clsx from "clsx";
import { get } from "../api/client";
import PageHeader from "../components/PageHeader";
import MetricCard from "../components/MetricCard";
import LoadingSpinner from "../components/LoadingSpinner";

// ── Types ─────────────────────────────────────────────────────────

type AgentStatus = "running" | "healthy" | "error" | "idle";

interface AgentStatusItem {
  agent_name: string;
  status: AgentStatus;
  last_run: string | null;
  success_rate: number;
  total_runs: number;
  recent_errors: string[];
}

interface AgentStatusListResponse {
  agents: AgentStatusItem[];
}

interface AgentRunSummary {
  id: string;
  status: string;
  duration_ms: number;
  error_message: string | null;
  created_at: string;
}

interface AgentHistoryResponse {
  agent_name: string;
  runs: AgentRunSummary[];
}

interface ConnectorHealthItem {
  name: string;
  status: "healthy" | "degraded" | "unavailable" | "unknown";
  latency_ms: number;
  message: string;
  last_checked: string | null;
}

interface AgentConnectorsResponse {
  agent_name: string;
  connectors: ConnectorHealthItem[];
}

// ── Helpers ────────────────────────────────────────────────────────

function prettyAgentName(name: string): string {
  return name
    .split("_")
    .map((s) => s.charAt(0).toUpperCase() + s.slice(1))
    .join(" ");
}

function relativeTime(iso: string | null): string {
  if (!iso) return "never";
  const diffMs = Date.now() - new Date(iso).getTime();
  const sec = Math.floor(diffMs / 1000);
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const days = Math.floor(hr / 24);
  return `${days}d ago`;
}

const STATUS_DOT: Record<AgentStatus, string> = {
  running: "bg-blue-400",
  healthy: "bg-emerald-400",
  error: "bg-red-400",
  idle: "bg-gray-500",
};

const STATUS_LABEL: Record<AgentStatus, string> = {
  running: "Running",
  healthy: "Healthy",
  error: "Error",
  idle: "Idle",
};

const CONNECTOR_STATUS_COLOR: Record<ConnectorHealthItem["status"], string> = {
  healthy: "text-emerald-400",
  degraded: "text-amber-400",
  unavailable: "text-red-400",
  unknown: "text-gray-500",
};

function successRateColor(rate: number): string {
  if (rate >= 0.9) return "text-emerald-400";
  if (rate >= 0.7) return "text-amber-400";
  return "text-red-400";
}

// ── Expanded detail panel ──────────────────────────────────────────

function AgentDetailPanel({ agentName }: { agentName: string }) {
  const historyQuery = useQuery({
    queryKey: ["agent-status", "history", agentName],
    queryFn: () =>
      get<AgentHistoryResponse>(`/agents/status/${agentName}/history`),
    refetchInterval: 30_000,
  });

  const connectorsQuery = useQuery({
    queryKey: ["agent-status", "connectors", agentName],
    queryFn: () =>
      get<AgentConnectorsResponse>(`/agents/status/${agentName}/connectors`),
    refetchInterval: 30_000,
  });

  return (
    <div className="grid grid-cols-1 gap-4 border-t border-white/[0.06] bg-surface-1 px-5 py-5 lg:grid-cols-2">
      {/* Execution history */}
      <div>
        <div className="mb-3 flex items-center gap-2">
          <Activity className="h-4 w-4 text-brand-400" />
          <h3 className="text-sm font-semibold text-gray-200">
            Recent Executions
          </h3>
        </div>
        {historyQuery.isLoading ? (
          <LoadingSpinner size="sm" className="py-6" />
        ) : historyQuery.isError ? (
          <p className="text-xs text-red-400">Failed to load history.</p>
        ) : historyQuery.data?.runs.length === 0 ? (
          <p className="text-xs text-gray-500">No executions recorded yet.</p>
        ) : (
          <ul className="space-y-2">
            {historyQuery.data?.runs.map((run) => (
              <li
                key={run.id}
                className="flex items-start justify-between gap-3 rounded-lg border border-white/[0.06] bg-surface-2 px-3 py-2"
              >
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span
                      className={clsx(
                        "text-xs font-medium uppercase tracking-wide",
                        run.status === "completed" && "text-emerald-400",
                        run.status === "failed" && "text-red-400",
                        run.status === "running" && "text-blue-400",
                        run.status === "pending" && "text-gray-400",
                      )}
                    >
                      {run.status}
                    </span>
                    <span className="font-mono text-[10px] text-gray-500">
                      {run.id.slice(0, 12)}
                    </span>
                  </div>
                  {run.error_message && (
                    <p className="mt-1 truncate text-[11px] text-red-300/80">
                      {run.error_message}
                    </p>
                  )}
                </div>
                <div className="text-right text-[11px] text-gray-500">
                  <div>{relativeTime(run.created_at)}</div>
                  <div className="font-mono">{run.duration_ms}ms</div>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* Connectors */}
      <div>
        <div className="mb-3 flex items-center gap-2">
          <Plug className="h-4 w-4 text-brand-400" />
          <h3 className="text-sm font-semibold text-gray-200">
            Connector Dependencies
          </h3>
        </div>
        {connectorsQuery.isLoading ? (
          <LoadingSpinner size="sm" className="py-6" />
        ) : connectorsQuery.isError ? (
          <p className="text-xs text-red-400">Failed to load connectors.</p>
        ) : connectorsQuery.data?.connectors.length === 0 ? (
          <p className="text-xs text-gray-500">No connector dependencies.</p>
        ) : (
          <ul className="space-y-2">
            {connectorsQuery.data?.connectors.map((c) => (
              <li
                key={c.name}
                className="flex items-start justify-between gap-3 rounded-lg border border-white/[0.06] bg-surface-2 px-3 py-2"
              >
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <div
                      className={clsx(
                        "h-2 w-2 rounded-full",
                        c.status === "healthy" && "bg-emerald-400",
                        c.status === "degraded" && "bg-amber-400",
                        c.status === "unavailable" && "bg-red-400",
                        c.status === "unknown" && "bg-gray-500",
                      )}
                    />
                    <span className="text-xs font-medium text-gray-200">
                      {c.name}
                    </span>
                    <span
                      className={clsx(
                        "text-[10px] uppercase tracking-wide",
                        CONNECTOR_STATUS_COLOR[c.status],
                      )}
                    >
                      {c.status}
                    </span>
                  </div>
                  {c.message && (
                    <p className="mt-1 truncate text-[11px] text-gray-500">
                      {c.message}
                    </p>
                  )}
                </div>
                {c.latency_ms > 0 && (
                  <span className="font-mono text-[11px] text-gray-500">
                    {Math.round(c.latency_ms)}ms
                  </span>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

// ── Main Page ──────────────────────────────────────────────────────

export default function AgentStatusMonitor() {
  const [expanded, setExpanded] = useState<string | null>(null);

  const { data, isLoading, isError, refetch, isFetching } = useQuery({
    queryKey: ["agent-status", "list"],
    queryFn: () => get<AgentStatusListResponse>("/agents/status"),
    refetchInterval: 30_000,
  });

  const summary = useMemo(() => {
    const agents = data?.agents ?? [];
    return {
      healthy: agents.filter((a) => a.status === "healthy").length,
      running: agents.filter((a) => a.status === "running").length,
      errors: agents.filter((a) => a.status === "error").length,
      idle: agents.filter((a) => a.status === "idle").length,
    };
  }, [data]);

  function toggle(name: string) {
    setExpanded((curr) => (curr === name ? null : name));
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Agent Status Monitor"
        description="Real-time status of the 10 launch agents — execution state, success rate, and connector health."
        action={{
          label: isFetching ? "Refreshing…" : "Refresh",
          onClick: () => refetch(),
          icon: <RefreshCw className="h-4 w-4" />,
          loading: isFetching,
        }}
      />

      {/* Summary tiles */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <MetricCard
          label="Healthy"
          value={summary.healthy}
          icon={<CheckCircle className="h-5 w-5 text-emerald-400" />}
        />
        <MetricCard
          label="Running"
          value={summary.running}
          icon={<Loader2 className="h-5 w-5 text-blue-400" />}
        />
        <MetricCard
          label="Errors"
          value={summary.errors}
          icon={<AlertTriangle className="h-5 w-5 text-red-400" />}
        />
        <MetricCard
          label="Idle"
          value={summary.idle}
          icon={<Moon className="h-5 w-5 text-gray-400" />}
        />
      </div>

      {/* Loading / error states */}
      {isLoading && <LoadingSpinner size="lg" className="mt-20" />}

      {isError && (
        <div className="rounded-xl border border-red-500/20 bg-red-500/10 p-6 text-center">
          <p className="text-sm text-red-400">
            Failed to load agent status. Please try refreshing.
          </p>
        </div>
      )}

      {/* Agent grid */}
      {data && !isLoading && !isError && (
        <div className="rounded-xl border border-white/[0.06] bg-surface-2">
          <div className="border-b border-white/[0.06] px-5 py-3">
            <h2 className="text-sm font-semibold text-gray-200">
              Launch Agents ({data.agents.length})
            </h2>
          </div>
          <ul className="divide-y divide-white/[0.04]">
            {data.agents.map((agent) => {
              const isOpen = expanded === agent.agent_name;
              const pct = Math.round(agent.success_rate * 100);
              return (
                <li key={agent.agent_name}>
                  <button
                    type="button"
                    onClick={() => toggle(agent.agent_name)}
                    className={clsx(
                      "flex w-full items-center gap-4 px-5 py-4 text-left transition-colors",
                      "hover:bg-white/[0.03]",
                    )}
                  >
                    {isOpen ? (
                      <ChevronDown className="h-4 w-4 text-gray-500" />
                    ) : (
                      <ChevronRight className="h-4 w-4 text-gray-500" />
                    )}
                    <div
                      className={clsx(
                        "h-2.5 w-2.5 shrink-0 rounded-full",
                        STATUS_DOT[agent.status],
                        agent.status === "running" && "animate-pulse",
                      )}
                    />
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium text-gray-100">
                          {prettyAgentName(agent.agent_name)}
                        </span>
                        <span className="text-[10px] uppercase tracking-wide text-gray-500">
                          {STATUS_LABEL[agent.status]}
                        </span>
                      </div>
                      <div className="mt-0.5 text-xs text-gray-500">
                        Last run: {relativeTime(agent.last_run)}
                      </div>
                    </div>
                    <div className="hidden text-right sm:block">
                      <div
                        className={clsx(
                          "text-sm font-semibold",
                          successRateColor(agent.success_rate),
                        )}
                      >
                        {agent.total_runs === 0 ? "—" : `${pct}%`}
                      </div>
                      <div className="text-[11px] text-gray-500">
                        success rate
                      </div>
                    </div>
                    <div className="hidden w-20 text-right md:block">
                      <div className="text-sm font-semibold text-gray-200">
                        {agent.total_runs.toLocaleString()}
                      </div>
                      <div className="text-[11px] text-gray-500">
                        total runs
                      </div>
                    </div>
                  </button>
                  {isOpen && <AgentDetailPanel agentName={agent.agent_name} />}
                </li>
              );
            })}
          </ul>
        </div>
      )}
    </div>
  );
}
