import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  ResponsiveContainer,
  LineChart,
  Line,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
} from "recharts";
import { CheckCircle, Clock, DollarSign, Layers, Zap } from "lucide-react";
import clsx from "clsx";
import { get } from "../api/client";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import LoadingSpinner from "../components/LoadingSpinner";

// ── Types ────────────────────────────────────────────────────────

interface AgentMetric {
  agent_name: string;
  total_runs: number;
  success_count: number;
  failure_count: number;
  success_rate: number;
  avg_duration_ms: number;
  max_duration_ms: number;
  total_tokens: number;
  estimated_cost_usd: number;
}

interface AgentMetricsResponse {
  range: string;
  agents: AgentMetric[];
}

interface FleetMetricsResponse {
  range: string;
  total_agents: number;
  total_runs: number;
  total_success: number;
  total_failure: number;
  fleet_success_rate: number;
  avg_duration_ms: number;
  total_tokens: number;
  estimated_cost_usd: number;
}

interface TrendPoint {
  bucket: string | null;
  agent_name: string;
  runs: number;
  success_rate: number;
  avg_duration_ms: number;
  total_tokens: number;
}

interface TrendsResponse {
  range: string;
  granularity: "hour" | "day";
  points: TrendPoint[];
}

type RangeValue = "1h" | "6h" | "24h" | "7d" | "30d";
type TrendRangeValue = "24h" | "7d" | "30d";

const RANGES: { label: string; value: RangeValue }[] = [
  { label: "1h", value: "1h" },
  { label: "6h", value: "6h" },
  { label: "24h", value: "24h" },
  { label: "7d", value: "7d" },
  { label: "30d", value: "30d" },
];

const AGENT_COLORS = [
  "#06b6d4", // cyan
  "#3b82f6", // blue
  "#22c55e", // green
  "#f59e0b", // amber
  "#a855f7", // purple
  "#ef4444", // red
  "#14b8a6", // teal
  "#eab308", // yellow
  "#ec4899", // pink
  "#8b5cf6", // violet
];

// ── Helpers ──────────────────────────────────────────────────────

const fmtPct = (n: number) => `${(n * 100).toFixed(1)}%`;
const fmtMs = (n: number) => {
  if (n < 1000) return `${n.toFixed(0)}ms`;
  return `${(n / 1000).toFixed(2)}s`;
};
const fmtNum = (n: number) => n.toLocaleString();
const fmtCost = (n: number) => `$${n.toFixed(2)}`;
const fmtTokens = (n: number) => {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(2)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return n.toFixed(0);
};

// ── Component ────────────────────────────────────────────────────

export default function AgentMetrics() {
  const [range, setRange] = useState<RangeValue>("24h");
  const [selected, setSelected] = useState<string[]>([]);

  const metricsQ = useQuery<AgentMetricsResponse>({
    queryKey: ["agent-metrics", range],
    queryFn: () => get<AgentMetricsResponse>(`/agents/metrics?range=${range}`),
  });

  const fleetQ = useQuery<FleetMetricsResponse>({
    queryKey: ["agent-metrics-fleet", range],
    queryFn: () =>
      get<FleetMetricsResponse>(`/agents/metrics/fleet?range=${range}`),
  });

  // Trends endpoint only supports 24h/7d/30d; upscale 1h/6h to 24h.
  const trendRange: TrendRangeValue = useMemo(() => {
    if (range === "1h" || range === "6h" || range === "24h") return "24h";
    return range;
  }, [range]);

  const trendsQ = useQuery<TrendsResponse>({
    queryKey: ["agent-metrics-trends", trendRange],
    queryFn: () =>
      get<TrendsResponse>(`/agents/metrics/trends?range=${trendRange}`),
  });

  const agents = metricsQ.data?.agents ?? [];
  const fleet = fleetQ.data;

  // Pivot trend points → [{bucket, agentA: val, agentB: val, ...}]
  const trendSeries = useMemo(() => {
    const points = trendsQ.data?.points ?? [];
    const byBucket = new Map<string, Record<string, number | string>>();
    for (const p of points) {
      const key = p.bucket ?? "";
      if (!byBucket.has(key)) byBucket.set(key, { bucket: key });
      const row = byBucket.get(key)!;
      row[`${p.agent_name}__success`] = p.success_rate * 100;
      row[`${p.agent_name}__duration`] = p.avg_duration_ms;
      row[`${p.agent_name}__runs`] = p.runs;
    }
    return Array.from(byBucket.values()).sort((a, b) =>
      String(a.bucket).localeCompare(String(b.bucket)),
    );
  }, [trendsQ.data]);

  const agentNames = useMemo(
    () => agents.map((a) => a.agent_name),
    [agents],
  );

  const activeAgents = selected.length > 0 ? selected : agentNames.slice(0, 5);

  const toggleAgent = (name: string) => {
    setSelected((prev) =>
      prev.includes(name) ? prev.filter((n) => n !== name) : [...prev, name],
    );
  };

  const isLoading = metricsQ.isLoading || fleetQ.isLoading;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Agent Metrics"
        description="Per-agent success, latency, tokens, and cost across the fleet"
      />

      {/* Time range selector */}
      <div className="flex items-center justify-between">
        <div className="tab-bar inline-flex gap-1">
          {RANGES.map((r) => (
            <button
              key={r.value}
              type="button"
              onClick={() => setRange(r.value)}
              className={clsx(
                "rounded px-3 py-1.5 text-sm font-medium transition-colors",
                range === r.value
                  ? "bg-cyan-500/15 text-cyan-300"
                  : "text-white/60 hover:text-white/90",
              )}
            >
              {r.label}
            </button>
          ))}
        </div>
        <div className="text-xs text-white/50">
          {fleet && `${fleet.total_agents} agents · ${fmtNum(fleet.total_runs)} runs`}
        </div>
      </div>

      {isLoading && (
        <div className="flex justify-center py-12">
          <LoadingSpinner />
        </div>
      )}

      {/* Fleet summary */}
      {fleet && (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-5">
          <MetricCard
            icon={<Layers className="h-4 w-4" />}
            label="Active Agents"
            value={fmtNum(fleet.total_agents)}
            description={`${fmtNum(fleet.total_runs)} runs`}
          />
          <MetricCard
            icon={<CheckCircle className="h-4 w-4" />}
            label="Fleet Success Rate"
            value={fmtPct(fleet.fleet_success_rate)}
            description={`${fmtNum(fleet.total_failure)} failures`}
          />
          <MetricCard
            icon={<Clock className="h-4 w-4" />}
            label="Avg Duration"
            value={fmtMs(fleet.avg_duration_ms)}
            description="across all agents"
          />
          <MetricCard
            icon={<Zap className="h-4 w-4" />}
            label="Total Tokens"
            value={fmtTokens(fleet.total_tokens)}
            description="prompt + completion"
          />
          <MetricCard
            icon={<DollarSign className="h-4 w-4" />}
            label="Estimated Cost"
            value={fmtCost(fleet.estimated_cost_usd)}
            description="blended LLM rate"
          />
        </div>
      )}

      {/* Per-agent cards */}
      {agents.length > 0 && (
        <section>
          <h2 className="section-heading mb-3">Per-Agent Metrics</h2>
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
            {agents.map((a, i) => {
              const color = AGENT_COLORS[i % AGENT_COLORS.length];
              const isSelected = selected.includes(a.agent_name);
              return (
                <button
                  key={a.agent_name}
                  type="button"
                  onClick={() => toggleAgent(a.agent_name)}
                  className={clsx(
                    "card-interactive text-left",
                    isSelected && "ring-2 ring-cyan-400/60",
                  )}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span
                        className="h-2 w-2 rounded-full"
                        style={{ backgroundColor: color }}
                      />
                      <span className="font-mono text-sm font-semibold text-white">
                        {a.agent_name}
                      </span>
                    </div>
                    <span
                      className={clsx(
                        "rounded px-2 py-0.5 text-xs font-medium",
                        a.success_rate >= 0.95
                          ? "bg-emerald-500/15 text-emerald-300"
                          : a.success_rate >= 0.8
                            ? "bg-amber-500/15 text-amber-300"
                            : "bg-rose-500/15 text-rose-300",
                      )}
                    >
                      {fmtPct(a.success_rate)}
                    </span>
                  </div>
                  <div className="mt-4 grid grid-cols-2 gap-3 text-xs">
                    <div>
                      <div className="text-white/50">Runs</div>
                      <div className="font-mono text-white">
                        {fmtNum(a.total_runs)}
                      </div>
                    </div>
                    <div>
                      <div className="text-white/50">Avg Duration</div>
                      <div className="font-mono text-white">
                        {fmtMs(a.avg_duration_ms)}
                      </div>
                    </div>
                    <div>
                      <div className="text-white/50">Tokens</div>
                      <div className="font-mono text-white">
                        {fmtTokens(a.total_tokens)}
                      </div>
                    </div>
                    <div>
                      <div className="text-white/50">Cost</div>
                      <div className="font-mono text-white">
                        {fmtCost(a.estimated_cost_usd)}
                      </div>
                    </div>
                  </div>
                </button>
              );
            })}
          </div>
          <p className="mt-2 text-xs text-white/40">
            Click agent cards to compare them in the trend charts below.
          </p>
        </section>
      )}

      {/* Trend charts */}
      {trendSeries.length > 0 && (
        <section className="space-y-6">
          <h2 className="section-heading">Trends ({trendRange})</h2>

          <div className="card-surface">
            <h3 className="mb-2 text-sm font-semibold text-white/80">
              Success Rate Over Time (%)
            </h3>
            <div style={{ width: "100%", height: 260 }}>
              <ResponsiveContainer>
                <LineChart data={trendSeries}>
                  <CartesianGrid stroke="rgba(255,255,255,0.08)" />
                  <XAxis
                    dataKey="bucket"
                    stroke="rgba(255,255,255,0.5)"
                    fontSize={11}
                  />
                  <YAxis
                    domain={[0, 100]}
                    stroke="rgba(255,255,255,0.5)"
                    fontSize={11}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "rgba(12,18,28,0.95)",
                      border: "1px solid rgba(255,255,255,0.12)",
                      borderRadius: 6,
                    }}
                  />
                  <Legend />
                  {activeAgents.map((name, i) => (
                    <Line
                      key={name}
                      type="monotone"
                      dataKey={`${name}__success`}
                      name={name}
                      stroke={AGENT_COLORS[i % AGENT_COLORS.length]}
                      strokeWidth={2}
                      dot={false}
                    />
                  ))}
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="card-surface">
            <h3 className="mb-2 text-sm font-semibold text-white/80">
              Average Latency (ms)
            </h3>
            <div style={{ width: "100%", height: 260 }}>
              <ResponsiveContainer>
                <LineChart data={trendSeries}>
                  <CartesianGrid stroke="rgba(255,255,255,0.08)" />
                  <XAxis
                    dataKey="bucket"
                    stroke="rgba(255,255,255,0.5)"
                    fontSize={11}
                  />
                  <YAxis stroke="rgba(255,255,255,0.5)" fontSize={11} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "rgba(12,18,28,0.95)",
                      border: "1px solid rgba(255,255,255,0.12)",
                      borderRadius: 6,
                    }}
                  />
                  <Legend />
                  {activeAgents.map((name, i) => (
                    <Line
                      key={name}
                      type="monotone"
                      dataKey={`${name}__duration`}
                      name={name}
                      stroke={AGENT_COLORS[i % AGENT_COLORS.length]}
                      strokeWidth={2}
                      dot={false}
                    />
                  ))}
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="card-surface">
            <h3 className="mb-2 text-sm font-semibold text-white/80">
              Runs per Bucket
            </h3>
            <div style={{ width: "100%", height: 260 }}>
              <ResponsiveContainer>
                <BarChart data={trendSeries}>
                  <CartesianGrid stroke="rgba(255,255,255,0.08)" />
                  <XAxis
                    dataKey="bucket"
                    stroke="rgba(255,255,255,0.5)"
                    fontSize={11}
                  />
                  <YAxis stroke="rgba(255,255,255,0.5)" fontSize={11} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "rgba(12,18,28,0.95)",
                      border: "1px solid rgba(255,255,255,0.12)",
                      borderRadius: 6,
                    }}
                  />
                  <Legend />
                  {activeAgents.map((name, i) => (
                    <Bar
                      key={name}
                      dataKey={`${name}__runs`}
                      name={name}
                      fill={AGENT_COLORS[i % AGENT_COLORS.length]}
                      stackId="runs"
                    />
                  ))}
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </section>
      )}

      {!isLoading && agents.length === 0 && (
        <div className="card-surface text-center text-white/60">
          No agent runs recorded in the selected window.
        </div>
      )}
    </div>
  );
}
