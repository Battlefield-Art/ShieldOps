import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from "recharts";
import {
  Activity,
  AlertTriangle,
  Database,
  DollarSign,
  ShieldCheck,
  Timer,
} from "lucide-react";
import clsx from "clsx";
import { get } from "../api/client";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import LoadingSpinner from "../components/LoadingSpinner";

// ── Types ────────────────────────────────────────────────────────

interface BusinessMetricsResponse {
  range: string;
  mttd_seconds: number;
  mttr_seconds: number;
  cost_per_incident_usd: number;
  risk_score: number;
  data_volume_gb: number;
  agent_roi_percent: number;
  incidents_total: number;
  incidents_auto_resolved: number;
}

interface TrendPoint {
  bucket: string;
  value: number;
}

interface BusinessTrendsResponse {
  range: string;
  metric: string;
  granularity: "hour" | "day";
  points: TrendPoint[];
}

type RangeValue = "24h" | "7d" | "30d";

const RANGES: { label: string; value: RangeValue }[] = [
  { label: "24h", value: "24h" },
  { label: "7d", value: "7d" },
  { label: "30d", value: "30d" },
];

// Auto-refresh every 5 minutes as required by issue #207.
const REFRESH_MS = 5 * 60 * 1000;

// ── Helpers ──────────────────────────────────────────────────────

const fmtSeconds = (n: number) => {
  if (n < 60) return `${n.toFixed(1)}s`;
  if (n < 3600) return `${(n / 60).toFixed(1)}m`;
  return `${(n / 3600).toFixed(2)}h`;
};
const fmtUsd = (n: number) => `$${n.toFixed(2)}`;
const fmtPct = (n: number) => `${n.toFixed(1)}%`;
const fmtGb = (n: number) => {
  if (n >= 1024) return `${(n / 1024).toFixed(2)} TB`;
  if (n >= 1) return `${n.toFixed(2)} GB`;
  if (n >= 1 / 1024) return `${(n * 1024).toFixed(2)} MB`;
  return `${(n * 1024 * 1024).toFixed(0)} KB`;
};
const fmtRisk = (n: number) => n.toFixed(0);

const riskLabel = (n: number) => {
  if (n >= 70) return "elevated";
  if (n >= 40) return "moderate";
  return "low";
};

// ── Component ────────────────────────────────────────────────────

export default function BusinessValue() {
  const [range, setRange] = useState<RangeValue>("7d");

  const snapshotQ = useQuery<BusinessMetricsResponse>({
    queryKey: ["business-metrics", range],
    queryFn: () =>
      get<BusinessMetricsResponse>(`/metrics/business?range=${range}`),
    refetchInterval: REFRESH_MS,
  });

  const mttdTrendQ = useQuery<BusinessTrendsResponse>({
    queryKey: ["business-trends", "mttd", range],
    queryFn: () =>
      get<BusinessTrendsResponse>(
        `/metrics/business/trends?metric=mttd&range=${range}`,
      ),
    refetchInterval: REFRESH_MS,
  });

  const mttrTrendQ = useQuery<BusinessTrendsResponse>({
    queryKey: ["business-trends", "mttr", range],
    queryFn: () =>
      get<BusinessTrendsResponse>(
        `/metrics/business/trends?metric=mttr&range=${range}`,
      ),
    refetchInterval: REFRESH_MS,
  });

  const costTrendQ = useQuery<BusinessTrendsResponse>({
    queryKey: ["business-trends", "cost", range],
    queryFn: () =>
      get<BusinessTrendsResponse>(
        `/metrics/business/trends?metric=cost&range=${range}`,
      ),
    refetchInterval: REFRESH_MS,
  });

  const riskTrendQ = useQuery<BusinessTrendsResponse>({
    queryKey: ["business-trends", "risk", range],
    queryFn: () =>
      get<BusinessTrendsResponse>(
        `/metrics/business/trends?metric=risk&range=${range}`,
      ),
    refetchInterval: REFRESH_MS,
  });

  const snapshot = snapshotQ.data;
  const isLoading = snapshotQ.isLoading;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Business Value"
        description="Executive view of MTTD, MTTR, cost, risk, data volume, and agent ROI"
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
          {snapshot &&
            `${snapshot.incidents_total.toLocaleString()} incidents · ${snapshot.incidents_auto_resolved.toLocaleString()} auto-resolved`}
        </div>
      </div>

      {isLoading && (
        <div className="flex justify-center py-12">
          <LoadingSpinner />
        </div>
      )}

      {/* 6-metric card grid */}
      {snapshot && (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <MetricCard
            icon={<Timer className="h-4 w-4" />}
            label="MTTD"
            value={fmtSeconds(snapshot.mttd_seconds)}
            description="mean time to detect"
          />
          <MetricCard
            icon={<Activity className="h-4 w-4" />}
            label="MTTR"
            value={fmtSeconds(snapshot.mttr_seconds)}
            description="mean time to remediate"
          />
          <MetricCard
            icon={<DollarSign className="h-4 w-4" />}
            label="Cost / Incident"
            value={fmtUsd(snapshot.cost_per_incident_usd)}
            description="LLM + analyst blended"
          />
          <MetricCard
            icon={<AlertTriangle className="h-4 w-4" />}
            label="Risk Score"
            value={fmtRisk(snapshot.risk_score)}
            description={`composite 0-100 · ${riskLabel(snapshot.risk_score)}`}
          />
          <MetricCard
            icon={<Database className="h-4 w-4" />}
            label="Data Volume"
            value={fmtGb(snapshot.data_volume_gb)}
            description="ingested in window"
          />
          <MetricCard
            icon={<ShieldCheck className="h-4 w-4" />}
            label="Agent ROI"
            value={fmtPct(snapshot.agent_roi_percent)}
            description="auto-resolved share"
          />
        </div>
      )}

      {/* Trend charts */}
      <section className="space-y-6">
        <h2 className="section-heading">Trends ({range})</h2>

        <TrendChart
          title="MTTD Over Time (seconds)"
          data={mttdTrendQ.data?.points}
          color="#06b6d4"
        />
        <TrendChart
          title="MTTR Over Time (seconds)"
          data={mttrTrendQ.data?.points}
          color="#3b82f6"
        />
        <TrendChart
          title="Cost per Incident ($)"
          data={costTrendQ.data?.points}
          color="#22c55e"
        />
        <TrendChart
          title="Risk Score Over Time"
          data={riskTrendQ.data?.points}
          color="#f59e0b"
          domain={[0, 100]}
        />
      </section>

      {!isLoading && snapshot && snapshot.incidents_total === 0 && (
        <div className="card-surface text-center text-white/60">
          No incident activity recorded in the selected window.
        </div>
      )}
    </div>
  );
}

// ── Subcomponent ─────────────────────────────────────────────────

interface TrendChartProps {
  title: string;
  data: TrendPoint[] | undefined;
  color: string;
  domain?: [number, number];
}

function TrendChart({ title, data, color, domain }: TrendChartProps) {
  const points = data ?? [];
  return (
    <div className="card-surface">
      <h3 className="mb-2 text-sm font-semibold text-white/80">{title}</h3>
      {points.length === 0 ? (
        <div className="flex h-[220px] items-center justify-center text-xs text-white/40">
          No data in selected window
        </div>
      ) : (
        <div style={{ width: "100%", height: 220 }}>
          <ResponsiveContainer>
            <LineChart data={points}>
              <CartesianGrid stroke="rgba(255,255,255,0.08)" />
              <XAxis
                dataKey="bucket"
                stroke="rgba(255,255,255,0.5)"
                fontSize={11}
                tickFormatter={(v: string) => v.slice(5, 16)}
              />
              <YAxis
                domain={domain}
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
              <Line
                type="monotone"
                dataKey="value"
                stroke={color}
                strokeWidth={2}
                dot={false}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
}
