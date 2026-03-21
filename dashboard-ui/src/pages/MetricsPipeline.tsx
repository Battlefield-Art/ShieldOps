import { useState } from "react";
import { Activity, BarChart3, AlertTriangle, Gauge } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

const SERVICES = [
  { service: "payment-api", source: "prometheus", metrics: 342, cardinality: 12400, interval: "15s", status: "healthy" },
  { service: "auth-service", source: "otlp", metrics: 187, cardinality: 5600, interval: "30s", status: "healthy" },
  { service: "order-processor", source: "prometheus", metrics: 256, cardinality: 18900, interval: "15s", status: "high_cardinality" },
  { service: "notification-svc", source: "statsd", metrics: 94, cardinality: 2100, interval: "10s", status: "healthy" },
  { service: "search-engine", source: "otlp", metrics: 412, cardinality: 31200, interval: "30s", status: "high_cardinality" },
  { service: "user-profile", source: "prometheus", metrics: 128, cardinality: 3800, interval: "15s", status: "healthy" },
  { service: "cdn-edge", source: "statsd", metrics: 67, cardinality: 1400, interval: "60s", status: "degraded" },
];

const SOURCE_COLORS: Record<string, string> = {
  prometheus: "bg-orange-500/10 text-orange-400 ring-orange-500/20",
  otlp: "bg-cyan-500/10 text-cyan-400 ring-cyan-500/20",
  statsd: "bg-green-500/10 text-green-400 ring-green-500/20",
};

export default function MetricsPipeline() {
  const [running, setRunning] = useState(false);
  const handleClick = () => { setRunning(true); setTimeout(() => setRunning(false), 2000); };

  return (
    <div className="space-y-6">
      <PageHeader
        title="OTel Metrics Pipeline"
        action={{
          label: "Discover Endpoints",
          onClick: handleClick,
          loading: running,
        }}
      />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard label="Metric Endpoints" value={23} icon={<Activity className="h-5 w-5" />} change={4.5} />
        <MetricCard label="Total Series" value={"75.4K"} icon={<BarChart3 className="h-5 w-5" />} change={12.3} />
        <MetricCard label="High Cardinality Count" value={2} icon={<AlertTriangle className="h-5 w-5" />} change={-33.0} />
        <MetricCard label="Golden Signals %" value={96} icon={<Gauge className="h-5 w-5" />} change={2.1} />
      </div>

      <div className="overflow-x-auto rounded-xl border border-gray-800/80 bg-gray-900 shadow-card">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-gray-800/60 text-left text-[11px] font-semibold uppercase tracking-wider text-gray-400">
            <tr>
              <th className="px-5 py-3.5">Service</th>
              <th className="px-5 py-3.5">Source</th>
              <th className="px-5 py-3.5">Metrics Count</th>
              <th className="px-5 py-3.5">Cardinality</th>
              <th className="px-5 py-3.5">Scrape Interval</th>
              <th className="px-5 py-3.5">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800/40">
            {SERVICES.map((s) => (
              <tr key={s.service} className="hover:bg-gray-800/30">
                <td className="px-5 py-3.5 font-medium">{s.service}</td>
                <td className="px-5 py-3.5">
                  <span className={clsx("inline-flex rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset", SOURCE_COLORS[s.source])}>{s.source}</span>
                </td>
                <td className="px-5 py-3.5 text-gray-300">{s.metrics}</td>
                <td className="px-5 py-3.5 text-gray-300">{s.cardinality.toLocaleString()}</td>
                <td className="px-5 py-3.5 text-gray-300">{s.interval}</td>
                <td className="px-5 py-3.5"><StatusBadge status={s.status} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
