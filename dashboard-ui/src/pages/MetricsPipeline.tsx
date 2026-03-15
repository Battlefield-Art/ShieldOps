import { useState } from "react";
import { Activity, BarChart3, AlertTriangle, Gauge, Loader2 } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";

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

const STATUS_COLORS: Record<string, string> = {
  healthy: "text-green-400",
  high_cardinality: "text-amber-400",
  degraded: "text-red-400",
};

export default function MetricsPipeline() {
  const [running, setRunning] = useState(false);
  const handleClick = () => { setRunning(true); setTimeout(() => setRunning(false), 2000); };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">OTel Metrics Pipeline</h1>
        <button onClick={handleClick} disabled={running} className="flex items-center gap-2 rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-500 disabled:opacity-50">
          {running && <Loader2 className="h-4 w-4 animate-spin" />}
          Discover Endpoints
        </button>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard label="Metric Endpoints" value={23} icon={<Activity className="h-5 w-5" />} change={4.5} />
        <MetricCard label="Total Series" value={"75.4K"} icon={<BarChart3 className="h-5 w-5" />} change={12.3} />
        <MetricCard label="High Cardinality Count" value={2} icon={<AlertTriangle className="h-5 w-5" />} change={-33.0} />
        <MetricCard label="Golden Signals %" value={96} icon={<Gauge className="h-5 w-5" />} change={2.1} />
      </div>

      <div className="overflow-x-auto rounded-xl border border-gray-800 bg-gray-900">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-gray-800 text-xs uppercase text-gray-400">
            <tr>
              <th className="px-4 py-3">Service</th>
              <th className="px-4 py-3">Source</th>
              <th className="px-4 py-3">Metrics Count</th>
              <th className="px-4 py-3">Cardinality</th>
              <th className="px-4 py-3">Scrape Interval</th>
              <th className="px-4 py-3">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800">
            {SERVICES.map((s) => (
              <tr key={s.service} className="hover:bg-gray-800/50">
                <td className="px-4 py-3 font-medium">{s.service}</td>
                <td className="px-4 py-3">
                  <span className={clsx("inline-flex rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset", SOURCE_COLORS[s.source])}>{s.source}</span>
                </td>
                <td className="px-4 py-3 text-gray-300">{s.metrics}</td>
                <td className="px-4 py-3 text-gray-300">{s.cardinality.toLocaleString()}</td>
                <td className="px-4 py-3 text-gray-300">{s.interval}</td>
                <td className={clsx("px-4 py-3 text-sm font-medium", STATUS_COLORS[s.status])}>{s.status.replace("_", " ")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
