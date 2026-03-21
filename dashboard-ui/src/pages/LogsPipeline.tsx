import { useState } from "react";
import { FileText, CheckCircle, Link, Activity, Loader2 } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";

const LOG_SOURCES = [
  { service: "payment-api", source: "otlp", format: "JSON", volume: 4200, parse: 99.2, correlated: 94.1 },
  { service: "auth-service", source: "syslog", format: "RFC5424", volume: 1800, parse: 97.8, correlated: 88.5 },
  { service: "order-processor", source: "filelog", format: "JSON", volume: 3100, parse: 98.5, correlated: 91.3 },
  { service: "notification-svc", source: "kafka", format: "Avro", volume: 6500, parse: 99.8, correlated: 96.2 },
  { service: "search-engine", source: "otlp", format: "JSON", volume: 2400, parse: 99.1, correlated: 93.7 },
  { service: "legacy-billing", source: "filelog", format: "Plain Text", volume: 890, parse: 82.4, correlated: 45.2 },
  { service: "k8s-audit", source: "syslog", format: "JSON", volume: 5600, parse: 99.9, correlated: 97.8 },
];

const SOURCE_COLORS: Record<string, string> = {
  filelog: "bg-green-500/10 text-green-400 ring-green-500/20",
  syslog: "bg-amber-500/10 text-amber-400 ring-amber-500/20",
  otlp: "bg-cyan-500/10 text-cyan-400 ring-cyan-500/20",
  kafka: "bg-slate-500/10 text-slate-400 ring-slate-500/20",
};

function parseColor(pct: number) {
  if (pct >= 98) return "text-green-400";
  if (pct >= 90) return "text-amber-400";
  return "text-red-400";
}

export default function LogsPipeline() {
  const [running, setRunning] = useState(false);
  const handleClick = () => { setRunning(true); setTimeout(() => setRunning(false), 2000); };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">OTel Logs Pipeline</h1>
        <button onClick={handleClick} disabled={running} className="flex items-center gap-2 rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-500 disabled:opacity-50">
          {running && <Loader2 className="h-4 w-4 animate-spin" />}
          Discover Log Sources
        </button>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard label="Log Sources" value={14} icon={<FileText className="h-5 w-5" />} change={7.7} />
        <MetricCard label="Parse Success %" value={96.7} icon={<CheckCircle className="h-5 w-5" />} change={1.2} />
        <MetricCard label="Trace Correlation %" value={86.7} icon={<Link className="h-5 w-5" />} change={4.5} />
        <MetricCard label="Volume/Min" value={"24.5K"} icon={<Activity className="h-5 w-5" />} change={8.3} />
      </div>

      <div className="overflow-x-auto rounded-xl border border-gray-800/80 bg-gray-900 shadow-card">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-gray-800/60 text-xs uppercase text-gray-400">
            <tr>
              <th className="px-5 py-3.5">Service</th>
              <th className="px-5 py-3.5">Source</th>
              <th className="px-5 py-3.5">Format</th>
              <th className="px-5 py-3.5">Volume/Min</th>
              <th className="px-5 py-3.5">Parse %</th>
              <th className="px-5 py-3.5">Correlated %</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800/40">
            {LOG_SOURCES.map((l) => (
              <tr key={l.service} className="hover:bg-gray-800/30">
                <td className="px-5 py-3.5 font-medium">{l.service}</td>
                <td className="px-5 py-3.5">
                  <span className={clsx("inline-flex rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset", SOURCE_COLORS[l.source])}>{l.source}</span>
                </td>
                <td className="px-5 py-3.5 text-gray-300">{l.format}</td>
                <td className="px-5 py-3.5 text-gray-300">{l.volume.toLocaleString()}</td>
                <td className={clsx("px-5 py-3.5 font-medium", parseColor(l.parse))}>{l.parse}%</td>
                <td className={clsx("px-5 py-3.5 font-medium", parseColor(l.correlated))}>{l.correlated}%</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
