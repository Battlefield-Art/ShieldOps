import { useState } from "react";
import { Filter, Activity, DollarSign, Shield, Loader2 } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";

const POLICIES = [
  { name: "High Latency Capture", type: "latency", threshold: "500ms", rate: 100, traces: 1240, status: "active" },
  { name: "Error Trace Retention", type: "error", threshold: "5xx", rate: 100, traces: 890, status: "active" },
  { name: "Rate Limit Sampling", type: "rate_limit", threshold: "10k/min", rate: 25, traces: 3200, status: "active" },
  { name: "Composite SLO Policy", type: "composite", threshold: "p99 > 1s", rate: 75, traces: 560, status: "active" },
  { name: "Debug Trace Filter", type: "latency", threshold: "100ms", rate: 10, traces: 8400, status: "paused" },
  { name: "Payment Flow Keep", type: "composite", threshold: "error+latency", rate: 100, traces: 320, status: "active" },
];

const TYPE_COLORS: Record<string, string> = {
  latency: "bg-amber-500/10 text-amber-400 ring-amber-500/20",
  error: "bg-red-500/10 text-red-400 ring-red-500/20",
  rate_limit: "bg-blue-500/10 text-blue-400 ring-blue-500/20",
  composite: "bg-sky-500/10 text-sky-400 ring-sky-500/20",
};

const STATUS_COLORS: Record<string, string> = {
  active: "text-green-400",
  paused: "text-gray-400",
};

export default function TailSampling() {
  const [running, setRunning] = useState(false);
  const handleClick = () => { setRunning(true); setTimeout(() => setRunning(false), 2000); };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Tail-Based Sampling</h1>
        <button onClick={handleClick} disabled={running} className="flex items-center gap-2 rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-500 disabled:opacity-50">
          {running && <Loader2 className="h-4 w-4 animate-spin" />}
          Design Policies
        </button>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard label="Active Policies" value={5} icon={<Filter className="h-5 w-5" />} change={1.0} />
        <MetricCard label="Traces Sampled %" value={68} icon={<Activity className="h-5 w-5" />} change={-4.2} />
        <MetricCard label="Cost Savings %" value={42} icon={<DollarSign className="h-5 w-5" />} change={6.8} />
        <MetricCard label="Coverage Score" value={94} icon={<Shield className="h-5 w-5" />} change={1.5} />
      </div>

      <div className="overflow-x-auto rounded-xl border border-gray-800 bg-gray-900">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-gray-800 text-xs uppercase text-gray-400">
            <tr>
              <th className="px-4 py-3">Policy Name</th>
              <th className="px-4 py-3">Type</th>
              <th className="px-4 py-3">Threshold</th>
              <th className="px-4 py-3">Sample Rate %</th>
              <th className="px-4 py-3">Traces/Min</th>
              <th className="px-4 py-3">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800">
            {POLICIES.map((p) => (
              <tr key={p.name} className="hover:bg-gray-800/50">
                <td className="px-4 py-3 font-medium">{p.name}</td>
                <td className="px-4 py-3">
                  <span className={clsx("inline-flex rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset", TYPE_COLORS[p.type])}>{p.type}</span>
                </td>
                <td className="px-4 py-3 text-gray-300">{p.threshold}</td>
                <td className="px-4 py-3 text-gray-300">{p.rate}%</td>
                <td className="px-4 py-3 text-gray-300">{p.traces.toLocaleString()}</td>
                <td className={clsx("px-4 py-3 text-sm font-medium", STATUS_COLORS[p.status])}>{p.status}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
