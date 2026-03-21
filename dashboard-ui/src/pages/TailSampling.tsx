import { useState } from "react";
import { Filter, Activity, DollarSign, Shield } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

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

export default function TailSampling() {
  const [running, setRunning] = useState(false);
  const handleClick = () => { setRunning(true); setTimeout(() => setRunning(false), 2000); };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Tail-Based Sampling"
        action={{
          label: "Design Policies",
          onClick: handleClick,
          loading: running,
        }}
      />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard label="Active Policies" value={5} icon={<Filter className="h-5 w-5" />} change={1.0} />
        <MetricCard label="Traces Sampled %" value={68} icon={<Activity className="h-5 w-5" />} change={-4.2} />
        <MetricCard label="Cost Savings %" value={42} icon={<DollarSign className="h-5 w-5" />} change={6.8} />
        <MetricCard label="Coverage Score" value={94} icon={<Shield className="h-5 w-5" />} change={1.5} />
      </div>

      <div className="overflow-x-auto rounded-xl border border-gray-800/80 bg-gray-900 shadow-card">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-gray-800/60 text-[11px] font-semibold uppercase tracking-wider text-gray-400">
            <tr>
              <th className="px-5 py-3.5">Policy Name</th>
              <th className="px-5 py-3.5">Type</th>
              <th className="px-5 py-3.5">Threshold</th>
              <th className="px-5 py-3.5">Sample Rate %</th>
              <th className="px-5 py-3.5">Traces/Min</th>
              <th className="px-5 py-3.5">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800/40">
            {POLICIES.map((p) => (
              <tr key={p.name} className="hover:bg-gray-800/30">
                <td className="px-5 py-3.5 font-medium">{p.name}</td>
                <td className="px-5 py-3.5">
                  <span className={clsx("inline-flex rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset", TYPE_COLORS[p.type])}>{p.type}</span>
                </td>
                <td className="px-5 py-3.5 text-gray-300">{p.threshold}</td>
                <td className="px-5 py-3.5 text-gray-300">{p.rate}%</td>
                <td className="px-5 py-3.5 text-gray-300">{p.traces.toLocaleString()}</td>
                <td className="px-5 py-3.5"><StatusBadge status={p.status} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
