import { useState } from "react";
import { DollarSign, TrendingDown, AlertTriangle, Activity, Loader2 } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";

const WASTE_COLORS: Record<string, string> = {
  high_cardinality: "bg-red-500/10 text-red-400 ring-red-500/20",
  over_sampling: "bg-amber-500/10 text-amber-400 ring-amber-500/20",
  duplicate: "bg-slate-500/10 text-slate-400 ring-slate-500/20",
};

const STATUS_COLORS: Record<string, string> = {
  proposed: "bg-gray-500/10 text-gray-400 ring-gray-500/20",
  accepted: "bg-cyan-500/10 text-cyan-400 ring-cyan-500/20",
  applied: "bg-green-500/10 text-green-400 ring-green-500/20",
};

const PROPOSALS = [
  { service: "payment-api", waste: "high_cardinality", cost: 4200, savings: 62, risk: "low", status: "applied" },
  { service: "auth-service", waste: "over_sampling", cost: 3100, savings: 45, risk: "medium", status: "accepted" },
  { service: "order-processor", waste: "duplicate", cost: 2800, savings: 78, risk: "low", status: "applied" },
  { service: "user-service", waste: "high_cardinality", cost: 1950, savings: 55, risk: "high", status: "proposed" },
  { service: "notification-hub", waste: "over_sampling", cost: 1400, savings: 38, risk: "low", status: "accepted" },
  { service: "search-indexer", waste: "duplicate", cost: 1100, savings: 82, risk: "medium", status: "proposed" },
  { service: "metrics-collector", waste: "high_cardinality", cost: 890, savings: 70, risk: "low", status: "applied" },
];

export default function TelemetryOptimizer() {
  const [scanning, setScanning] = useState(false);

  const handleScan = () => {
    setScanning(true);
    setTimeout(() => setScanning(false), 2000);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Telemetry Cost Optimizer</h1>
        <button
          onClick={handleScan}
          disabled={scanning}
          className="flex items-center gap-2 rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-500 disabled:opacity-50"
        >
          {scanning && <Loader2 className="h-4 w-4 animate-spin" />}
          Run Optimization Scan
        </button>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard label="Monthly Cost" value="$15,440" icon={<DollarSign className="h-5 w-5" />} change={-8.3} />
        <MetricCard label="Savings Found" value="$9,280" icon={<TrendingDown className="h-5 w-5" />} change={12.5} />
        <MetricCard label="Cardinality Issues" value={14} icon={<AlertTriangle className="h-5 w-5" />} change={-3.2} />
        <MetricCard label="Sampling Efficiency" value="87%" icon={<Activity className="h-5 w-5" />} change={4.1} />
      </div>

      <div className="overflow-x-auto rounded-xl border border-gray-800 bg-gray-900">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-gray-800 text-xs uppercase text-gray-400">
            <tr>
              <th className="px-4 py-3">Service</th>
              <th className="px-4 py-3">Waste Category</th>
              <th className="px-4 py-3">Monthly Cost</th>
              <th className="px-4 py-3">Proposed Savings</th>
              <th className="px-4 py-3">Risk Level</th>
              <th className="px-4 py-3">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800">
            {PROPOSALS.map((p) => (
              <tr key={p.service} className="hover:bg-gray-800/50">
                <td className="px-4 py-3 font-medium">{p.service}</td>
                <td className="px-4 py-3">
                  <span className={clsx("inline-flex rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset", WASTE_COLORS[p.waste])}>
                    {p.waste.replace(/_/g, " ")}
                  </span>
                </td>
                <td className="px-4 py-3">${p.cost.toLocaleString()}</td>
                <td className="px-4 py-3 text-green-400">{p.savings}%</td>
                <td className="px-4 py-3">
                  <span className={clsx("text-xs font-medium", p.risk === "high" ? "text-red-400" : p.risk === "medium" ? "text-amber-400" : "text-green-400")}>
                    {p.risk}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <span className={clsx("inline-flex rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset", STATUS_COLORS[p.status])}>
                    {p.status}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
