import { useState } from "react";
import { DollarSign, TrendingDown, AlertTriangle, Activity } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

const WASTE_COLORS: Record<string, string> = {
  high_cardinality: "bg-red-500/10 text-red-400 ring-red-500/20",
  over_sampling: "bg-amber-500/10 text-amber-400 ring-amber-500/20",
  duplicate: "bg-slate-500/10 text-slate-400 ring-slate-500/20",
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
      <PageHeader
        title="Telemetry Cost Optimizer"
        action={{ label: "Run Optimization Scan", onClick: handleScan, loading: scanning }}
      />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard label="Monthly Cost" value="$15,440" icon={<DollarSign className="h-5 w-5" />} change={-8.3} />
        <MetricCard label="Savings Found" value="$9,280" icon={<TrendingDown className="h-5 w-5" />} change={12.5} />
        <MetricCard label="Cardinality Issues" value={14} icon={<AlertTriangle className="h-5 w-5" />} change={-3.2} />
        <MetricCard label="Sampling Efficiency" value="87%" icon={<Activity className="h-5 w-5" />} change={4.1} />
      </div>

      <div className="overflow-x-auto rounded-xl border border-gray-800/80 bg-gray-900 shadow-card">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-gray-800/60 text-[11px] font-semibold uppercase tracking-wider text-gray-400">
            <tr>
              <th className="px-5 py-3.5">Service</th>
              <th className="px-5 py-3.5">Waste Category</th>
              <th className="px-5 py-3.5">Monthly Cost</th>
              <th className="px-5 py-3.5">Proposed Savings</th>
              <th className="px-5 py-3.5">Risk Level</th>
              <th className="px-5 py-3.5">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800/40">
            {PROPOSALS.map((p) => (
              <tr key={p.service} className="hover:bg-gray-800/30">
                <td className="px-5 py-3.5 font-medium">{p.service}</td>
                <td className="px-5 py-3.5">
                  <span className={clsx("inline-flex rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset", WASTE_COLORS[p.waste])}>
                    {p.waste.replace(/_/g, " ")}
                  </span>
                </td>
                <td className="px-5 py-3.5">${p.cost.toLocaleString()}</td>
                <td className="px-5 py-3.5 text-green-400">{p.savings}%</td>
                <td className="px-5 py-3.5">
                  <span className={clsx("text-xs font-medium", p.risk === "high" ? "text-red-400" : p.risk === "medium" ? "text-amber-400" : "text-green-400")}>
                    {p.risk}
                  </span>
                </td>
                <td className="px-5 py-3.5">
                  <StatusBadge status={p.status} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
