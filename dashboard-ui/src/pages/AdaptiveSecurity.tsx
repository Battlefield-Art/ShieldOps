import { useState } from "react";
import { ShieldCheck, AlertTriangle, Clock, Zap, ScanSearch } from "lucide-react";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

const MOCK_THRESHOLDS = [
  { name: "Login Failure Rate", type: "Rate", current: "5/min", proposed: "8/min", drift: 3.2, status: "active" as ThresholdStatus },
  { name: "API Error Spike", type: "Anomaly", current: "2σ", proposed: "2.5σ", drift: 12.5, status: "proposed" as ThresholdStatus },
  { name: "Privilege Escalation", type: "Count", current: "3", proposed: "2", drift: -8.1, status: "active" as ThresholdStatus },
  { name: "Data Exfil Volume", type: "Volume", current: "500MB", proposed: "350MB", drift: 18.4, status: "proposed" as ThresholdStatus },
  { name: "Lateral Movement Hops", type: "Count", current: "2", proposed: "2", drift: 0, status: "active" as ThresholdStatus },
  { name: "Legacy SSH Access", type: "Rate", current: "10/hr", proposed: "—", drift: 0, status: "retired" as ThresholdStatus },
];

export default function AdaptiveSecurity() {
  const [running, setRunning] = useState(false);
  const handleClick = () => { setRunning(true); setTimeout(() => setRunning(false), 2000); };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Adaptive Security Thresholds"
        action={{ label: "Run Baseline Scan", onClick: handleClick, icon: <ScanSearch className="h-4 w-4" />, loading: running }}
      />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard label="Active Thresholds" value={142} icon={<ShieldCheck className="h-5 w-5" />} change={5.6} />
        <MetricCard label="Drift Detected" value={18} icon={<AlertTriangle className="h-5 w-5" />} change={-3.2} />
        <MetricCard label="Proposals Pending" value={7} icon={<Clock className="h-5 w-5" />} change={2.1} />
        <MetricCard label="Auto-Adjusted" value={34} icon={<Zap className="h-5 w-5" />} change={12.0} />
      </div>

      <div className="overflow-hidden rounded-xl border border-gray-800/80 bg-gray-900 shadow-card">
        <div className="border-b border-gray-800/60 px-5 py-4">
          <h2 className="text-lg font-semibold text-gray-50">Threshold Configuration</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800/60 text-left text-[11px] font-semibold uppercase tracking-wider text-gray-400">
                <th className="px-5 py-3.5 font-medium">Threshold Name</th>
                <th className="px-5 py-3.5 font-medium">Type</th>
                <th className="px-5 py-3.5 font-medium">Current Value</th>
                <th className="px-5 py-3.5 font-medium">Proposed Value</th>
                <th className="px-5 py-3.5 font-medium">Drift %</th>
                <th className="px-5 py-3.5 font-medium">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/40">
              {MOCK_THRESHOLDS.map((t, i) => (
                <tr key={i} className="text-gray-300 hover:bg-gray-800/30">
                  <td className="px-5 py-3.5 text-gray-100">{t.name}</td>
                  <td className="px-5 py-3.5">{t.type}</td>
                  <td className="px-5 py-3.5 font-mono text-xs">{t.current}</td>
                  <td className="px-5 py-3.5 font-mono text-xs">{t.proposed}</td>
                  <td className="px-5 py-3.5">{t.drift !== 0 ? `${t.drift > 0 ? "+" : ""}${t.drift}%` : "—"}</td>
                  <td className="px-5 py-3.5">
                    <StatusBadge status={t.status} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
