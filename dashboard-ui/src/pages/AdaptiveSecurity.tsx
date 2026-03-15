import { ShieldCheck, AlertTriangle, Clock, Zap, ScanSearch } from "lucide-react";
import MetricCard from "../components/MetricCard";

type ThresholdStatus = "active" | "proposed" | "retired";

const STATUS_CLASSES: Record<ThresholdStatus, string> = {
  active: "bg-green-500/10 text-green-400 ring-green-500/20",
  proposed: "bg-yellow-500/10 text-yellow-400 ring-yellow-500/20",
  retired: "bg-gray-500/10 text-gray-400 ring-gray-500/20",
};

const MOCK_THRESHOLDS = [
  { name: "Login Failure Rate", type: "Rate", current: "5/min", proposed: "8/min", drift: 3.2, status: "active" as ThresholdStatus },
  { name: "API Error Spike", type: "Anomaly", current: "2σ", proposed: "2.5σ", drift: 12.5, status: "proposed" as ThresholdStatus },
  { name: "Privilege Escalation", type: "Count", current: "3", proposed: "2", drift: -8.1, status: "active" as ThresholdStatus },
  { name: "Data Exfil Volume", type: "Volume", current: "500MB", proposed: "350MB", drift: 18.4, status: "proposed" as ThresholdStatus },
  { name: "Lateral Movement Hops", type: "Count", current: "2", proposed: "2", drift: 0, status: "active" as ThresholdStatus },
  { name: "Legacy SSH Access", type: "Rate", current: "10/hr", proposed: "—", drift: 0, status: "retired" as ThresholdStatus },
];

export default function AdaptiveSecurity() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-100">Adaptive Security Thresholds</h1>
        <button className="flex items-center gap-2 rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-500">
          <ScanSearch className="h-4 w-4" /> Run Baseline Scan
        </button>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard label="Active Thresholds" value={142} icon={<ShieldCheck className="h-5 w-5" />} change={5.6} />
        <MetricCard label="Drift Detected" value={18} icon={<AlertTriangle className="h-5 w-5" />} change={-3.2} />
        <MetricCard label="Proposals Pending" value={7} icon={<Clock className="h-5 w-5" />} change={2.1} />
        <MetricCard label="Auto-Adjusted" value={34} icon={<Zap className="h-5 w-5" />} change={12.0} />
      </div>

      <div className="overflow-hidden rounded-xl border border-gray-800 bg-gray-900">
        <div className="border-b border-gray-800 px-5 py-4">
          <h2 className="text-lg font-semibold text-gray-100">Threshold Configuration</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-left text-gray-400">
                <th className="px-5 py-3 font-medium">Threshold Name</th>
                <th className="px-5 py-3 font-medium">Type</th>
                <th className="px-5 py-3 font-medium">Current Value</th>
                <th className="px-5 py-3 font-medium">Proposed Value</th>
                <th className="px-5 py-3 font-medium">Drift %</th>
                <th className="px-5 py-3 font-medium">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {MOCK_THRESHOLDS.map((t, i) => (
                <tr key={i} className="text-gray-300 hover:bg-gray-800/50">
                  <td className="px-5 py-3 text-gray-100">{t.name}</td>
                  <td className="px-5 py-3">{t.type}</td>
                  <td className="px-5 py-3 font-mono text-xs">{t.current}</td>
                  <td className="px-5 py-3 font-mono text-xs">{t.proposed}</td>
                  <td className="px-5 py-3">{t.drift !== 0 ? `${t.drift > 0 ? "+" : ""}${t.drift}%` : "—"}</td>
                  <td className="px-5 py-3">
                    <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${STATUS_CLASSES[t.status]}`}>
                      {t.status}
                    </span>
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
