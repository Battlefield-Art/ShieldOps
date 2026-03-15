import { useState } from "react";
import { ShieldCheck, Target, AlertTriangle, Rocket, Loader2 } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";

const RULES = [
  { name: "Brute Force Login", type: "threshold", technique: "T1110", fpRate: 2.1, status: "active", risk: 85 },
  { name: "Lateral Movement Chain", type: "sequence", technique: "T1021", fpRate: 1.4, status: "active", risk: 92 },
  { name: "Data Exfiltration Pattern", type: "correlation", technique: "T1048", fpRate: 3.8, status: "testing", risk: 78 },
  { name: "Anomalous DNS Queries", type: "anomaly", technique: "T1071", fpRate: 5.2, status: "tuning", risk: 65 },
  { name: "Privilege Escalation Alert", type: "threshold", technique: "T1068", fpRate: 0.8, status: "active", risk: 95 },
  { name: "Credential Dumping Detect", type: "sequence", technique: "T1003", fpRate: 1.1, status: "active", risk: 90 },
  { name: "C2 Beacon Detection", type: "anomaly", technique: "T1573", fpRate: 7.5, status: "draft", risk: 72 },
];

const TYPE_COLORS: Record<string, string> = {
  correlation: "bg-sky-500/10 text-sky-400 ring-sky-500/20",
  threshold: "bg-blue-500/10 text-blue-400 ring-blue-500/20",
  anomaly: "bg-amber-500/10 text-amber-400 ring-amber-500/20",
  sequence: "bg-cyan-500/10 text-cyan-400 ring-cyan-500/20",
};

const STATUS_COLORS: Record<string, string> = {
  draft: "text-gray-400",
  testing: "text-amber-400",
  active: "text-green-400",
  tuning: "text-blue-400",
};

function riskColor(score: number) {
  if (score > 80) return "text-red-400";
  if (score >= 50) return "text-amber-400";
  return "text-green-400";
}

export default function DetectionEngineering() {
  const [running, setRunning] = useState(false);
  const handleClick = () => { setRunning(true); setTimeout(() => setRunning(false), 2000); };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Detection Engineering</h1>
        <button onClick={handleClick} disabled={running} className="flex items-center gap-2 rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-500 disabled:opacity-50">
          {running && <Loader2 className="h-4 w-4 animate-spin" />}
          Assess Coverage
        </button>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard label="Active Rules" value={42} icon={<ShieldCheck className="h-5 w-5" />} change={8.3} />
        <MetricCard label="MITRE Coverage %" value={74} icon={<Target className="h-5 w-5" />} change={3.1} />
        <MetricCard label="Avg FP Rate %" value={3.1} icon={<AlertTriangle className="h-5 w-5" />} change={-1.2} />
        <MetricCard label="Deployed This Week" value={6} icon={<Rocket className="h-5 w-5" />} change={50.0} />
      </div>

      <div className="overflow-x-auto rounded-xl border border-gray-800 bg-gray-900">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-gray-800 text-xs uppercase text-gray-400">
            <tr>
              <th className="px-4 py-3">Rule Name</th>
              <th className="px-4 py-3">Type</th>
              <th className="px-4 py-3">MITRE Technique</th>
              <th className="px-4 py-3">FP Rate %</th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3">Risk Score</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800">
            {RULES.map((r) => (
              <tr key={r.name} className="hover:bg-gray-800/50">
                <td className="px-4 py-3 font-medium">{r.name}</td>
                <td className="px-4 py-3">
                  <span className={clsx("inline-flex rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset", TYPE_COLORS[r.type])}>{r.type}</span>
                </td>
                <td className="px-4 py-3 text-gray-300">{r.technique}</td>
                <td className="px-4 py-3 text-gray-300">{r.fpRate}%</td>
                <td className={clsx("px-4 py-3 text-sm font-medium", STATUS_COLORS[r.status])}>{r.status}</td>
                <td className={clsx("px-4 py-3 font-semibold", riskColor(r.risk))}>{r.risk}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
