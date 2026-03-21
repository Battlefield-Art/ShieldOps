import { useState } from "react";
import { Shield, Crosshair, CheckCircle, AlertTriangle, Loader2 } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";

const STRIDE_CATEGORIES = [
  { letter: "S", name: "Spoofing", count: 12, color: "bg-red-500/10 text-red-400 border-red-500/20" },
  { letter: "T", name: "Tampering", count: 8, color: "bg-orange-500/10 text-orange-400 border-orange-500/20" },
  { letter: "R", name: "Repudiation", count: 5, color: "bg-amber-500/10 text-amber-400 border-amber-500/20" },
  { letter: "I", name: "Info Disclosure", count: 15, color: "bg-blue-500/10 text-blue-400 border-blue-500/20" },
  { letter: "D", name: "Denial of Service", count: 9, color: "bg-slate-500/10 text-slate-400 border-slate-500/20" },
  { letter: "E", name: "Elevation of Priv", count: 7, color: "bg-cyan-500/10 text-cyan-400 border-cyan-500/20" },
];

const THREATS = [
  { threat: "Token Replay Attack", stride: "Spoofing", component: "auth-service", likelihood: "High", risk: 88, mitigation: "mitigated" },
  { threat: "API Parameter Tampering", stride: "Tampering", component: "payment-api", likelihood: "Medium", risk: 72, mitigation: "in_progress" },
  { threat: "Log Deletion by Insider", stride: "Repudiation", component: "audit-service", likelihood: "Low", risk: 45, mitigation: "mitigated" },
  { threat: "PII Leakage via Logs", stride: "Info Disclosure", component: "logging-pipeline", likelihood: "High", risk: 91, mitigation: "pending" },
  { threat: "Rate Limit Bypass", stride: "Denial of Service", component: "api-gateway", likelihood: "Medium", risk: 65, mitigation: "mitigated" },
  { threat: "RBAC Misconfiguration", stride: "Elevation of Priv", component: "k8s-cluster", likelihood: "High", risk: 85, mitigation: "in_progress" },
  { threat: "Session Fixation", stride: "Spoofing", component: "web-frontend", likelihood: "Medium", risk: 58, mitigation: "mitigated" },
];

const STRIDE_BADGE: Record<string, string> = {
  Spoofing: "bg-red-500/10 text-red-400 ring-red-500/20",
  Tampering: "bg-orange-500/10 text-orange-400 ring-orange-500/20",
  Repudiation: "bg-amber-500/10 text-amber-400 ring-amber-500/20",
  "Info Disclosure": "bg-blue-500/10 text-blue-400 ring-blue-500/20",
  "Denial of Service": "bg-slate-500/10 text-slate-400 ring-slate-500/20",
  "Elevation of Priv": "bg-cyan-500/10 text-cyan-400 ring-cyan-500/20",
};

const MITIGATION_COLORS: Record<string, string> = {
  mitigated: "text-green-400",
  in_progress: "text-amber-400",
  pending: "text-red-400",
};

function riskColor(score: number) {
  if (score > 80) return "text-red-400";
  if (score >= 50) return "text-amber-400";
  return "text-green-400";
}

export default function ThreatModeling() {
  const [running, setRunning] = useState(false);
  const handleClick = () => { setRunning(true); setTimeout(() => setRunning(false), 2000); };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Threat Modeling</h1>
        <button onClick={handleClick} disabled={running} className="flex items-center gap-2 rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-500 disabled:opacity-50">
          {running && <Loader2 className="h-4 w-4 animate-spin" />}
          Run Threat Model
        </button>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard label="Services Modeled" value={18} icon={<Shield className="h-5 w-5" />} change={12.5} />
        <MetricCard label="Threat Vectors Found" value={56} icon={<Crosshair className="h-5 w-5" />} change={8.0} />
        <MetricCard label="Mitigations Applied" value={38} icon={<CheckCircle className="h-5 w-5" />} change={15.2} />
        <MetricCard label="Residual Risk %" value={24} icon={<AlertTriangle className="h-5 w-5" />} change={-6.3} />
      </div>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        {STRIDE_CATEGORIES.map((s) => (
          <div key={s.letter} className={clsx("rounded-lg border p-3 text-center", s.color)}>
            <div className="text-2xl font-bold">{s.count}</div>
            <div className="text-xs font-medium opacity-80">{s.letter} - {s.name}</div>
          </div>
        ))}
      </div>

      <div className="overflow-x-auto rounded-xl border border-gray-800/80 bg-gray-900 shadow-card">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-gray-800/60 text-xs uppercase text-gray-400">
            <tr>
              <th className="px-5 py-3.5">Threat</th>
              <th className="px-5 py-3.5">STRIDE Category</th>
              <th className="px-5 py-3.5">Component</th>
              <th className="px-5 py-3.5">Likelihood</th>
              <th className="px-5 py-3.5">Risk Score</th>
              <th className="px-5 py-3.5">Mitigation</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800/40">
            {THREATS.map((t) => (
              <tr key={t.threat} className="hover:bg-gray-800/30">
                <td className="px-5 py-3.5 font-medium">{t.threat}</td>
                <td className="px-5 py-3.5">
                  <span className={clsx("inline-flex rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset", STRIDE_BADGE[t.stride])}>{t.stride}</span>
                </td>
                <td className="px-5 py-3.5 text-gray-300">{t.component}</td>
                <td className="px-5 py-3.5 text-gray-300">{t.likelihood}</td>
                <td className={clsx("px-5 py-3.5 font-semibold", riskColor(t.risk))}>{t.risk}</td>
                <td className={clsx("px-5 py-3.5 text-sm font-medium", MITIGATION_COLORS[t.mitigation])}>{t.mitigation.replace("_", " ")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
