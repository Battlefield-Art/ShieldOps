import { ShieldCheck, Layers, AlertTriangle, TrendingUp, ScanSearch } from "lucide-react";
import MetricCard from "../components/MetricCard";

const DOMAINS = [
  { name: "Identity & Access", score: 82, color: "bg-blue-500" },
  { name: "Network Security", score: 74, color: "bg-cyan-500" },
  { name: "Endpoint Protection", score: 91, color: "bg-green-500" },
  { name: "Cloud Configuration", score: 67, color: "bg-yellow-500" },
  { name: "Data Protection", score: 78, color: "bg-sky-500" },
];

export default function SecurityPosture() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-100">Security Posture</h1>
        <button className="flex items-center gap-2 rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-500">
          <ScanSearch className="h-4 w-4" /> Run Assessment
        </button>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard label="Overall Score" value="78/100" icon={<ShieldCheck className="h-5 w-5" />} change={3.4} />
        <MetricCard label="Domains Assessed" value={5} icon={<Layers className="h-5 w-5" />} change={0} />
        <MetricCard label="Critical Gaps" value={4} icon={<AlertTriangle className="h-5 w-5" />} change={-12.5} />
        <MetricCard label="Trend" value="+3.4%" icon={<TrendingUp className="h-5 w-5" />} change={3.4} />
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
        {DOMAINS.map((d) => (
          <div key={d.name} className="rounded-xl border border-gray-800 bg-gray-900 p-5">
            <p className="text-sm font-medium text-gray-400">{d.name}</p>
            <p className="mt-2 text-2xl font-semibold text-gray-100">{d.score}</p>
            <div className="mt-3 h-2 w-full rounded-full bg-gray-800">
              <div
                className={`h-2 rounded-full ${d.color}`}
                style={{ width: `${d.score}%` }}
              />
            </div>
            <p className="mt-1 text-xs text-gray-500">{d.score >= 80 ? "Good" : d.score >= 60 ? "Needs work" : "Critical"}</p>
          </div>
        ))}
      </div>
    </div>
  );
}
