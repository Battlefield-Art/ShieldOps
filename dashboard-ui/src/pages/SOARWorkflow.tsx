import { Siren, Clock, ShieldCheck, BookOpen, Zap } from "lucide-react";
import MetricCard from "../components/MetricCard";

type Stage = "intake" | "enrich" | "contain" | "eradicate" | "recover";
type AlertStatus = "in-progress" | "contained" | "resolved" | "escalated";

const STATUS_CLASSES: Record<AlertStatus, string> = {
  "in-progress": "bg-yellow-500/10 text-yellow-400 ring-yellow-500/20",
  contained: "bg-blue-500/10 text-blue-400 ring-blue-500/20",
  resolved: "bg-green-500/10 text-green-400 ring-green-500/20",
  escalated: "bg-red-500/10 text-red-400 ring-red-500/20",
};

const MOCK_RESPONSES = [
  { alertId: "SOA-4821", severity: "Critical", stage: "contain" as Stage, status: "in-progress" as AlertStatus, duration: "4m 12s", actions: 6 },
  { alertId: "SOA-4820", severity: "High", stage: "eradicate" as Stage, status: "contained" as AlertStatus, duration: "12m 34s", actions: 9 },
  { alertId: "SOA-4819", severity: "Medium", stage: "recover" as Stage, status: "resolved" as AlertStatus, duration: "28m 01s", actions: 14 },
  { alertId: "SOA-4818", severity: "Critical", stage: "enrich" as Stage, status: "escalated" as AlertStatus, duration: "2m 48s", actions: 3 },
  { alertId: "SOA-4817", severity: "Low", stage: "intake" as Stage, status: "in-progress" as AlertStatus, duration: "0m 42s", actions: 1 },
  { alertId: "SOA-4816", severity: "High", stage: "recover" as Stage, status: "resolved" as AlertStatus, duration: "18m 22s", actions: 11 },
];

export default function SOARWorkflow() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-100">SOAR Workflows</h1>
        <button className="flex items-center gap-2 rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-500">
          <Zap className="h-4 w-4" /> Trigger Response
        </button>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard label="Active Responses" value={14} icon={<Siren className="h-5 w-5" />} change={-5.2} />
        <MetricCard label="Avg Containment" value="6m 18s" icon={<Clock className="h-5 w-5" />} change={-12.4} />
        <MetricCard label="Auto-Contained %" value="82%" icon={<ShieldCheck className="h-5 w-5" />} change={7.3} />
        <MetricCard label="Lessons Learned" value={238} icon={<BookOpen className="h-5 w-5" />} change={4.1} />
      </div>

      <div className="overflow-hidden rounded-xl border border-gray-800 bg-gray-900">
        <div className="border-b border-gray-800 px-5 py-4">
          <h2 className="text-lg font-semibold text-gray-100">Active Response Workflows</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-left text-gray-400">
                <th className="px-5 py-3 font-medium">Alert ID</th>
                <th className="px-5 py-3 font-medium">Severity</th>
                <th className="px-5 py-3 font-medium">Stage</th>
                <th className="px-5 py-3 font-medium">Status</th>
                <th className="px-5 py-3 font-medium">Duration</th>
                <th className="px-5 py-3 font-medium">Actions Taken</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {MOCK_RESPONSES.map((r, i) => (
                <tr key={i} className="text-gray-300 hover:bg-gray-800/50">
                  <td className="px-5 py-3 font-mono text-xs text-gray-100">{r.alertId}</td>
                  <td className="px-5 py-3">{r.severity}</td>
                  <td className="px-5 py-3">{r.stage}</td>
                  <td className="px-5 py-3">
                    <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${STATUS_CLASSES[r.status]}`}>
                      {r.status}
                    </span>
                  </td>
                  <td className="px-5 py-3 font-mono text-xs">{r.duration}</td>
                  <td className="px-5 py-3">{r.actions}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
