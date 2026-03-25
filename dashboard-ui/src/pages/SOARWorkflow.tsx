import { useState } from "react";
import { Siren, Clock, ShieldCheck, BookOpen, Zap } from "lucide-react";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type AlertStatus = "in-progress" | "contained" | "eradicated" | "recovered" | "pending" | "monitoring" | "resolved" | "escalated";
type Stage = "intake" | "enrich" | "contain" | "eradicate" | "recover";



const MOCK_RESPONSES = [
  { alertId: "SOA-4821", severity: "Critical", stage: "contain" as Stage, status: "in-progress" as AlertStatus, duration: "4m 12s", actions: 6 },
  { alertId: "SOA-4820", severity: "High", stage: "eradicate" as Stage, status: "contained" as AlertStatus, duration: "12m 34s", actions: 9 },
  { alertId: "SOA-4819", severity: "Medium", stage: "recover" as Stage, status: "resolved" as AlertStatus, duration: "28m 01s", actions: 14 },
  { alertId: "SOA-4818", severity: "Critical", stage: "enrich" as Stage, status: "escalated" as AlertStatus, duration: "2m 48s", actions: 3 },
  { alertId: "SOA-4817", severity: "Low", stage: "intake" as Stage, status: "in-progress" as AlertStatus, duration: "0m 42s", actions: 1 },
  { alertId: "SOA-4816", severity: "High", stage: "recover" as Stage, status: "resolved" as AlertStatus, duration: "18m 22s", actions: 11 },
];

export default function SOARWorkflow() {
  const [running, setRunning] = useState(false);
  const handleClick = () => { setRunning(true); setTimeout(() => setRunning(false), 2000); };

  return (
    <div className="space-y-6">
      <PageHeader
        title="SOAR Workflows"
        action={{ label: "Trigger Response", onClick: handleClick, icon: <Zap className="h-4 w-4" />, loading: running }}
      />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard label="Active Responses" value={14} icon={<Siren className="h-5 w-5" />} change={-5.2} />
        <MetricCard label="Avg Containment" value="6m 18s" icon={<Clock className="h-5 w-5" />} change={-12.4} />
        <MetricCard label="Auto-Contained %" value="82%" icon={<ShieldCheck className="h-5 w-5" />} change={7.3} />
        <MetricCard label="Lessons Learned" value={238} icon={<BookOpen className="h-5 w-5" />} change={4.1} />
      </div>

      <div className="overflow-hidden rounded-xl border border-gray-800/80 bg-gray-900 shadow-card">
        <div className="border-b border-gray-800/60 px-5 py-4">
          <h2 className="text-lg font-semibold text-gray-50">Active Response Workflows</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800/60 text-left text-[11px] font-semibold uppercase tracking-wider text-gray-400">
                <th className="px-5 py-3.5 font-medium">Alert ID</th>
                <th className="px-5 py-3.5 font-medium">Severity</th>
                <th className="px-5 py-3.5 font-medium">Stage</th>
                <th className="px-5 py-3.5 font-medium">Status</th>
                <th className="px-5 py-3.5 font-medium">Duration</th>
                <th className="px-5 py-3.5 font-medium">Actions Taken</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/40">
              {MOCK_RESPONSES.map((r, i) => (
                <tr key={i} className="text-gray-300 hover:bg-gray-800/30">
                  <td className="px-5 py-3.5 font-mono text-xs text-gray-100">{r.alertId}</td>
                  <td className="px-5 py-3.5">{r.severity}</td>
                  <td className="px-5 py-3.5">{r.stage}</td>
                  <td className="px-5 py-3.5">
                    <StatusBadge
                      status={r.status}
                      variant={r.status === "resolved" ? "success" : r.status === "escalated" ? "error" : r.status === "contained" ? "info" : "warning"}
                    />
                  </td>
                  <td className="px-5 py-3.5 font-mono text-xs">{r.duration}</td>
                  <td className="px-5 py-3.5">{r.actions}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
