import { useState } from "react";
import { Users, AlertTriangle, Activity, Bell, Loader2 } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";

const ENTITIES = [
  { entity: "admin@corp.io", type: "user", score: 92, factors: 7, tactics: "Initial Access, Privilege Escalation", updated: "2 min ago" },
  { entity: "db-prod-west-03", type: "host", score: 85, factors: 5, tactics: "Lateral Movement, Exfiltration", updated: "5 min ago" },
  { entity: "payment-gateway", type: "service", score: 78, factors: 4, tactics: "Collection, Command and Control", updated: "12 min ago" },
  { entity: "svc-deploy@ci", type: "user", score: 65, factors: 3, tactics: "Execution, Persistence", updated: "18 min ago" },
  { entity: "k8s-node-07", type: "host", score: 54, factors: 3, tactics: "Discovery", updated: "25 min ago" },
  { entity: "auth-service", type: "service", score: 41, factors: 2, tactics: "Credential Access", updated: "1 hr ago" },
  { entity: "dev@intern.io", type: "user", score: 28, factors: 1, tactics: "Reconnaissance", updated: "3 hr ago" },
];

const NOTABLE_EVENTS = [
  { entity: "admin@corp.io", score: 92, action: "Account disabled, SOC notified" },
  { entity: "db-prod-west-03", score: 85, action: "Network isolated, forensics initiated" },
  { entity: "payment-gateway", score: 78, action: "Rate limiting applied, playbook triggered" },
  { entity: "svc-deploy@ci", score: 65, action: "Escalated for human review" },
];

function riskColor(score: number) {
  if (score > 80) return { bar: "bg-red-500", text: "text-red-400" };
  if (score >= 50) return { bar: "bg-amber-500", text: "text-amber-400" };
  return { bar: "bg-green-500", text: "text-green-400" };
}

const TYPE_COLORS: Record<string, string> = {
  user: "bg-blue-500/10 text-blue-400 ring-blue-500/20",
  host: "bg-slate-500/10 text-slate-400 ring-slate-500/20",
  service: "bg-cyan-500/10 text-cyan-400 ring-cyan-500/20",
};

export default function RiskScoring() {
  const [assessing, setAssessing] = useState(false);

  const handleAssess = () => {
    setAssessing(true);
    setTimeout(() => setAssessing(false), 2000);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Risk-Based Alerting</h1>
        <button
          onClick={handleAssess}
          disabled={assessing}
          className="flex items-center gap-2 rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-500 disabled:opacity-50"
        >
          {assessing && <Loader2 className="h-4 w-4 animate-spin" />}
          Run Risk Assessment
        </button>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard label="Entities Monitored" value={1284} icon={<Users className="h-5 w-5" />} change={5.2} />
        <MetricCard label="High Risk Count" value={3} icon={<AlertTriangle className="h-5 w-5" />} change={-12.0} />
        <MetricCard label="Average Risk Score" value={56} icon={<Activity className="h-5 w-5" />} change={-2.8} />
        <MetricCard label="Notable Events" value={47} icon={<Bell className="h-5 w-5" />} change={8.1} />
      </div>

      <div className="overflow-x-auto rounded-xl border border-gray-800 bg-gray-900">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-gray-800 text-xs uppercase text-gray-400">
            <tr>
              <th className="px-4 py-3">Entity</th>
              <th className="px-4 py-3">Type</th>
              <th className="px-4 py-3">Risk Score</th>
              <th className="px-4 py-3">Factors</th>
              <th className="px-4 py-3">MITRE Tactics</th>
              <th className="px-4 py-3">Last Updated</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800">
            {ENTITIES.map((e) => {
              const rc = riskColor(e.score);
              return (
                <tr key={e.entity} className="hover:bg-gray-800/50">
                  <td className="px-4 py-3 font-medium">{e.entity}</td>
                  <td className="px-4 py-3">
                    <span className={clsx("inline-flex rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset", TYPE_COLORS[e.type])}>{e.type}</span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <div className="h-2 w-16 rounded-full bg-gray-700">
                        <div className={clsx("h-2 rounded-full", rc.bar)} style={{ width: `${e.score}%` }} />
                      </div>
                      <span className={clsx("text-xs font-semibold", rc.text)}>{e.score}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-gray-300">{e.factors}</td>
                  <td className="px-4 py-3 text-xs text-gray-400">{e.tactics}</td>
                  <td className="px-4 py-3 text-gray-400">{e.updated}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
        <h2 className="mb-4 text-lg font-semibold">Recent Notable Events</h2>
        <div className="space-y-3">
          {NOTABLE_EVENTS.map((ev) => {
            const rc = riskColor(ev.score);
            return (
              <div key={ev.entity} className="flex items-center justify-between rounded-lg border border-gray-800 px-4 py-3">
                <div className="flex items-center gap-3">
                  <span className={clsx("text-sm font-semibold", rc.text)}>{ev.score}</span>
                  <span className="font-medium">{ev.entity}</span>
                </div>
                <span className="text-sm text-gray-400">{ev.action}</span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
