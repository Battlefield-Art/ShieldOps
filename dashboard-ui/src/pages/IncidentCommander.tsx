import { useState } from "react";
import { Siren, Clock, CheckCircle, ArrowUpRight, AlertTriangle } from "lucide-react";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type Severity = "sev1" | "sev2" | "sev3" | "sev4" | "sev5";


const MOCK_INCIDENTS = [
  { id: "INC-1042", service: "payment-service", severity: "sev1" as Severity, status: "Mitigating", agents: 4, duration: "23m" },
  { id: "INC-1041", service: "auth-gateway", severity: "sev2" as Severity, status: "Investigating", agents: 2, duration: "1h 12m" },
  { id: "INC-1040", service: "order-processor", severity: "sev3" as Severity, status: "Monitoring", agents: 1, duration: "45m" },
  { id: "INC-1039", service: "search-indexer", severity: "sev2" as Severity, status: "Resolved", agents: 3, duration: "2h 5m" },
  { id: "INC-1038", service: "billing-engine", severity: "sev1" as Severity, status: "Resolved", agents: 5, duration: "38m" },
  { id: "INC-1037", service: "user-api", severity: "sev3" as Severity, status: "Resolved", agents: 1, duration: "15m" },
];

export default function IncidentCommander() {
  const [running, setRunning] = useState(false);
  const handleClick = () => { setRunning(true); setTimeout(() => setRunning(false), 2000); };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Incident Commander"
        action={{ label: "Declare Incident", onClick: handleClick, icon: <AlertTriangle className="h-4 w-4" />, loading: running }}
      />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard label="Active Incidents" value={3} icon={<Siren className="h-5 w-5" />} change={-25} />
        <MetricCard label="Avg MTTR" value="47 min" icon={<Clock className="h-5 w-5" />} change={-8.3} />
        <MetricCard label="Auto-Resolved %" value="68%" icon={<CheckCircle className="h-5 w-5" />} change={4.2} />
        <MetricCard label="Escalation Rate" value="12%" icon={<ArrowUpRight className="h-5 w-5" />} change={-2.1} />
      </div>

      <div className="overflow-hidden rounded-xl border border-gray-800/80 bg-gray-900 shadow-card">
        <div className="border-b border-gray-800/60 px-5 py-4">
          <h2 className="text-lg font-semibold text-gray-50">Recent Incidents</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800/60 text-left text-[11px] font-semibold uppercase tracking-wider text-gray-400">
                <th className="px-5 py-3.5 font-medium">ID</th>
                <th className="px-5 py-3.5 font-medium">Service</th>
                <th className="px-5 py-3.5 font-medium">Severity</th>
                <th className="px-5 py-3.5 font-medium">Status</th>
                <th className="px-5 py-3.5 font-medium">Agents Dispatched</th>
                <th className="px-5 py-3.5 font-medium">Duration</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/40">
              {MOCK_INCIDENTS.map((inc) => (
                <tr key={inc.id} className="text-gray-300 hover:bg-gray-800/30">
                  <td className="px-5 py-3.5 font-mono text-xs text-gray-100">{inc.id}</td>
                  <td className="px-5 py-3.5">{inc.service}</td>
                  <td className="px-5 py-3.5">
                    <StatusBadge
                      status={inc.severity}
                      variant={inc.severity === "sev1" ? "error" : inc.severity === "sev2" ? "warning" : "info"}
                    />
                  </td>
                  <td className="px-5 py-3.5">{inc.status}</td>
                  <td className="px-5 py-3.5 text-center">{inc.agents}</td>
                  <td className="px-5 py-3.5 text-gray-400">{inc.duration}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
