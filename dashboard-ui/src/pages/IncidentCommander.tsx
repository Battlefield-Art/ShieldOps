import { Siren, Clock, CheckCircle, ArrowUpRight, AlertTriangle } from "lucide-react";
import MetricCard from "../components/MetricCard";

type Severity = "sev1" | "sev2" | "sev3";

const SEV_CLASSES: Record<Severity, string> = {
  sev1: "bg-red-500/10 text-red-400 ring-red-500/20",
  sev2: "bg-orange-500/10 text-orange-400 ring-orange-500/20",
  sev3: "bg-yellow-500/10 text-yellow-400 ring-yellow-500/20",
};

const MOCK_INCIDENTS = [
  { id: "INC-1042", service: "payment-service", severity: "sev1" as Severity, status: "Mitigating", agents: 4, duration: "23m" },
  { id: "INC-1041", service: "auth-gateway", severity: "sev2" as Severity, status: "Investigating", agents: 2, duration: "1h 12m" },
  { id: "INC-1040", service: "order-processor", severity: "sev3" as Severity, status: "Monitoring", agents: 1, duration: "45m" },
  { id: "INC-1039", service: "search-indexer", severity: "sev2" as Severity, status: "Resolved", agents: 3, duration: "2h 5m" },
  { id: "INC-1038", service: "billing-engine", severity: "sev1" as Severity, status: "Resolved", agents: 5, duration: "38m" },
  { id: "INC-1037", service: "user-api", severity: "sev3" as Severity, status: "Resolved", agents: 1, duration: "15m" },
];

export default function IncidentCommander() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-100">Incident Commander</h1>
        <button className="flex items-center gap-2 rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-500">
          <AlertTriangle className="h-4 w-4" /> Declare Incident
        </button>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard label="Active Incidents" value={3} icon={<Siren className="h-5 w-5" />} change={-25} />
        <MetricCard label="Avg MTTR" value="47 min" icon={<Clock className="h-5 w-5" />} change={-8.3} />
        <MetricCard label="Auto-Resolved %" value="68%" icon={<CheckCircle className="h-5 w-5" />} change={4.2} />
        <MetricCard label="Escalation Rate" value="12%" icon={<ArrowUpRight className="h-5 w-5" />} change={-2.1} />
      </div>

      <div className="overflow-hidden rounded-xl border border-gray-800 bg-gray-900">
        <div className="border-b border-gray-800 px-5 py-4">
          <h2 className="text-lg font-semibold text-gray-100">Recent Incidents</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-left text-gray-400">
                <th className="px-5 py-3 font-medium">ID</th>
                <th className="px-5 py-3 font-medium">Service</th>
                <th className="px-5 py-3 font-medium">Severity</th>
                <th className="px-5 py-3 font-medium">Status</th>
                <th className="px-5 py-3 font-medium">Agents Dispatched</th>
                <th className="px-5 py-3 font-medium">Duration</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {MOCK_INCIDENTS.map((inc) => (
                <tr key={inc.id} className="text-gray-300 hover:bg-gray-800/50">
                  <td className="px-5 py-3 font-mono text-xs text-gray-100">{inc.id}</td>
                  <td className="px-5 py-3">{inc.service}</td>
                  <td className="px-5 py-3">
                    <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium uppercase ring-1 ring-inset ${SEV_CLASSES[inc.severity]}`}>
                      {inc.severity}
                    </span>
                  </td>
                  <td className="px-5 py-3">{inc.status}</td>
                  <td className="px-5 py-3 text-center">{inc.agents}</td>
                  <td className="px-5 py-3 text-gray-400">{inc.duration}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
