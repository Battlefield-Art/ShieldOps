import { FileCheck, CheckCircle, AlertTriangle, Wrench, ScanSearch } from "lucide-react";
import MetricCard from "../components/MetricCard";

type ComplianceStatus = "compliant" | "partial" | "non-compliant";

const STATUS_CLASSES: Record<ComplianceStatus, string> = {
  compliant: "bg-green-500/10 text-green-400 ring-green-500/20",
  partial: "bg-yellow-500/10 text-yellow-400 ring-yellow-500/20",
  "non-compliant": "bg-red-500/10 text-red-400 ring-red-500/20",
};

const MOCK_SERVICES = [
  { service: "checkout-api", scope: "resource", violations: 0, complianceScore: 100, status: "compliant" as ComplianceStatus },
  { service: "user-service", scope: "span", violations: 3, complianceScore: 87, status: "partial" as ComplianceStatus },
  { service: "payment-gateway", scope: "metric", violations: 1, complianceScore: 94, status: "partial" as ComplianceStatus },
  { service: "inventory-worker", scope: "log", violations: 8, complianceScore: 62, status: "non-compliant" as ComplianceStatus },
  { service: "notification-svc", scope: "resource", violations: 0, complianceScore: 100, status: "compliant" as ComplianceStatus },
  { service: "search-indexer", scope: "span", violations: 5, complianceScore: 78, status: "partial" as ComplianceStatus },
];

export default function OTelSemantic() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-100">OTel Semantic Conventions</h1>
        <button className="flex items-center gap-2 rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-500">
          <ScanSearch className="h-4 w-4" /> Scan Services
        </button>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard label="Services Scanned" value={86} icon={<FileCheck className="h-5 w-5" />} change={2.4} />
        <MetricCard label="Compliant %" value="91.2%" icon={<CheckCircle className="h-5 w-5" />} change={4.1} />
        <MetricCard label="Violations Found" value={37} icon={<AlertTriangle className="h-5 w-5" />} change={-8.3} />
        <MetricCard label="Auto-Fixable" value={22} icon={<Wrench className="h-5 w-5" />} change={6.7} />
      </div>

      <div className="overflow-hidden rounded-xl border border-gray-800 bg-gray-900">
        <div className="border-b border-gray-800 px-5 py-4">
          <h2 className="text-lg font-semibold text-gray-100">Service Compliance</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-left text-gray-400">
                <th className="px-5 py-3 font-medium">Service</th>
                <th className="px-5 py-3 font-medium">Scope</th>
                <th className="px-5 py-3 font-medium">Violations</th>
                <th className="px-5 py-3 font-medium">Compliance Score</th>
                <th className="px-5 py-3 font-medium">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {MOCK_SERVICES.map((s, i) => (
                <tr key={i} className="text-gray-300 hover:bg-gray-800/50">
                  <td className="px-5 py-3 font-mono text-xs text-gray-100">{s.service}</td>
                  <td className="px-5 py-3">{s.scope}</td>
                  <td className="px-5 py-3">{s.violations}</td>
                  <td className="px-5 py-3">{s.complianceScore}%</td>
                  <td className="px-5 py-3">
                    <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${STATUS_CLASSES[s.status]}`}>
                      {s.status}
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
