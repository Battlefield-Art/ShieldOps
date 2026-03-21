import { useState } from "react";
import { FileCheck, CheckCircle, AlertTriangle, Wrench, ScanSearch } from "lucide-react";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type ComplianceStatus = "compliant" | "partial" | "non-compliant";

const MOCK_SERVICES = [
  { service: "checkout-api", scope: "resource", violations: 0, complianceScore: 100, status: "compliant" as ComplianceStatus },
  { service: "user-service", scope: "span", violations: 3, complianceScore: 87, status: "partial" as ComplianceStatus },
  { service: "payment-gateway", scope: "metric", violations: 1, complianceScore: 94, status: "partial" as ComplianceStatus },
  { service: "inventory-worker", scope: "log", violations: 8, complianceScore: 62, status: "non-compliant" as ComplianceStatus },
  { service: "notification-svc", scope: "resource", violations: 0, complianceScore: 100, status: "compliant" as ComplianceStatus },
  { service: "search-indexer", scope: "span", violations: 5, complianceScore: 78, status: "partial" as ComplianceStatus },
];

export default function OTelSemantic() {
  const [scanning, setScanning] = useState(false);
  const handleScan = () => { setScanning(true); setTimeout(() => setScanning(false), 2000); };

  return (
    <div className="space-y-6">
      <PageHeader
        title="OTel Semantic Conventions"
        action={{
          label: "Scan Services",
          onClick: handleScan,
          icon: <ScanSearch className="h-4 w-4" />,
          loading: scanning,
        }}
      />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard label="Services Scanned" value={86} icon={<FileCheck className="h-5 w-5" />} change={2.4} />
        <MetricCard label="Compliant %" value="91.2%" icon={<CheckCircle className="h-5 w-5" />} change={4.1} />
        <MetricCard label="Violations Found" value={37} icon={<AlertTriangle className="h-5 w-5" />} change={-8.3} />
        <MetricCard label="Auto-Fixable" value={22} icon={<Wrench className="h-5 w-5" />} change={6.7} />
      </div>

      <div className="overflow-hidden rounded-xl border border-gray-800/80 bg-gray-900 shadow-card">
        <div className="border-b border-gray-800/60 px-5 py-4">
          <h2 className="text-lg font-semibold text-gray-50">Service Compliance</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800/60 text-left text-[11px] font-semibold uppercase tracking-wider text-gray-400">
                <th className="px-5 py-3.5 font-medium">Service</th>
                <th className="px-5 py-3.5 font-medium">Scope</th>
                <th className="px-5 py-3.5 font-medium">Violations</th>
                <th className="px-5 py-3.5 font-medium">Compliance Score</th>
                <th className="px-5 py-3.5 font-medium">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/40">
              {MOCK_SERVICES.map((s, i) => (
                <tr key={i} className="text-gray-300 hover:bg-gray-800/30">
                  <td className="px-5 py-3.5 font-mono text-xs text-gray-100">{s.service}</td>
                  <td className="px-5 py-3.5">{s.scope}</td>
                  <td className="px-5 py-3.5">{s.violations}</td>
                  <td className="px-5 py-3.5">{s.complianceScore}%</td>
                  <td className="px-5 py-3.5">
                    <StatusBadge status={s.status === "non-compliant" ? "non_compliant" : s.status} />
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
