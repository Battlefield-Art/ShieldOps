import { ShieldCheck, BarChart3, AlertTriangle, Clock, ClipboardCheck } from "lucide-react";
import MetricCard from "../components/MetricCard";
import StatusBadge from "../components/StatusBadge";

const MOCK_FRAMEWORKS = [
  { name: "SOC 2 Type II", score: 94, color: "text-green-400" },
  { name: "PCI-DSS v4.0", score: 87, color: "text-green-400" },
  { name: "HIPAA", score: 91, color: "text-green-400" },
  { name: "GDPR", score: 78, color: "text-yellow-400" },
  { name: "ISO 27001", score: 82, color: "text-yellow-400" },
];

const MOCK_FINDINGS = [
  { controlId: "CC6.1", framework: "SOC 2", status: "compliant", evidence: "Auto-collected", gap: "—" },
  { controlId: "REQ-3.4", framework: "PCI-DSS", status: "non-compliant", evidence: "Missing", gap: "Encryption at rest not verified" },
  { controlId: "164.312(a)", framework: "HIPAA", status: "compliant", evidence: "Auto-collected", gap: "—" },
  { controlId: "Art. 32", framework: "GDPR", status: "partial", evidence: "Partial", gap: "DPA review pending" },
  { controlId: "A.12.4.1", framework: "ISO 27001", status: "compliant", evidence: "Auto-collected", gap: "—" },
  { controlId: "CC7.2", framework: "SOC 2", status: "partial", evidence: "Partial", gap: "Incident response drill overdue" },
  { controlId: "REQ-10.1", framework: "PCI-DSS", status: "compliant", evidence: "Auto-collected", gap: "—" },
];

function scoreColor(score: number): string {
  if (score >= 90) return "text-green-400";
  if (score >= 80) return "text-yellow-400";
  return "text-red-400";
}


export default function ComplianceAudit() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-100">Compliance Auditor</h1>
        <button className="flex items-center gap-2 rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-500">
          <ClipboardCheck className="h-4 w-4" /> Run Audit
        </button>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard label="Frameworks Assessed" value={5} icon={<ShieldCheck className="h-5 w-5" />} change={0} />
        <MetricCard label="Controls Compliant %" value="86.4%" icon={<BarChart3 className="h-5 w-5" />} change={1.8} />
        <MetricCard label="Gaps Found" value={7} icon={<AlertTriangle className="h-5 w-5" />} change={-12} />
        <MetricCard label="Last Scan" value="2h ago" icon={<Clock className="h-5 w-5" />} />
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-5">
        {MOCK_FRAMEWORKS.map((fw) => (
          <div key={fw.name} className="rounded-xl border border-gray-800 bg-gray-900 p-5 text-center">
            <p className="text-sm font-medium text-gray-400">{fw.name}</p>
            <p className={`mt-2 text-3xl font-bold ${scoreColor(fw.score)}`}>{fw.score}%</p>
            <div className="mt-3 h-1.5 rounded-full bg-gray-800">
              <div
                className={`h-1.5 rounded-full ${fw.score >= 90 ? "bg-green-500" : fw.score >= 80 ? "bg-yellow-500" : "bg-red-500"}`}
                style={{ width: `${fw.score}%` }}
              />
            </div>
          </div>
        ))}
      </div>

      <div className="overflow-hidden rounded-xl border border-gray-800 bg-gray-900">
        <div className="border-b border-gray-800 px-5 py-4">
          <h2 className="text-lg font-semibold text-gray-100">Recent Audit Findings</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-left text-gray-400">
                <th className="px-5 py-3 font-medium">Control ID</th>
                <th className="px-5 py-3 font-medium">Framework</th>
                <th className="px-5 py-3 font-medium">Status</th>
                <th className="px-5 py-3 font-medium">Evidence</th>
                <th className="px-5 py-3 font-medium">Gap</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {MOCK_FINDINGS.map((f, i) => (
                <tr key={i} className="text-gray-300 hover:bg-gray-800/50">
                  <td className="px-5 py-3 font-mono text-xs text-gray-100">{f.controlId}</td>
                  <td className="px-5 py-3">{f.framework}</td>
                  <td className="px-5 py-3">
                    <StatusBadge
                      status={f.status}
                      variant={f.status === "compliant" ? "success" : f.status === "non-compliant" ? "error" : "warning"}
                    />
                  </td>
                  <td className="px-5 py-3">{f.evidence}</td>
                  <td className="px-5 py-3 text-gray-400">{f.gap}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
