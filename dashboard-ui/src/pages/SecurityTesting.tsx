import { useState } from "react";
import { Play, AlertTriangle, ShieldAlert, CheckCircle, Loader2 } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";

const FINDINGS = [
  { finding: "SQL Injection in /api/v1/users", category: "vulnerability", severity: "critical", resource: "payment-api", cve: "CVE-2024-3271", remediation: "Parameterize query" },
  { finding: "TLS 1.0 Enabled", category: "config", severity: "high", resource: "auth-lb-01", cve: "N/A", remediation: "Upgrade to TLS 1.3" },
  { finding: "Hardcoded AWS Key", category: "credential", severity: "critical", resource: "deploy-script.sh", cve: "N/A", remediation: "Use secrets manager" },
  { finding: "Missing CSP Header", category: "config", severity: "medium", resource: "web-frontend", cve: "N/A", remediation: "Add CSP header" },
  { finding: "Outdated OpenSSL", category: "vulnerability", severity: "high", resource: "nginx-proxy", cve: "CVE-2024-0727", remediation: "Upgrade to 3.2.1" },
  { finding: "PCI-DSS Log Gap", category: "compliance", severity: "medium", resource: "payment-db", cve: "N/A", remediation: "Enable audit logging" },
  { finding: "Weak SSH Config", category: "config", severity: "low", resource: "bastion-host", cve: "N/A", remediation: "Disable password auth" },
];

const CATEGORY_COLORS: Record<string, string> = {
  vulnerability: "bg-red-500/10 text-red-400 ring-red-500/20",
  config: "bg-blue-500/10 text-blue-400 ring-blue-500/20",
  credential: "bg-slate-500/10 text-slate-400 ring-slate-500/20",
  compliance: "bg-amber-500/10 text-amber-400 ring-amber-500/20",
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/10 text-red-400 ring-red-500/20",
  high: "bg-orange-500/10 text-orange-400 ring-orange-500/20",
  medium: "bg-yellow-500/10 text-yellow-400 ring-yellow-500/20",
  low: "bg-green-500/10 text-green-400 ring-green-500/20",
};

export default function SecurityTesting() {
  const [running, setRunning] = useState(false);
  const handleClick = () => { setRunning(true); setTimeout(() => setRunning(false), 2000); };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Security Testing</h1>
        <button onClick={handleClick} disabled={running} className="flex items-center gap-2 rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-500 disabled:opacity-50">
          {running && <Loader2 className="h-4 w-4 animate-spin" />}
          Run Security Test
        </button>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard label="Tests Run" value={156} icon={<Play className="h-5 w-5" />} change={12.0} />
        <MetricCard label="Critical Findings" value={2} icon={<ShieldAlert className="h-5 w-5" />} change={-50.0} />
        <MetricCard label="High Findings" value={5} icon={<AlertTriangle className="h-5 w-5" />} change={-16.7} />
        <MetricCard label="Pass Rate %" value={91} icon={<CheckCircle className="h-5 w-5" />} change={3.4} />
      </div>

      <div className="overflow-x-auto rounded-xl border border-gray-800 bg-gray-900">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-gray-800 text-xs uppercase text-gray-400">
            <tr>
              <th className="px-4 py-3">Finding</th>
              <th className="px-4 py-3">Category</th>
              <th className="px-4 py-3">Severity</th>
              <th className="px-4 py-3">Resource</th>
              <th className="px-4 py-3">CVE ID</th>
              <th className="px-4 py-3">Remediation</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800">
            {FINDINGS.map((f) => (
              <tr key={f.finding} className="hover:bg-gray-800/50">
                <td className="px-4 py-3 font-medium">{f.finding}</td>
                <td className="px-4 py-3">
                  <span className={clsx("inline-flex rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset", CATEGORY_COLORS[f.category])}>{f.category}</span>
                </td>
                <td className="px-4 py-3">
                  <span className={clsx("inline-flex rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset", SEVERITY_COLORS[f.severity])}>{f.severity}</span>
                </td>
                <td className="px-4 py-3 text-gray-300">{f.resource}</td>
                <td className="px-4 py-3 text-gray-400">{f.cve}</td>
                <td className="px-4 py-3 text-gray-400">{f.remediation}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
