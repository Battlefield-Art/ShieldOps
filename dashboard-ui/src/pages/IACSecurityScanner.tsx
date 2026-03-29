import { useState } from "react";
import { FileCode, Shield, AlertTriangle, Bug, Server, CheckSquare } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "misconfigs" | "policies" | "providers";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "misconfigs", label: "Misconfigs" }, { id: "policies", label: "Policies" }, { id: "providers", label: "Providers" }];
export default function IACSecurityScanner() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="IaC Security Scanner" subtitle="Scan Terraform, CloudFormation, and Kubernetes YAML for security misconfigurations" icon={<FileCode className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Templates" value="156" icon={<FileCode className="h-5 w-5" />} />
      <MetricCard title="Misconfigs" value="78" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Critical" value="9" icon={<Bug className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Auto-fixable" value="45%" icon={<CheckSquare className="h-5 w-5 text-emerald-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Misconfigurations by Category</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">
      {[{ cat: "IAM/Access", count: 22, color: "text-red-400" }, { cat: "Network", count: 18, color: "text-yellow-400" }, { cat: "Encryption", count: 15, color: "text-yellow-400" }, { cat: "Logging", count: 23, color: "text-white/60" }].map((c) => (
        <div key={c.cat} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{c.cat}</p><p className={clsx("text-3xl font-bold mt-1", c.color)}>{c.count}</p></div>))}</div></div>)}
    {tab === "misconfigs" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Finding</th><th className="px-4 py-3">File</th><th className="px-4 py-3">CIS</th><th className="px-4 py-3">Severity</th></tr></thead>
      <tbody>{[
        { finding: "Wildcard IAM action allowed", file: "infra/iam.tf:12", cis: "CIS 1.16", sev: "critical" },
        { finding: "Unrestricted ingress 0.0.0.0/0", file: "infra/sg.tf:28", cis: "CIS 4.1", sev: "high" },
        { finding: "Encryption disabled on S3", file: "infra/s3.tf:5", cis: "CIS 2.6", sev: "high" },
        { finding: "Logging disabled", file: "infra/rds.tf:18", cis: "CIS 3.1", sev: "medium" },
      ].map((f, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90">{f.finding}</td><td className="px-4 py-3 font-mono text-xs text-white/60">{f.file}</td><td className="px-4 py-3 text-cyan-400">{f.cis}</td><td className="px-4 py-3"><StatusBadge status={f.sev} /></td></tr>))}</tbody></table></div>)}
    {tab === "policies" && (<div className="space-y-3">
      {[{ policy: "deny_wildcard_iam", violations: 5, sev: "critical" },
        { policy: "deny_public_access", violations: 3, sev: "high" },
        { policy: "require_encryption", violations: 8, sev: "high" },
        { policy: "require_logging", violations: 12, sev: "medium" },
      ].map((p, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium font-mono">{p.policy}</p><p className="text-xs text-white/50">{p.violations} violations</p></div><StatusBadge status={p.sev} /></div>))}</div>)}
    {tab === "providers" && (<div className="card-surface p-6"><h3 className="section-heading">Provider Coverage</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">
      {[{ provider: "Terraform", templates: 89, misconfigs: 42 }, { provider: "K8s YAML", templates: 34, misconfigs: 18 }, { provider: "CloudFormation", templates: 21, misconfigs: 12 }, { provider: "Helm", templates: 12, misconfigs: 6 }].map((p) => (
        <div key={p.provider} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{p.provider}</p><p className="text-3xl font-bold mt-1 text-white/90">{p.templates}</p><p className="text-xs text-yellow-400">{p.misconfigs} issues</p></div>))}</div></div>)}
  </div>);
}
