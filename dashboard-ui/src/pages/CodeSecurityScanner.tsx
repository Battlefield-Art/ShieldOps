import { useState } from "react";
import { Code, Shield, AlertTriangle, FileSearch, GitBranch, Bug } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "iac" | "dependencies" | "code";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "iac", label: "IaC Scanning" }, { id: "dependencies", label: "Dependencies" }, { id: "code", label: "Code Analysis" }];
export default function CodeSecurityScanner() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Code Security Scanner" subtitle="Shift-left IaC, dependency, and application code scanning with LLM reasoning" icon={<Code className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Repos Scanned" value="34" icon={<GitBranch className="h-5 w-5" />} />
      <MetricCard title="Total Findings" value="89" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Critical" value="7" icon={<Bug className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Fix Rate (30d)" value="87%" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Findings by Category</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">
      {[{ cat: "IaC Misconfig", count: 34, color: "text-yellow-400" }, { cat: "Vulnerable Deps", count: 28, color: "text-red-400" }, { cat: "Code Vulns", count: 19, color: "text-yellow-400" }, { cat: "AI Config", count: 8, color: "text-cyan-400" }].map((c) => (
        <div key={c.cat} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{c.cat}</p><p className={clsx("text-3xl font-bold mt-1", c.color)}>{c.count}</p></div>))}</div></div>)}
    {tab === "iac" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Finding</th><th className="px-4 py-3">File</th><th className="px-4 py-3">Platform</th><th className="px-4 py-3">Severity</th></tr></thead>
      <tbody>{[
        { finding: "S3 bucket without encryption", file: "infra/s3.tf", platform: "Terraform", sev: "critical" },
        { finding: "Security group allows 0.0.0.0/0", file: "infra/vpc.tf", platform: "Terraform", sev: "high" },
        { finding: "Container runs as root", file: "k8s/deploy.yaml", platform: "Kubernetes", sev: "high" },
        { finding: "Prompt template with injection risk", file: "agents/config.yaml", platform: "AI Config", sev: "medium" },
      ].map((f, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90">{f.finding}</td><td className="px-4 py-3 font-mono text-xs text-white/60">{f.file}</td><td className="px-4 py-3 text-white/70">{f.platform}</td><td className="px-4 py-3"><StatusBadge status={f.sev} /></td></tr>))}</tbody></table></div>)}
    {tab === "dependencies" && (<div className="space-y-3">
      {[{ pkg: "lodash@4.17.20", vuln: "CVE-2024-XXXX", severity: "critical", fix: "Upgrade to 4.17.22", repos: 12 },
        { pkg: "requests@2.28.0", vuln: "CVE-2023-YYYY", severity: "high", fix: "Upgrade to 2.31.0", repos: 8 },
        { pkg: "langchain@0.1.0", vuln: "Prompt injection via tool output", severity: "high", fix: "Upgrade to 0.2.0", repos: 3 },
      ].map((d, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><p className="text-white/90 font-medium font-mono">{d.pkg}</p><StatusBadge status={d.severity} /></div>
        <p className="text-xs text-white/50">{d.vuln} | Fix: {d.fix} | {d.repos} repos affected</p></div>))}</div>)}
    {tab === "code" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">LLM-Detected Code Issues</h3>
      {[{ file: "api/auth.py:42", issue: "SQL injection via unsanitized user input", type: "OWASP A03", severity: "critical" },
        { file: "agents/tools.py:89", issue: "Command injection in subprocess call", type: "OWASP A03", severity: "critical" },
        { file: "utils/crypto.py:15", issue: "Weak random number generator for token", type: "CWE-338", severity: "high" },
      ].map((c, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{c.issue}</p><p className="text-xs text-white/50"><span className="font-mono text-cyan-400">{c.file}</span> | {c.type}</p></div><StatusBadge status={c.severity} /></div>))}</div>)}
  </div>);
}
