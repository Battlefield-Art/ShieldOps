import { useState } from "react";
import { Cloud, Shield, Key, Code, BarChart3, AlertTriangle } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "cspm" | "cwpp" | "ciem";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "cspm", label: "CSPM" }, { id: "cwpp", label: "CWPP" }, { id: "ciem", label: "CIEM" }];
export default function CNAPPAnalyzer() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="CNAPP Analyzer" subtitle="Unified CSPM + CWPP + CIEM + Code Security — multi-cloud, vendor-neutral" icon={<Cloud className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Posture Findings" value="34" icon={<Shield className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Workload Threats" value="7" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Over-Privileged IDs" value="23" icon={<Key className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Code Vulns" value="12" icon={<Code className="h-5 w-5 text-red-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Unified Risk by Domain</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">
      {[{ domain: "CSPM", score: 72, findings: 34, color: "text-yellow-400" }, { domain: "CWPP", score: 85, findings: 7, color: "text-emerald-400" }, { domain: "CIEM", score: 61, findings: 23, color: "text-red-400" }, { domain: "Code Security", score: 78, findings: 12, color: "text-cyan-400" }].map((d) => (
        <div key={d.domain} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{d.domain}</p><p className={clsx("text-3xl font-bold mt-1", d.color)}>{d.score}%</p><p className="text-xs text-white/40">{d.findings} findings</p></div>))}</div></div>)}
    {tab === "cspm" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Finding</th><th className="px-4 py-3">Cloud</th><th className="px-4 py-3">Benchmark</th><th className="px-4 py-3">Severity</th></tr></thead>
      <tbody>{[
        { finding: "S3 bucket public access", cloud: "AWS", bench: "CIS 2.1.1", sev: "critical" },
        { finding: "Firewall rule allows 0.0.0.0/0", cloud: "GCP", bench: "CIS 3.6", sev: "high" },
        { finding: "Storage account no encryption", cloud: "Azure", bench: "CIS 3.1", sev: "high" },
        { finding: "Default VPC in use", cloud: "AWS", bench: "CIS 2.6", sev: "medium" },
      ].map((f, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90">{f.finding}</td><td className="px-4 py-3 text-white/60">{f.cloud}</td><td className="px-4 py-3 font-mono text-xs text-cyan-400">{f.bench}</td><td className="px-4 py-3"><StatusBadge status={f.sev} /></td></tr>))}</tbody></table></div>)}
    {tab === "cwpp" && (<div className="space-y-3">
      {[{ id: "WRK-007", type: "Container image CVE", target: "nginx:1.21", cve: "CVE-2024-1234", severity: "critical", runtime: true },
        { id: "WRK-006", type: "Cryptominer process", target: "worker-pod-3", cve: "Runtime", severity: "critical", runtime: true },
        { id: "WRK-005", type: "Outdated base image", target: "api-service:v2", cve: "Multiple", severity: "high", runtime: false },
      ].map((w) => (<div key={w.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{w.id}</span>{w.runtime && <span className="text-xs text-red-400 ml-2">RUNTIME</span>}</div><StatusBadge status={w.severity} /></div>
        <p className="text-white/90 font-medium">{w.type}</p><p className="text-xs text-white/50">Target: {w.target} | {w.cve}</p></div>))}</div>)}
    {tab === "ciem" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Identity</th><th className="px-4 py-3">Cloud</th><th className="px-4 py-3">Risk</th><th className="px-4 py-3">Recommendation</th></tr></thead>
      <tbody>{[
        { id: "sa-admin@gcp", cloud: "GCP", risk: "over_privileged", rec: "Remove 12 unused permissions" },
        { id: "LambdaExecRole", cloud: "AWS", risk: "over_privileged", rec: "Restrict to 3 required actions" },
        { id: "deploy-bot", cloud: "Azure", risk: "stale", rec: "Unused 90d — disable or remove" },
        { id: "ci-pipeline-sa", cloud: "GCP", risk: "shared", rec: "Split into per-service accounts" },
      ].map((e, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90 font-mono text-sm">{e.id}</td><td className="px-4 py-3 text-white/60">{e.cloud}</td><td className="px-4 py-3"><StatusBadge status={e.risk} /></td><td className="px-4 py-3 text-white/70 text-xs">{e.rec}</td></tr>))}</tbody></table></div>)}
  </div>);
}
