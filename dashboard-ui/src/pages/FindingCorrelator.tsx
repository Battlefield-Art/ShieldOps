import { useState } from "react";
import { Layers, Target, CheckCircle, AlertTriangle, GitBranch, Filter } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "correlations" | "duplicates" | "sources";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "correlations", label: "Correlations" }, { id: "duplicates", label: "Deduplication" }, { id: "sources", label: "Sources" }];
export default function FindingCorrelator() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Finding Correlator" subtitle="Deduplicate + correlate findings across all scanner agents" icon={<Layers className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Raw Findings" value="312" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="After Dedup" value="189" icon={<Filter className="h-5 w-5 text-cyan-400" />} />
      <MetricCard title="Correlation Groups" value="34" icon={<GitBranch className="h-5 w-5 text-cyan-400" />} />
      <MetricCard title="Duplicates Removed" value="123" icon={<CheckCircle className="h-5 w-5 text-emerald-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Finding Flow</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">
      {[{ stage: "Raw Input", count: 312, color: "text-yellow-400" }, { stage: "Deduplicated", count: 189, color: "text-cyan-400" }, { stage: "Correlated", count: 34, color: "text-emerald-400" }, { stage: "Prioritized", count: 189, color: "text-emerald-400" }].map((s) => (
        <div key={s.stage} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.stage}</p><p className={clsx("text-3xl font-bold mt-1", s.color)}>{s.count}</p></div>))}</div></div>)}
    {tab === "correlations" && (<div className="space-y-3">
      {[{ group: "web-server-42 attack chain", findings: ["SQLi in /api/users", "Weak SSH ciphers", "Outdated nginx"], sources: 3, severity: "critical" },
        { group: "IAM over-privilege cluster", findings: ["Lambda wildcard", "SA admin role", "Cross-account trust"], sources: 2, severity: "high" },
      ].map((g, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><p className="text-white/90 font-medium">{g.group}</p><StatusBadge status={g.severity} /></div>
        <ul className="text-xs text-white/50 space-y-1">{g.findings.map((f, j) => <li key={j}>- {f}</li>)}</ul><p className="text-xs text-white/40 mt-1">{g.sources} scanner sources</p></div>))}</div>)}
    {tab === "duplicates" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Deduplication Results</h3>
      {[{ vuln: "Open port 22 (SSH)", scanners: "network_pentest + cloud_pentest", action: "Merged into 1 finding" },
        { vuln: "Public S3 bucket", scanners: "cloud_pentest + exposure_management", action: "Merged into 1 finding" },
        { vuln: "Weak TLS configuration", scanners: "web_app_scanner + network_pentest", action: "Merged into 1 finding" },
      ].map((d, i) => (<div key={i} className="card-interactive p-4"><p className="text-white/90 font-medium">{d.vuln}</p><p className="text-xs text-white/50">Found by: {d.scanners} | {d.action}</p></div>))}</div>)}
    {tab === "sources" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Source Agent</th><th className="px-4 py-3">Findings</th><th className="px-4 py-3">Unique</th><th className="px-4 py-3">Duplicates</th></tr></thead>
      <tbody>{[
        { src: "network_pentest", total: 89, unique: 67, dups: 22 },
        { src: "web_app_scanner", total: 67, unique: 52, dups: 15 },
        { src: "cloud_pentest", total: 78, unique: 45, dups: 33 },
        { src: "api_pentest", total: 45, unique: 34, dups: 11 },
        { src: "credential_tester", total: 23, unique: 18, dups: 5 },
        { src: "exposure_management", total: 34, unique: 12, dups: 22 },
      ].map((s, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90">{s.src}</td><td className="px-4 py-3 text-white/80">{s.total}</td><td className="px-4 py-3 text-emerald-400">{s.unique}</td><td className="px-4 py-3 text-white/40">{s.dups}</td></tr>))}</tbody></table></div>)}
  </div>);
}
