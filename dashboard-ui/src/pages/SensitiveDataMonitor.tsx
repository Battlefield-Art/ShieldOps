import { useState } from "react";
import { Eye, FileSearch, Shield, Database, Lock, AlertTriangle } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "sources" | "classifications" | "exposures";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "sources", label: "Data Sources" }, { id: "classifications", label: "Classifications" }, { id: "exposures", label: "Exposures" }];
export default function SensitiveDataMonitor() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Sensitive Data Monitor" subtitle="Continuous classification across databases, cloud, backups, and AI pipelines" icon={<Eye className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Sources Monitored" value="34" icon={<Database className="h-5 w-5" />} />
      <MetricCard title="Sensitive Records" value="12.4K" icon={<FileSearch className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Exposed" value="47" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Compliance" value="94.7%" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Data Classification Summary</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">
      {[{ type: "PII", count: "5.2K", regulation: "GDPR", color: "text-yellow-400" }, { type: "PHI", count: "3.1K", regulation: "HIPAA", color: "text-red-400" }, { type: "PCI", count: "2.8K", regulation: "PCI DSS", color: "text-red-400" }, { type: "Credentials", count: "1.3K", regulation: "SOC 2", color: "text-cyan-400" }].map((d) => (
        <div key={d.type} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{d.type}</p><p className={clsx("text-3xl font-bold mt-1", d.color)}>{d.count}</p><p className="text-xs text-white/40">{d.regulation}</p></div>))}</div></div>)}
    {tab === "sources" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Source</th><th className="px-4 py-3">Type</th><th className="px-4 py-3">Sensitive</th><th className="px-4 py-3">Last Scan</th><th className="px-4 py-3">Status</th></tr></thead>
      <tbody>{[
        { src: "customer-db", type: "PostgreSQL", sensitive: 4200, scan: "5 min ago", status: "monitored" },
        { src: "s3-data-lake", type: "Cloud Storage", sensitive: 3100, scan: "15 min ago", status: "monitored" },
        { src: "llm-prompts", type: "AI Pipeline", sensitive: 890, scan: "Real-time", status: "monitored" },
        { src: "backup-vault", type: "Backup", sensitive: 4200, scan: "1h ago", status: "monitored" },
      ].map((s, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90 font-medium">{s.src}</td><td className="px-4 py-3 text-white/60">{s.type}</td><td className="px-4 py-3 text-white/80">{s.sensitive.toLocaleString()}</td><td className="px-4 py-3 text-white/50">{s.scan}</td><td className="px-4 py-3"><StatusBadge status={s.status} /></td></tr>))}</tbody></table></div>)}
    {tab === "classifications" && (<div className="space-y-3">
      {[{ data: "Customer SSNs", category: "PII", regulation: "GDPR Art. 9", exposure: "encrypted", sources: 2, status: "compliant" },
        { data: "Patient Records", category: "PHI", regulation: "HIPAA", exposure: "restricted", sources: 1, status: "compliant" },
        { data: "Credit Card Numbers", category: "PCI", regulation: "PCI DSS 3.4", exposure: "internal", sources: 3, status: "at_risk" },
        { data: "API Keys in Prompts", category: "Credentials", regulation: "SOC 2", exposure: "shared", sources: 1, status: "violation" },
      ].map((c, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><p className="text-white/90 font-medium">{c.data}</p><span className="text-xs text-white/40">{c.category} | {c.regulation}</span></div><StatusBadge status={c.status} /></div>
        <p className="text-xs text-white/50">Exposure: {c.exposure} | Found in {c.sources} sources</p></div>))}</div>)}
    {tab === "exposures" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Active Exposures</h3>
      {[{ data: "API keys detected in LLM prompts", severity: "critical", source: "AI Pipeline", action: "Auto-sanitized" },
        { data: "PCI data in unencrypted S3 bucket", severity: "high", source: "Cloud Storage", action: "Encryption enforced" },
        { data: "PHI in shared backup without access controls", severity: "high", source: "Backup", action: "ACL applied" },
      ].map((e, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{e.data}</p><p className="text-xs text-white/50">{e.source} | Action: {e.action}</p></div><StatusBadge status={e.severity} /></div>))}</div>)}
  </div>);
}
