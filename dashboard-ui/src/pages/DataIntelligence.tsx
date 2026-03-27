import { useState } from "react";
import { Database, Brain, Shield, Eye, BarChart3, GitBranch } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "classification" | "lineage" | "protection";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "classification", label: "Classification" }, { id: "lineage", label: "Lineage" }, { id: "protection", label: "Protection" }];
export default function DataIntelligence() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Data Intelligence" subtitle="AI-native data classification, risk assessment, and lineage tracking" icon={<Database className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Data Assets" value="2.4K" icon={<Database className="h-5 w-5" />} />
      <MetricCard title="AI Classified" value="98.2%" icon={<Brain className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="At Risk" value="34" icon={<Shield className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Lineage Mapped" value="89%" icon={<GitBranch className="h-5 w-5 text-cyan-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Data by Domain</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {[{ domain: "Structured (DBs)", count: 890, classified: "99%", color: "text-emerald-400" }, { domain: "Unstructured (Files)", count: 1200, classified: "97%", color: "text-cyan-400" }, { domain: "AI Artifacts", count: 310, classified: "98%", color: "text-yellow-400" }].map((d) => (
        <div key={d.domain} className="card-interactive p-4"><p className={clsx("font-bold", d.color)}>{d.domain}</p><p className="text-2xl font-bold text-white/80 mt-1">{d.count}</p><p className="text-xs text-white/40">{d.classified} classified</p></div>))}</div></div>)}
    {tab === "classification" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Asset</th><th className="px-4 py-3">Domain</th><th className="px-4 py-3">Classification</th><th className="px-4 py-3">Risk</th></tr></thead>
      <tbody>{[
        { asset: "customer-db", domain: "structured", cls: "PII + PCI", risk: "high" },
        { asset: "training-data-v3", domain: "ai_training", cls: "IP + PII", risk: "critical" },
        { asset: "embeddings-prod", domain: "embedding", cls: "Derived PII", risk: "medium" },
        { asset: "model-weights-v3", domain: "model_artifact", cls: "Trade Secret", risk: "critical" },
      ].map((c, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90">{c.asset}</td><td className="px-4 py-3"><StatusBadge status={c.domain} /></td><td className="px-4 py-3 text-white/70">{c.cls}</td><td className="px-4 py-3"><StatusBadge status={c.risk} /></td></tr>))}</tbody></table></div>)}
    {tab === "lineage" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Data Lineage</h3>
      {[{ source: "customer-db", transforms: "Extract → Anonymize → Embed", dest: "RAG Index", verified: true },
        { source: "raw-logs", transforms: "Parse → Enrich → Aggregate", dest: "SIEM", verified: true },
        { source: "customer-db", transforms: "Extract → NO ANONYMIZE", dest: "Training Data", verified: false },
      ].map((l, i) => (<div key={i} className="card-interactive p-4"><p className="text-white/90 font-medium font-mono text-sm">{l.source} → {l.transforms} → {l.dest}</p><p className="text-xs mt-1">{l.verified ? <span className="text-emerald-400">Verified lineage</span> : <span className="text-red-400">ALERT: Missing anonymization step</span>}</p></div>))}</div>)}
    {tab === "protection" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Protection Recommendations</h3>
      {[{ asset: "training-data-v3", rec: "Add PII anonymization before model training", priority: "critical", status: "pending" },
        { asset: "model-weights-v3", rec: "Enable immutable lock + access audit", priority: "critical", status: "in_progress" },
        { asset: "embeddings-prod", rec: "Restrict access to ML team only", priority: "high", status: "completed" },
      ].map((p, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{p.rec}</p><p className="text-xs text-white/50">{p.asset} | {p.priority}</p></div><StatusBadge status={p.status} /></div>))}</div>)}
  </div>);
}
