import { useState } from "react";
import { Package, Shield, AlertTriangle, Database, Lock } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "assets" | "findings" | "integrity";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "assets", label: "AI Assets" }, { id: "findings", label: "Findings" }, { id: "integrity", label: "Integrity" }];
export default function SupplyChainScanner() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="AI Supply Chain Scanner" subtitle="RAG poisoning detection, model registry scanning, prompt template integrity" icon={<Package className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="AI Assets" value="89" icon={<Database className="h-5 w-5" />} />
      <MetricCard title="Threats Found" value="7" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Integrity Score" value="93.4%" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Last Scan" value="15m ago" icon={<Lock className="h-5 w-5 text-cyan-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Supply Chain by Component</h3><div className="grid grid-cols-1 md:grid-cols-5 gap-3">
      {[{ type: "Models", count: 23, threats: 2, color: "text-yellow-400" }, { type: "RAG Docs", count: 34, threats: 3, color: "text-red-400" }, { type: "Templates", count: 12, threats: 1, color: "text-yellow-400" }, { type: "Tools", count: 8, threats: 1, color: "text-yellow-400" }, { type: "Training", count: 12, threats: 0, color: "text-emerald-400" }].map((c) => (
        <div key={c.type} className="card-interactive p-3 text-center"><p className="text-xs text-white/60">{c.type}</p><p className={clsx("text-2xl font-bold mt-1", c.color)}>{c.count}</p><p className="text-xs text-white/40">{c.threats} threats</p></div>))}</div></div>)}
    {tab === "assets" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Asset</th><th className="px-4 py-3">Type</th><th className="px-4 py-3">Provenance</th><th className="px-4 py-3">Status</th></tr></thead>
      <tbody>{[
        { name: "claude-ft-v3", type: "model_weight", prov: "Anthropic API", status: "verified" },
        { name: "customer-faq.md", type: "rag_document", prov: "Internal CMS", status: "clean" },
        { name: "investigation-prompt.yaml", type: "prompt_template", prov: "Git repo", status: "verified" },
        { name: "malicious-doc-42.pdf", type: "rag_document", prov: "External upload", status: "poisoned" },
      ].map((a, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90">{a.name}</td><td className="px-4 py-3"><StatusBadge status={a.type} /></td><td className="px-4 py-3 text-white/60">{a.prov}</td><td className="px-4 py-3"><StatusBadge status={a.status} /></td></tr>))}</tbody></table></div>)}
    {tab === "findings" && (<div className="space-y-3">
      {[{ id: "SC-007", type: "RAG poisoning", asset: "malicious-doc-42.pdf", detail: "Adversarial content designed to manipulate LLM responses", severity: "critical" },
        { id: "SC-006", type: "Model backdoor", asset: "custom-classifier-v2", detail: "Anomalous activation pattern on trigger phrase", severity: "high" },
        { id: "SC-005", type: "Prompt injection template", asset: "support-prompt.yaml", detail: "Template allows user input in system prompt section", severity: "high" },
      ].map((f) => (<div key={f.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{f.id}</span><span className="text-xs text-white/40 ml-2">{f.asset}</span></div><StatusBadge status={f.severity} /></div>
        <p className="text-white/90 font-medium">{f.type}</p><p className="text-xs text-white/50">{f.detail}</p></div>))}</div>)}
    {tab === "integrity" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Integrity Chain</h3>
      {[{ asset: "claude-ft-v3", method: "SHA-256 + signature", status: "verified", last: "15m ago" },
        { asset: "RAG corpus (34 docs)", method: "Content scan + embedding analysis", status: "3 quarantined", last: "1h ago" },
        { asset: "Prompt templates (12)", method: "Injection pattern scan", status: "1 flagged", last: "30m ago" },
        { asset: "Tool definitions (8)", method: "Schema + permission audit", status: "1 over-scoped", last: "2h ago" },
      ].map((i, idx) => (<div key={idx} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{i.asset}</p><p className="text-xs text-white/50">{i.method} | Last: {i.last}</p></div><StatusBadge status={i.status} /></div>))}</div>)}
  </div>);
}
