import { useState } from "react";
import { Lock, Database, Bug, Shield, CheckCircle, FileSearch } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "models" | "provenance" | "threats";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "models", label: "Model Inventory" }, { id: "provenance", label: "Provenance" }, { id: "threats", label: "Threat Detection" }];
export default function ModelSecurity() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Model Security" subtitle="Model integrity verification, backdoor detection, and supply chain security" icon={<Lock className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Models Tracked" value="23" icon={<Database className="h-5 w-5" />} />
      <MetricCard title="Provenance Verified" value="19" icon={<CheckCircle className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Backdoor Alerts" value="2" icon={<Bug className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Integrity Score" value="94.2%" icon={<Shield className="h-5 w-5 text-cyan-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Model Security Posture</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {[{ label: "Verified Models", count: 19, color: "text-emerald-400" }, { label: "Pending Verification", count: 2, color: "text-yellow-400" }, { label: "Integrity Issues", count: 2, color: "text-red-400" }].map((s) => (
        <div key={s.label} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.label}</p><p className={clsx("text-3xl font-bold mt-1", s.color)}>{s.count}</p></div>))}</div></div>)}
    {tab === "models" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Model</th><th className="px-4 py-3">Source</th><th className="px-4 py-3">Version</th><th className="px-4 py-3">Integrity</th><th className="px-4 py-3">Status</th></tr></thead>
      <tbody>{[
        { name: "claude-sonnet-4", source: "Anthropic", version: "4.0", integrity: "verified", status: "active" },
        { name: "gpt-4o", source: "OpenAI", version: "2024-08", integrity: "verified", status: "active" },
        { name: "custom-rag-v3", source: "Self-hosted", version: "3.1", integrity: "unverified", status: "review" },
        { name: "llama-3-70b-ft", source: "HuggingFace", version: "3.0-ft", integrity: "tampered", status: "blocked" },
      ].map((m, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90 font-medium">{m.name}</td><td className="px-4 py-3 text-white/60">{m.source}</td><td className="px-4 py-3 font-mono text-xs text-white/70">{m.version}</td><td className="px-4 py-3"><StatusBadge status={m.integrity} /></td><td className="px-4 py-3"><StatusBadge status={m.status} /></td></tr>))}</tbody></table></div>)}
    {tab === "provenance" && (<div className="space-y-3">
      {[{ model: "claude-sonnet-4", source: "Anthropic API", checksum: "sha256:a4e8f2...", lineage: "Direct API", verified: true },
        { model: "custom-rag-v3", source: "Internal registry", checksum: "sha256:b7c1d3...", lineage: "Fine-tuned from base", verified: false },
        { model: "llama-3-70b-ft", source: "HuggingFace Hub", checksum: "sha256:MISMATCH", lineage: "Community fine-tune", verified: false },
      ].map((p, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><p className="text-white/90 font-medium">{p.model}</p>{p.verified ? <CheckCircle className="h-4 w-4 text-emerald-400" /> : <FileSearch className="h-4 w-4 text-yellow-400" />}</div>
        <p className="text-xs text-white/50">Source: {p.source} | Checksum: <span className="font-mono">{p.checksum}</span></p><p className="text-xs text-white/50">Lineage: {p.lineage}</p></div>))}</div>)}
    {tab === "threats" && (<div className="space-y-3">
      {[{ id: "MDL-001", model: "llama-3-70b-ft", type: "Checksum Mismatch", method: "Cryptographic", severity: "critical", detail: "Model weights differ from registered hash" },
        { id: "MDL-002", model: "custom-rag-v3", type: "Suspicious Activation Pattern", method: "Statistical", severity: "high", detail: "Anomalous neuron activation on trigger phrases" },
      ].map((t) => (<div key={t.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{t.id}</span><span className="text-xs text-white/40 ml-2">{t.model}</span></div><StatusBadge status={t.severity} /></div>
        <p className="text-white/90 font-medium">{t.type}</p><p className="text-xs text-white/50">{t.detail} | Method: {t.method}</p></div>))}</div>)}
  </div>);
}
