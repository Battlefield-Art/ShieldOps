import { useState } from "react";
import { ShieldAlert, Scan, Zap, BarChart3, Ban } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "detections" | "patterns" | "policies";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "detections", label: "Detections" }, { id: "patterns", label: "Attack Patterns" }, { id: "policies", label: "Policies" }];
export default function PromptShield() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Prompt Shield" subtitle="Multi-layer prompt injection and jailbreak defense" icon={<ShieldAlert className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Prompts Scanned (24h)" value="14.2K" icon={<Scan className="h-5 w-5" />} />
      <MetricCard title="Injections Blocked" value="47" icon={<Ban className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Jailbreak Attempts" value="12" icon={<Zap className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Detection Rate" value="99.7%" icon={<BarChart3 className="h-5 w-5 text-emerald-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Defense Summary (24h)</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">
      {[{ label: "Clean", count: "14.1K", color: "text-emerald-400" }, { label: "Suspicious", count: 23, color: "text-yellow-400" }, { label: "Injection", count: 47, color: "text-red-400" }, { label: "Jailbreak", count: 12, color: "text-red-400" }].map((s) => (
        <div key={s.label} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.label}</p><p className={clsx("text-3xl font-bold mt-1", s.color)}>{s.count}</p></div>))}</div></div>)}
    {tab === "detections" && (<div className="space-y-3">
      {[{ id: "INJ-001", app: "customer-chatbot", type: "Direct Injection", pattern: "Ignore previous instructions...", verdict: "blocked", layer: "Regex + Semantic" },
        { id: "INJ-002", app: "internal-copilot", type: "Indirect Injection", pattern: "Base64 encoded payload in document", verdict: "blocked", layer: "Behavioral" },
        { id: "JBK-001", app: "support-agent", type: "Jailbreak", pattern: "DAN role-play attempt", verdict: "blocked", layer: "LLM-based" },
        { id: "INJ-003", app: "data-analyst", type: "System Prompt Extraction", pattern: "Repeat your system prompt", verdict: "suspicious", layer: "Semantic" },
      ].map((d) => (<div key={d.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{d.id}</span><span className="text-xs text-white/40 ml-2">{d.app}</span></div><StatusBadge status={d.verdict} /></div>
        <p className="text-white/90 font-medium">{d.type}</p><p className="text-xs text-white/50">{d.pattern} | Layer: {d.layer}</p></div>))}</div>)}
    {tab === "patterns" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Pattern</th><th className="px-4 py-3">Category</th><th className="px-4 py-3">Detections</th><th className="px-4 py-3">Evolution</th><th className="px-4 py-3">Defense</th></tr></thead>
      <tbody>{[
        { pattern: "Ignore previous instructions", cat: "Direct Injection", count: 31, evolution: "established", defense: "hardened" },
        { pattern: "Base64/ROT13 encoded payloads", cat: "Encoding Bypass", count: 8, evolution: "emerging", defense: "partial" },
        { pattern: "DAN / Do Anything Now", cat: "Role-Play Jailbreak", count: 6, evolution: "established", defense: "defended" },
        { pattern: "Multi-turn context manipulation", cat: "Context Manipulation", count: 4, evolution: "novel", defense: "undefended" },
      ].map((p, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90 font-medium">{p.pattern}</td><td className="px-4 py-3 text-white/60">{p.cat}</td><td className="px-4 py-3 text-white/80">{p.count}</td><td className="px-4 py-3"><StatusBadge status={p.evolution} /></td><td className="px-4 py-3"><StatusBadge status={p.defense} /></td></tr>))}</tbody></table></div>)}
    {tab === "policies" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Active Defense Policies</h3>
      {[{ name: "Block Direct Injection", apps: "All", layers: "Regex + Semantic + LLM", action: "Block + Alert", status: "active" },
        { name: "Jailbreak Prevention", apps: "Customer-facing", layers: "Behavioral + LLM", action: "Block + Escalate", status: "active" },
        { name: "System Prompt Protection", apps: "All", layers: "Semantic", action: "Sanitize + Log", status: "active" },
        { name: "Encoded Payload Detection", apps: "All", layers: "Regex + Behavioral", action: "Block + Alert", status: "active" },
      ].map((p, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{p.name}</p><p className="text-xs text-white/50">Apps: {p.apps} | Layers: {p.layers} | Action: {p.action}</p></div><StatusBadge status={p.status} /></div>))}</div>)}
  </div>);
}
