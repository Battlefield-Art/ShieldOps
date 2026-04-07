import { useState } from "react";
import { ShieldCheck, Brain, Ban, Eye } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "threats" | "guardrails" | "runtime";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "threats", label: "Threats" }, { id: "guardrails", label: "Guardrails" }, { id: "runtime", label: "Runtime" }];
export default function AIRuntimeGuardian() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="AI Runtime Guardian" subtitle="Comprehensive AI runtime security — prompt, model, tool, agent, output" icon={<ShieldCheck className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="AI Apps Protected" value="34" icon={<Brain className="h-5 w-5" />} />
      <MetricCard title="Threats Blocked (24h)" value="89" icon={<Ban className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Guardrail Hits" value="234" icon={<ShieldCheck className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Coverage" value="100%" icon={<Eye className="h-5 w-5 text-emerald-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Threat Vectors (24h)</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {[{ vector: "Prompt Injection", blocked: 47, color: "text-red-400" }, { vector: "Tool Abuse", blocked: 23, color: "text-yellow-400" }, { vector: "Output Manipulation", blocked: 19, color: "text-yellow-400" }].map((v) => (
        <div key={v.vector} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{v.vector}</p><p className={clsx("text-3xl font-bold mt-1", v.color)}>{v.blocked}</p><p className="text-xs text-white/40">blocked</p></div>))}</div></div>)}
    {tab === "threats" && (<div className="space-y-3">
      {[{ id: "AIG-089", vector: "prompt_injection", app: "customer-chatbot", detail: "Multi-turn jailbreak attempt via role-play", action: "blocked" },
        { id: "AIG-088", vector: "tool_abuse", app: "data-agent-v3", detail: "Agent attempted file system access outside scope", action: "blocked" },
        { id: "AIG-087", vector: "agent_hijacking", app: "orchestrator", detail: "Injected instruction in agent delegation chain", action: "quarantined" },
        { id: "AIG-086", vector: "output_manipulation", app: "report-gen", detail: "Model output contained embedded JavaScript", action: "sanitized" },
      ].map((t) => (<div key={t.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{t.id}</span><span className="text-xs text-white/40 ml-2">{t.app}</span></div><StatusBadge status={t.action} /></div>
        <p className="text-white/90 font-medium">{t.vector}</p><p className="text-xs text-white/50">{t.detail}</p></div>))}</div>)}
    {tab === "guardrails" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Active Guardrails</h3>
      {[{ name: "Prompt Injection Defense", scope: "All AI apps", layers: "Regex + Semantic + LLM", hits: 47, status: "active" },
        { name: "Tool Scope Enforcement", scope: "Agent tools", layers: "Policy + OPA", hits: 23, status: "active" },
        { name: "Output Sanitization", scope: "All responses", layers: "Content filter + encoding", hits: 19, status: "active" },
        { name: "Model Behavior Monitor", scope: "All models", layers: "Behavioral baseline", hits: 5, status: "active" },
      ].map((g, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{g.name}</p><p className="text-xs text-white/50">{g.scope} | {g.layers} | {g.hits} hits</p></div><StatusBadge status={g.status} /></div>))}</div>)}
    {tab === "runtime" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">AI App</th><th className="px-4 py-3">Model</th><th className="px-4 py-3">Requests (24h)</th><th className="px-4 py-3">Threats</th><th className="px-4 py-3">Status</th></tr></thead>
      <tbody>{[
        { app: "customer-chatbot", model: "Claude Sonnet", reqs: "12.4K", threats: 23, status: "protected" },
        { app: "data-agent-v3", model: "Claude Haiku", reqs: "8.9K", threats: 12, status: "protected" },
        { app: "code-assistant", model: "Claude Opus", reqs: "3.2K", threats: 4, status: "protected" },
        { app: "internal-copilot", model: "GPT-4o", reqs: "5.6K", threats: 8, status: "protected" },
      ].map((r, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90">{r.app}</td><td className="px-4 py-3 text-white/60">{r.model}</td><td className="px-4 py-3 text-white/80">{r.reqs}</td><td className="px-4 py-3 text-red-400">{r.threats}</td><td className="px-4 py-3"><StatusBadge status={r.status} /></td></tr>))}</tbody></table></div>)}
  </div>);
}
