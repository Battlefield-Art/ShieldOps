import { useState } from "react";
import { Shield, AlertTriangle, Zap, Eye, Filter, BarChart3 } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "intercepted_prompts" | "injection_attempts" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "intercepted_prompts", label: "Intercepted Prompts" },
  { id: "injection_attempts", label: "Injection Attempts" },
  { id: "metrics", label: "Metrics" },
];

const INTERCEPTED = [
  { id: "PF-001", model: "claude-3.5-sonnet", category: "jailbreak", risk_score: 0.94, action: "blocked", time: "2m ago" },
  { id: "PF-002", model: "gpt-4o", category: "data_exfil", risk_score: 0.87, action: "blocked", time: "8m ago" },
  { id: "PF-003", model: "claude-3.5-sonnet", category: "role_override", risk_score: 0.72, action: "flagged", time: "15m ago" },
  { id: "PF-004", model: "llama-3.1-70b", category: "indirect_injection", risk_score: 0.91, action: "blocked", time: "22m ago" },
];

const INJECTIONS = [
  { id: "INJ-001", vector: "System prompt override", technique: "DAN variant", severity: "critical", source: "api-gateway", blocked: true },
  { id: "INJ-002", vector: "Base64 encoded payload", technique: "Encoding bypass", severity: "high", source: "chat-ui", blocked: true },
  { id: "INJ-003", vector: "Multi-turn context manipulation", technique: "Context window abuse", severity: "high", source: "agent-sdk", blocked: false },
];

export default function LlmPromptFirewall() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="LLM Prompt Firewall" subtitle="Real-time prompt injection detection and defense" icon={<Shield className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Prompts Scanned (24h)" value="45,210" icon={<Filter className="h-5 w-5" />} />
        <MetricCard title="Injections Blocked" value="127" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Detection Rate" value="99.2%" icon={<Zap className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Avg Latency" value="12ms" icon={<BarChart3 className="h-5 w-5 text-emerald-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Threat Categories</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Jailbreak", v: "42", c: "text-red-400" }, { l: "Data Exfil", v: "31", c: "text-yellow-400" }, { l: "Indirect Injection", v: "38", c: "text-cyan-400" }, { l: "Role Override", v: "16", c: "text-white/70" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "intercepted_prompts" && (<div className="space-y-3">{INTERCEPTED.map((p) => (<div key={p.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{p.id}</span><span className="ml-2 text-xs text-white/40">{p.model}</span></div><StatusBadge status={p.action} /></div><p className="text-white/90 text-sm">Category: <span className="text-yellow-400">{p.category}</span></p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>Risk: {(p.risk_score * 100).toFixed(0)}%</span><span>{p.time}</span></div></div>))}</div>)}
      {tab === "injection_attempts" && (<div className="space-y-3">{INJECTIONS.map((inj) => (<div key={inj.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{inj.id}</span><span className="ml-2 text-xs text-white/40">{inj.source}</span></div><StatusBadge status={inj.severity} /></div><p className="text-white/90 text-sm"><Eye className="inline h-3 w-3 mr-1" />{inj.vector}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>Technique: {inj.technique}</span><span className={inj.blocked ? "text-emerald-400" : "text-red-400"}>{inj.blocked ? "Blocked" : "Escaped"}</span></div></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Firewall Performance</h3>{[{ m: "Block Rate", v: "99.2%", t: "+0.3%" }, { m: "False Positive Rate", v: "0.4%", t: "-0.1%" }, { m: "Avg Scan Latency", v: "12ms", t: "-3ms" }, { m: "Models Protected", v: "14", t: "+2" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
