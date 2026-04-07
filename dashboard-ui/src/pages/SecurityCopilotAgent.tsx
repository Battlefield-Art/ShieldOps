import { useState } from "react";
import { Bot, MessageSquare, Shield, Zap, CheckCircle } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "query_history" | "recommendations" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "query_history", label: "Query History" },
  { id: "recommendations", label: "Recommendations" },
  { id: "metrics", label: "Metrics" },
];

const QUERIES = [
  { id: "SCA-001", query: "Investigate unusual outbound traffic from db-prod-03", category: "Threat Investigation", status: "resolved", confidence: 0.92, actions: 3 },
  { id: "SCA-002", query: "Check CVE-2024-3094 exposure across Linux fleet", category: "Vulnerability Triage", status: "active", confidence: 0.87, actions: 1 },
  { id: "SCA-003", query: "Review failed login attempts on admin portal", category: "Incident Response", status: "resolved", confidence: 0.95, actions: 2 },
  { id: "SCA-004", query: "Assess PCI-DSS compliance for payment service", category: "Compliance Check", status: "active", confidence: 0.78, actions: 0 },
];

const RECOMMENDATIONS = [
  { id: "REC-001", query: "SCA-001", title: "Block outbound traffic to 185.x.x.x", action: "block", risk: "high", automated: true },
  { id: "REC-002", query: "SCA-001", title: "Isolate db-prod-03 for forensics", action: "isolate", risk: "critical", automated: false },
  { id: "REC-003", query: "SCA-002", title: "Patch xz-utils to 5.6.1-2 on affected hosts", action: "remediate", risk: "critical", automated: true },
  { id: "REC-004", query: "SCA-003", title: "Enable MFA enforcement on admin portal", action: "remediate", risk: "high", automated: false },
];

export default function SecurityCopilotAgent() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Security Copilot" subtitle="Interactive AI copilot for security analysts" icon={<Bot className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Queries (24h)" value="47" icon={<MessageSquare className="h-5 w-5" />} />
        <MetricCard title="Resolution Rate" value="89%" icon={<CheckCircle className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Actions Executed" value="124" icon={<Zap className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Avg Confidence" value="0.88" icon={<Shield className="h-5 w-5 text-yellow-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Query Categories</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Threat Investigation", v: "18", c: "text-red-400" }, { l: "Vulnerability Triage", v: "12", c: "text-yellow-400" }, { l: "Incident Response", v: "9", c: "text-cyan-400" }, { l: "Compliance Check", v: "8", c: "text-emerald-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "query_history" && (<div className="space-y-3">{QUERIES.map((q) => (<div key={q.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{q.id}</span><span className="ml-2 text-xs text-white/40">{q.category}</span></div><StatusBadge status={q.status} /></div><p className="text-white/90 text-sm">{q.query}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>Confidence: {q.confidence}</span><span>{q.actions} actions</span></div></div>))}</div>)}
      {tab === "recommendations" && (<div className="space-y-3">{RECOMMENDATIONS.map((r) => (<div key={r.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{r.id}</span><span className="ml-2 text-xs text-white/40">{r.query}</span></div><StatusBadge status={r.risk} /></div><p className="text-white/90 text-sm">{r.title}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>Action: {r.action}</span>{r.automated && <span className="text-emerald-400">Automated</span>}</div></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Copilot Performance</h3>{[{ m: "Resolution Rate", v: "89%", t: "+5%" }, { m: "Avg Response Time", v: "2.4s", t: "-0.8s" }, { m: "Analyst Satisfaction", v: "4.6/5", t: "+0.3" }, { m: "Actions per Query", v: "2.6", t: "+0.4" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
