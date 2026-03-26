import { useState } from "react";
import { Bot, Zap, Clock, Target, Shield, TrendingUp } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "investigations" | "responses" | "learning";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "investigations", label: "Investigations" }, { id: "responses", label: "Responses" }, { id: "learning", label: "Closed-Loop Learning" }];
export default function AgenticMDR() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Agentic MDR" subtitle="Machine-speed detection, investigation, and response — vendor-neutral, cross-tool" icon={<Bot className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="MTTR" value="3.2 min" icon={<Clock className="h-5 w-5 text-cyan-400" />} />
      <MetricCard title="Auto-Resolved (24h)" value="142" icon={<Zap className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Triage Accuracy" value="97.3%" icon={<Target className="h-5 w-5" />} />
      <MetricCard title="Closed-Loop Improvements" value="+12%" icon={<TrendingUp className="h-5 w-5 text-cyan-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">MDR Performance (24h)</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">
      {[{ label: "Auto-Remediated", count: 142, color: "text-emerald-400" }, { label: "Human-Approved", count: 18, color: "text-cyan-400" }, { label: "Escalated", count: 3, color: "text-yellow-400" }, { label: "Suppressed (FP)", count: 67, color: "text-white/40" }].map((s) => (
        <div key={s.label} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.label}</p><p className={clsx("text-3xl font-bold mt-1", s.color)}>{s.count}</p></div>))}</div></div>)}
    {tab === "investigations" && (<div className="space-y-3">
      {[{ id: "MDR-047", source: "CrowdStrike Falcon", type: "Credential Abuse", depth: "deep", duration: "2.1 min", verdict: "true_positive" },
        { id: "MDR-046", source: "Microsoft Defender", type: "Malware Execution", depth: "standard", duration: "1.4 min", verdict: "true_positive" },
        { id: "MDR-045", source: "Splunk SIEM", type: "Brute Force", depth: "shallow", duration: "0.8 min", verdict: "false_positive" },
        { id: "MDR-044", source: "Wiz Cloud", type: "S3 Exposure", depth: "standard", duration: "1.1 min", verdict: "true_positive" },
      ].map((i) => (<div key={i.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{i.id}</span><span className="text-xs text-white/40 ml-2">{i.source}</span></div><StatusBadge status={i.verdict} /></div>
        <p className="text-white/90 font-medium">{i.type}</p><p className="text-xs text-white/50">Depth: {i.depth} | Duration: {i.duration}</p></div>))}</div>)}
    {tab === "responses" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Recent Automated Responses</h3>
      {[{ action: "Credential Revocation", target: "svc-admin@prod", source: "Falcon", decision: "auto_remediate", time: "0.3 min" },
        { action: "Host Isolation", target: "web-server-42", source: "Defender", decision: "auto_remediate", time: "0.5 min" },
        { action: "Firewall Rule Update", target: "sg-0a1b2c3d", source: "Wiz", decision: "human_approve", time: "4.2 min" },
      ].map((r, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{r.action}</p><p className="text-xs text-white/50">{r.source} | Target: {r.target} | {r.time}</p></div><StatusBadge status={r.decision} /></div>))}</div>)}
    {tab === "learning" && (<div className="card-surface p-6"><h3 className="section-heading">Closed-Loop Improvements</h3><div className="space-y-3">
      {[{ metric: "False Positive Rate", before: "8.2%", after: "3.1%", improvement: "-62%", trend: "improving" },
        { metric: "Auto-Resolve Rate", before: "54%", after: "78%", improvement: "+44%", trend: "improving" },
        { metric: "Mean Investigation Time", before: "8.5 min", after: "2.1 min", improvement: "-75%", trend: "improving" },
        { metric: "Analyst Escalation Rate", before: "23%", after: "8%", improvement: "-65%", trend: "improving" },
      ].map((m, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{m.metric}</p><p className="text-xs text-white/50">Before: {m.before} → After: {m.after}</p></div><span className="text-emerald-400 font-mono text-sm">{m.improvement}</span></div>))}</div></div>)}
  </div>);
}
