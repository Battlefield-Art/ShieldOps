import { useState } from "react";
import { Brain, TrendingUp, Clock, Zap, BarChart3, Users } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "operations" | "automation" | "metrics";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "operations", label: "Operations" }, { id: "automation", label: "Automation" }, { id: "metrics", label: "Metrics" }];
export default function AutonomousSOC() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Autonomous SOC" subtitle="AI-native security operations — works with existing SIEM, no rip-and-replace" icon={<Brain className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="MTTD" value="1.8 min" icon={<Clock className="h-5 w-5 text-cyan-400" />} />
      <MetricCard title="MTTR" value="4.1 min" icon={<Clock className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Automation Rate" value="87%" icon={<Zap className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Analyst Productivity" value="+340%" icon={<TrendingUp className="h-5 w-5 text-emerald-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">SOC Performance (24h)</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">
      {[{ label: "Events Processed", value: "2.1M", color: "text-white/70" }, { label: "Anomalies Detected", value: 47, color: "text-yellow-400" }, { label: "Incidents Created", value: 12, color: "text-red-400" }, { label: "Auto-Resolved", value: 9, color: "text-emerald-400" }].map((s) => (
        <div key={s.label} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.label}</p><p className={clsx("text-3xl font-bold mt-1", s.color)}>{s.value}</p></div>))}</div></div>)}
    {tab === "operations" && (<div className="space-y-3">
      {[{ id: "INC-012", type: "Credential Compromise", source: "Splunk + Okta", level: "fully_autonomous", priority: "p1_high", status: "resolved" },
        { id: "INC-011", type: "Malware Detection", source: "Elastic SIEM", level: "supervised", priority: "p2_medium", status: "resolved" },
        { id: "INC-010", type: "Data Exfiltration", source: "Sentinel + CloudTrail", level: "fully_autonomous", priority: "p0_critical", status: "contained" },
        { id: "INC-009", type: "Policy Violation", source: "Splunk", level: "manual", priority: "p3_low", status: "open" },
      ].map((inc) => (<div key={inc.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{inc.id}</span><span className="text-xs text-white/40 ml-2">{inc.source}</span></div><StatusBadge status={inc.priority} /></div>
        <p className="text-white/90 font-medium">{inc.type}</p><p className="text-xs text-white/50">Automation: <StatusBadge status={inc.level} /> | <StatusBadge status={inc.status} /></p></div>))}</div>)}
    {tab === "automation" && (<div className="card-surface p-6"><h3 className="section-heading">Automation Levels</h3><div className="space-y-3">
      {[{ level: "Fully Autonomous", desc: "Auto-detect, triage, respond (confidence >0.95)", pct: "67%", incidents: 8, color: "text-emerald-400" },
        { level: "Supervised", desc: "AI recommends, analyst approves (0.80-0.95)", pct: "20%", incidents: 3, color: "text-cyan-400" },
        { level: "Manual", desc: "Analyst-driven with AI assistance (<0.80)", pct: "13%", incidents: 1, color: "text-white/60" },
      ].map((a, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-center justify-between"><div><p className={clsx("font-medium", a.color)}>{a.level}</p><p className="text-xs text-white/50">{a.desc}</p></div><div className="text-right"><p className="text-2xl font-bold text-white/80">{a.pct}</p><p className="text-xs text-white/40">{a.incidents} incidents</p></div></div></div>))}</div></div>)}
    {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">SOC Metrics (30d trend)</h3>
      {[{ metric: "Mean Time to Detect", current: "1.8 min", previous: "12.4 min", improvement: "-85%", trend: "improving" },
        { metric: "Mean Time to Respond", current: "4.1 min", previous: "48 min", improvement: "-91%", trend: "improving" },
        { metric: "False Positive Rate", current: "2.3%", previous: "18.7%", improvement: "-88%", trend: "improving" },
        { metric: "Analyst Caseload", current: "3/day", previous: "24/day", improvement: "-87%", trend: "improving" },
        { metric: "After-Hours Coverage", current: "100%", previous: "40%", improvement: "+150%", trend: "improving" },
      ].map((m, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{m.metric}</p><p className="text-xs text-white/50">{m.previous} → {m.current}</p></div><span className="text-emerald-400 font-mono text-sm">{m.improvement}</span></div>))}</div>)}
  </div>);
}
