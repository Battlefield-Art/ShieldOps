import { useState } from "react";
import { TrendingUp, Shield, BarChart3 } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "findings" | "details" | "metrics";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "findings", label: "Findings" }, { id: "details", label: "Details" }, { id: "metrics", label: "Metrics" }];
export default function SecurityCopilot() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Security Copilot" subtitle="AI security assistant for SOC analysts" icon={<Shield className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Queries" value="1,847" icon={<TrendingUp className="h-5 w-5" />} />
      <MetricCard title="Resolved" value="1,623" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Accuracy" value="94.2%" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Avg Response" value="2.3s" icon={<BarChart3 className="h-5 w-5 text-cyan-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Summary</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">{[{ l: "Threat Hunts", v: "412", c: "text-emerald-400" }, { l: "Incident Queries", v: "890", c: "text-yellow-400" }, { l: "Compliance Checks", v: "545", c: "text-cyan-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
    {tab === "findings" && (<div className="space-y-3">{[{ id: "SCP-001", t: "Analyst query: 'Show all failed logins from unusual geos' — 23 results", s: "high" }, { id: "SCP-002", t: "Auto-investigation of anomalous API key usage pattern", s: "medium" }].map((f) => (<div key={f.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><span className="font-mono text-xs text-cyan-400">{f.id}</span><StatusBadge status={f.s} /></div><p className="text-white/90">{f.t}</p></div>))}</div>)}
    {tab === "details" && (<div className="card-surface p-6"><p className="text-white/60">Natural language security query interface and context-aware responses.</p></div>)}
    {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Trends</h3>{[{ m: "Query Accuracy", v: "94.2%", t: "+1.8% this month" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
  </div>);
}
