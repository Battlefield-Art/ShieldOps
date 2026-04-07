import { useState } from "react";
import { TrendingUp, Shield, BarChart3 } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "findings" | "details" | "metrics";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "findings", label: "Findings" }, { id: "details", label: "Details" }, { id: "metrics", label: "Metrics" }];
export default function IncidentPlaybookGenerator() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Playbook Generator" subtitle="Auto-generate IR playbooks from threat intelligence" icon={<Shield className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Generated" value="67" icon={<TrendingUp className="h-5 w-5" />} />
      <MetricCard title="Active" value="42" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Effectiveness" value="91%" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Techniques" value="156" icon={<BarChart3 className="h-5 w-5 text-cyan-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Summary</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">{[{ l: "Ransomware", v: "12", c: "text-emerald-400" }, { l: "Phishing", v: "18", c: "text-yellow-400" }, { l: "Data Breach", v: "8", c: "text-red-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
    {tab === "findings" && (<div className="space-y-3">{[{ id: "IPG-001", t: "New ransomware playbook generated from LockBit 4.0 TTP analysis", s: "high" }, { id: "IPG-002", t: "Updated phishing playbook with MFA bypass techniques", s: "medium" }].map((f) => (<div key={f.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><span className="font-mono text-xs text-cyan-400">{f.id}</span><StatusBadge status={f.s} /></div><p className="text-white/90">{f.t}</p></div>))}</div>)}
    {tab === "details" && (<div className="card-surface p-6"><p className="text-white/60">MITRE ATT&CK technique mapping and playbook workflow design.</p></div>)}
    {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Trends</h3>{[{ m: "Playbook Effectiveness", v: "91.3%", t: "+3.2% this month" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
  </div>);
}
