import { useState } from "react";
import { Cloud, Shield, BarChart3, AlertTriangle } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "findings" | "resources" | "metrics";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "findings", label: "Findings" }, { id: "resources", label: "Resources" }, { id: "metrics", label: "Metrics" }];
export default function MultiCloudCompliance() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Multi-Cloud Compliance" subtitle="Unified CIS benchmarks across AWS GCP Azure" icon={<Cloud className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Resources" value="892" icon={<Cloud className="h-5 w-5" />} />
      <MetricCard title="Findings" value="23" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Compliant" value="94%" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Score" value="A-" icon={<BarChart3 className="h-5 w-5 text-cyan-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Status</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">{[{ label: "Passing", value: "838", color: "text-emerald-400" }, { label: "Warning", value: "31", color: "text-yellow-400" }, { label: "Failing", value: "23", color: "text-red-400" }].map((s) => (<div key={s.label} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.label}</p><p className={clsx("text-2xl font-bold mt-1", s.color)}>{s.value}</p></div>))}</div></div>)}
    {tab === "findings" && (<div className="space-y-3">{[{ id: "F-001", title: "Misconfiguration detected", severity: "high" }, { id: "F-002", title: "Access policy violation", severity: "medium" }].map((f) => (<div key={f.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><span className="font-mono text-xs text-cyan-400">{f.id}</span><StatusBadge status={f.severity} /></div><p className="text-white/90">{f.title}</p></div>))}</div>)}
    {tab === "resources" && (<div className="card-surface p-6"><p className="text-white/60">Resource inventory and details.</p></div>)}
    {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Trends</h3>{[{ m: "Compliance Score", v: "94%", t: "+2% vs last month" }, { m: "MTTR", v: "4.2h", t: "-30% vs last quarter" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
  </div>);
}
