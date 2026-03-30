import { useState } from "react";
import { TrendingUp, Shield, BarChart3, AlertTriangle } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "findings" | "details" | "metrics";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "findings", label: "Findings" }, { id: "details", label: "Details" }, { id: "metrics", label: "Metrics" }];
export default function AuditTrailAnalyzer() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Audit Trail Analyzer" subtitle="Audit log analysis and anomaly detection" icon={<Shield className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Scans" value="156" icon={<TrendingUp className="h-5 w-5" />} />
      <MetricCard title="Issues" value="12" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Compliant" value="94%" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Score" value="A-" icon={<BarChart3 className="h-5 w-5 text-cyan-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Summary</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">{[{ l: "Passing", v: "140", c: "text-emerald-400" }, { l: "Warning", v: "12", c: "text-yellow-400" }, { l: "Critical", v: "4", c: "text-red-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
    {tab === "findings" && (<div className="space-y-3">{[{ id: "F-001", t: "Finding detected", s: "high" }, { id: "F-002", t: "Issue found", s: "medium" }].map((f) => (<div key={f.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><span className="font-mono text-xs text-cyan-400">{f.id}</span><StatusBadge status={f.s} /></div><p className="text-white/90">{f.t}</p></div>))}</div>)}
    {tab === "details" && (<div className="card-surface p-6"><p className="text-white/60">Detailed view.</p></div>)}
    {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Trends</h3>{[{ m: "Detection", v: "98.5%", t: "+1.2%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
  </div>);
}
