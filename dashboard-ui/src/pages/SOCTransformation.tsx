import { useState } from "react";
import { Workflow, TrendingUp, Database, Filter, ArrowRight } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "assessment" | "migration" | "validation";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "assessment", label: "Assessment" }, { id: "migration", label: "Migration" }, { id: "validation", label: "Validation" }];
export default function SOCTransformation() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="SOC Transformation" subtitle="Agent-driven SIEM migration, data pipeline optimization, and workflow modernization" icon={<Workflow className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Current Maturity" value="Proactive" icon={<TrendingUp className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Rules Migrated" value="847/1,024" icon={<Filter className="h-5 w-5 text-cyan-400" />} />
      <MetricCard title="Data Sources" value="23" icon={<Database className="h-5 w-5" />} />
      <MetricCard title="Cost Reduction" value="-34%" icon={<TrendingUp className="h-5 w-5 text-emerald-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Transformation Progress</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">
      {[{ label: "SIEM Migration", pct: "83%", color: "text-cyan-400" }, { label: "Detection Rules", pct: "91%", color: "text-emerald-400" }, { label: "Data Pipelines", pct: "76%", color: "text-yellow-400" }, { label: "Workflows", pct: "68%", color: "text-white/70" }].map((s) => (
        <div key={s.label} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.label}</p><p className={clsx("text-3xl font-bold mt-1", s.color)}>{s.pct}</p></div>))}</div></div>)}
    {tab === "assessment" && (<div className="card-surface p-6"><h3 className="section-heading">SOC Maturity Assessment</h3><div className="space-y-3">
      {[{ dim: "Detection Coverage", current: "Proactive", target: "Adaptive", score: 3.2 },
        { dim: "Response Automation", current: "Reactive", target: "Autonomous", score: 2.1 },
        { dim: "Threat Intelligence", current: "Proactive", target: "Adaptive", score: 3.5 },
        { dim: "Data Pipeline", current: "Reactive", target: "Proactive", score: 2.8 },
      ].map((d, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-center justify-between"><p className="text-white/90 font-medium">{d.dim}</p><span className="text-cyan-400 font-mono">{d.score}/5</span></div><div className="flex items-center gap-2 mt-1 text-xs text-white/50"><StatusBadge status={d.current} /><ArrowRight className="h-3 w-3" /><StatusBadge status={d.target} /></div></div>))}</div></div>)}
    {tab === "migration" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Component</th><th className="px-4 py-3">Source</th><th className="px-4 py-3">Target</th><th className="px-4 py-3">Progress</th><th className="px-4 py-3">Status</th></tr></thead>
      <tbody>{[
        { comp: "Detection Rules", source: "Splunk SPL", target: "Native", progress: "847/1024", status: "in_progress" },
        { comp: "Data Pipelines", source: "HEC/Syslog", target: "OTel", progress: "18/23", status: "in_progress" },
        { comp: "Dashboards", source: "Splunk", target: "ShieldOps", progress: "12/15", status: "in_progress" },
        { comp: "Playbooks", source: "Phantom", target: "LangGraph", progress: "8/8", status: "completed" },
      ].map((m, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90 font-medium">{m.comp}</td><td className="px-4 py-3 text-white/60">{m.source}</td><td className="px-4 py-3 text-white/70">{m.target}</td><td className="px-4 py-3 font-mono text-white/80">{m.progress}</td><td className="px-4 py-3"><StatusBadge status={m.status} /></td></tr>))}</tbody></table></div>)}
    {tab === "validation" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Migration Validation</h3>
      {[{ check: "Detection Parity", result: "98.2% rules producing equivalent alerts", status: "passed" },
        { check: "Data Completeness", result: "All 23 sources ingesting, 2 with latency", status: "warning" },
        { check: "Response Playbooks", result: "8/8 playbooks validated end-to-end", status: "passed" },
        { check: "Performance", result: "Query latency 40% lower than legacy SIEM", status: "passed" },
      ].map((v, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{v.check}</p><p className="text-xs text-white/50">{v.result}</p></div><StatusBadge status={v.status} /></div>))}</div>)}
  </div>);
}
