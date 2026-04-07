import { useState } from "react";
import { Play, Target, BarChart3, CheckCircle, AlertTriangle } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "exercises" | "scoring" | "improvement";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "exercises", label: "Exercises" }, { id: "scoring", label: "Scoring" }, { id: "improvement", label: "Improvement" }];
export default function IncidentSimulator2() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Incident Simulator" subtitle="Tabletop exercises — inject scenarios, measure response, score readiness" icon={<Play className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Exercises Run" value="8" icon={<Target className="h-5 w-5" />} />
      <MetricCard title="Team Readiness" value="Good" icon={<CheckCircle className="h-5 w-5 text-cyan-400" />} />
      <MetricCard title="Avg Score" value="78/100" icon={<BarChart3 className="h-5 w-5 text-cyan-400" />} />
      <MetricCard title="Improvement" value="+23%" icon={<AlertTriangle className="h-5 w-5 text-emerald-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Exercise Types</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {[{ type: "Tabletop", count: 4, avg: 82, color: "text-cyan-400" }, { type: "Functional", count: 3, avg: 75, color: "text-yellow-400" }, { type: "Full Scale", count: 1, avg: 71, color: "text-yellow-400" }].map((e) => (
        <div key={e.type} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{e.type}</p><p className={clsx("text-2xl font-bold mt-1", e.color)}>Avg {e.avg}</p><p className="text-xs text-white/40">{e.count} exercises</p></div>))}</div></div>)}
    {tab === "exercises" && (<div className="space-y-3">
      {[{ id: "SIM-008", scenario: "Ransomware attack — file servers encrypted", type: "tabletop", score: 85, status: "completed" },
        { id: "SIM-007", scenario: "Data breach — customer PII exposed", type: "functional", score: 72, status: "completed" },
        { id: "SIM-006", scenario: "Supply chain compromise via dependency", type: "tabletop", score: 68, status: "completed" },
      ].map((e) => (<div key={e.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{e.id}</span><span className="text-xs text-white/40 ml-2">{e.type}</span></div><span className="text-cyan-400 font-mono">{e.score}/100</span></div>
        <p className="text-white/90 font-medium">{e.scenario}</p></div>))}</div>)}
    {tab === "scoring" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Metric</th><th className="px-4 py-3">Score</th><th className="px-4 py-3">Benchmark</th><th className="px-4 py-3">Status</th></tr></thead>
      <tbody>{[
        { metric: "Detection Speed", score: 85, benchmark: 80, status: "on_target" },
        { metric: "Communication Speed", score: 72, benchmark: 75, status: "at_risk" },
        { metric: "Decision Quality", score: 81, benchmark: 70, status: "on_target" },
        { metric: "Containment Time", score: 78, benchmark: 80, status: "at_risk" },
        { metric: "Coordination", score: 69, benchmark: 75, status: "off_target" },
      ].map((s, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90">{s.metric}</td><td className="px-4 py-3 font-mono text-white/80">{s.score}</td><td className="px-4 py-3 text-white/50">{s.benchmark}</td><td className="px-4 py-3"><StatusBadge status={s.status} /></td></tr>))}</tbody></table></div>)}
    {tab === "improvement" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Improvement Over Time</h3>
      {[{ metric: "Detection Speed", exercise1: 62, latest: 85, improvement: "+37%" },
        { metric: "Communication", exercise1: 54, latest: 72, improvement: "+33%" },
        { metric: "Coordination", exercise1: 48, latest: 69, improvement: "+44%" },
      ].map((i, idx) => (<div key={idx} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{i.metric}</p><p className="text-xs text-white/50">First: {i.exercise1} → Latest: {i.latest}</p></div><span className="text-emerald-400 font-mono">{i.improvement}</span></div>))}</div>)}
  </div>);
}
