import { useState } from "react";
import { GraduationCap, CheckCircle, AlertTriangle, TrendingUp, Users, Target } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "training_status" | "effectiveness" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "training_status", label: "Training Status" },
  { id: "effectiveness", label: "Effectiveness" },
  { id: "metrics", label: "Metrics" },
];

const TRAINING = [
  { id: "TR-001", title: "Phishing Awareness Q1 2026", category: "Phishing", completion: "92%", overdue: 14, status: "active" },
  { id: "TR-002", title: "Secure Coding Practices", category: "Secure Coding", completion: "78%", overdue: 31, status: "active" },
  { id: "TR-003", title: "Incident Response Procedures", category: "IR", completion: "85%", overdue: 22, status: "active" },
  { id: "TR-004", title: "Data Handling & Classification", category: "Data Handling", completion: "71%", overdue: 45, status: "overdue" },
  { id: "TR-005", title: "PCI DSS Compliance Training", category: "Compliance", completion: "96%", overdue: 6, status: "active" },
];

const EFFECTIVENESS = [
  { category: "Phishing Awareness", clickRate: "8%", priorRate: "18%", improvement: "56%", status: "high" },
  { category: "Secure Coding", vulnReduction: "23%", priorRate: "N/A", improvement: "23%", status: "medium" },
  { category: "Incident Response", mttr: "42m", priorRate: "68m", improvement: "38%", status: "high" },
  { category: "Data Handling", incidents: "3", priorRate: "11", improvement: "73%", status: "high" },
];

export default function SecurityTrainingTracker() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Security Training Tracker" subtitle="Training completion tracking and effectiveness measurement" icon={<GraduationCap className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Completion Rate" value="84%" icon={<CheckCircle className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Overdue" value="118" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Effectiveness" value="72%" icon={<TrendingUp className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Active Programs" value="12" icon={<Target className="h-5 w-5" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Training by Category</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Phishing", v: "92%", c: "text-emerald-400" }, { l: "Secure Coding", v: "78%", c: "text-yellow-400" }, { l: "IR Procedures", v: "85%", c: "text-cyan-400" }, { l: "Compliance", v: "96%", c: "text-emerald-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "training_status" && (<div className="space-y-3">{TRAINING.map((t) => (<div key={t.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{t.id}</span><span className="ml-2 text-xs text-white/40">{t.category}</span></div><StatusBadge status={t.status} /></div><p className="text-white/90 text-sm">{t.title}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span className="text-cyan-400">{t.completion} complete</span><span className={t.overdue > 20 ? "text-yellow-400" : "text-white/40"}>{t.overdue} overdue</span></div></div>))}</div>)}
      {tab === "effectiveness" && (<div className="space-y-3">{EFFECTIVENESS.map((e, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><span className="text-white/90 font-medium">{e.category}</span><StatusBadge status={e.status} /></div><div className="flex gap-4 mt-2 text-xs text-white/50"><span className="text-emerald-400">{e.improvement} improvement</span><span>{e.clickRate ? `Click rate: ${e.clickRate}` : e.vulnReduction ? `Vuln reduction: ${e.vulnReduction}` : e.mttr ? `MTTR: ${e.mttr}` : `Incidents: ${e.incidents}`}</span></div></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Training Program Metrics</h3>{[{ m: "Overall Completion", v: "84%", t: "+6%" }, { m: "Phishing Click Rate", v: "8%", t: "-10%" }, { m: "Avg Knowledge Score", v: "82/100", t: "+7" }, { m: "Compliance Coverage", v: "96%", t: "+2%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
