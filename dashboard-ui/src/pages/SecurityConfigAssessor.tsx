import { useState } from "react";
import { Settings, Shield, AlertTriangle, CheckCircle, FileText, BarChart3 } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "benchmarks" | "drift" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "benchmarks", label: "Benchmarks" },
  { id: "drift", label: "Config Drift" },
  { id: "metrics", label: "Metrics" },
];

const BENCHMARKS = [
  { name: "CIS AWS Foundations", score: 87, controls: 49, passing: 43, status: "active" },
  { name: "CIS Kubernetes", score: 72, controls: 78, passing: 56, status: "active" },
  { name: "CIS Linux (Ubuntu)", score: 91, controls: 45, passing: 41, status: "active" },
  { name: "CIS Docker", score: 84, controls: 32, passing: 27, status: "active" },
  { name: "CIS Azure", score: 78, controls: 56, passing: 44, status: "in_progress" },
];

export default function SecurityConfigAssessor() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Security Config Assessor" subtitle="CIS benchmark assessment with automated remediation scripts" icon={<Settings className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Systems Assessed" value="234" icon={<FileText className="h-5 w-5" />} />
        <MetricCard title="Avg Score" value="82%" icon={<BarChart3 className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Config Drifts" value="23" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Auto-Fixed" value="67" icon={<CheckCircle className="h-5 w-5 text-emerald-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Benchmark Summary</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Passing", v: "211", c: "text-emerald-400" }, { l: "Warning", v: "15", c: "text-yellow-400" }, { l: "Failing", v: "8", c: "text-red-400" }, { l: "Not Assessed", v: "3", c: "text-white/40" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "benchmarks" && (<div className="space-y-3">{BENCHMARKS.map((b) => (<div key={b.name} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><span className="text-white/90 font-medium">{b.name}</span><StatusBadge status={b.status} /></div><div className="flex items-center gap-4 text-sm"><span className="text-white/50">{b.controls} controls</span><span className="text-emerald-400">{b.passing} passing</span><div className="flex-1"><div className="h-2 rounded-full bg-white/10 overflow-hidden"><div className="h-full rounded-full bg-emerald-500" style={{ width: `${b.score}%` }} /></div></div><span className="text-white/70 font-mono text-xs">{b.score}%</span></div></div>))}</div>)}
      {tab === "drift" && (<div className="card-surface p-6"><h3 className="section-heading">Configuration Drift Events</h3><p className="text-white/60">23 configuration drifts detected across 234 assessed systems.</p></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Assessment Trends</h3>{[{ m: "Avg CIS Score", v: "82%", t: "+4%" }, { m: "Config Drifts", v: "23", t: "-8 vs last week" }, { m: "Auto-Remediated", v: "67%", t: "+12%" }, { m: "Assessment Coverage", v: "94%", t: "+3%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
