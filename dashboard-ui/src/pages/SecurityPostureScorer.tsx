import { useState } from "react";
import { Gauge, Shield, TrendingUp, BarChart3 } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "score_breakdown" | "benchmarks" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "score_breakdown", label: "Score Breakdown" },
  { id: "benchmarks", label: "Benchmarks" },
  { id: "metrics", label: "Metrics" },
];

const CATEGORIES = [
  { name: "Vulnerability Mgmt", score: 82, tier: "good", weight: "18%", benchmark: 68 },
  { name: "Identity & Access", score: 74, tier: "fair", weight: "16%", benchmark: 71 },
  { name: "Cloud Security", score: 69, tier: "fair", weight: "14%", benchmark: 65 },
  { name: "Endpoint Protection", score: 91, tier: "excellent", weight: "13%", benchmark: 72 },
  { name: "Network Security", score: 78, tier: "good", weight: "12%", benchmark: 70 },
  { name: "Data Protection", score: 55, tier: "poor", weight: "11%", benchmark: 63 },
  { name: "Incident Response", score: 88, tier: "good", weight: "9%", benchmark: 66 },
  { name: "Compliance", score: 93, tier: "excellent", weight: "7%", benchmark: 75 },
];

export default function SecurityPostureScorer() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Security Posture Scorer" subtitle="Continuous multi-source security posture scoring and benchmarking" icon={<Gauge className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Overall Score" value="78.5" icon={<Gauge className="h-5 w-5" />} />
        <MetricCard title="Tier" value="Good" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Industry Pctile" value="72nd" icon={<BarChart3 className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="30d Trend" value="+3.2" icon={<TrendingUp className="h-5 w-5 text-emerald-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Posture Summary</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Excellent", v: "2", c: "text-emerald-400" }, { l: "Good", v: "3", c: "text-cyan-400" }, { l: "Fair", v: "2", c: "text-yellow-400" }, { l: "Poor/Critical", v: "1", c: "text-red-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "score_breakdown" && (<div className="space-y-3">{CATEGORIES.map((c) => (<div key={c.name} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="text-white/90 font-medium">{c.name}</span><span className="ml-2 text-xs text-white/40">Weight: {c.weight}</span></div><StatusBadge status={c.tier} /></div><div className="flex items-center gap-2 mt-2"><div className="flex-1 h-2 rounded-full bg-white/10"><div className="h-2 rounded-full bg-cyan-500" style={{ width: `${c.score}%` }} /></div><span className="text-cyan-400 font-mono text-sm w-10 text-right">{c.score}</span></div></div>))}</div>)}
      {tab === "benchmarks" && (<div className="space-y-3">{CATEGORIES.map((c) => (<div key={c.name} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{c.name}</p><p className="text-xs text-white/50">Industry avg: {c.benchmark}</p></div><div className="flex items-center gap-3"><span className={clsx("font-mono", c.score >= c.benchmark ? "text-emerald-400" : "text-red-400")}>{c.score >= c.benchmark ? "+" : ""}{c.score - c.benchmark}</span><span className="text-cyan-400 font-mono">{c.score}/100</span></div></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Scoring Trends</h3>{[{ m: "Overall Score (30d)", v: "78.5", t: "+3.2" }, { m: "Categories Improving", v: "5/8", t: "+1" }, { m: "Below Industry Avg", v: "1", t: "-1" }, { m: "Forecast (30d)", v: "81.2", t: "+2.7" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
