import { useState } from "react";
import { Globe, TrendingUp, Shield, AlertTriangle, BarChart3, Target } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "threat_trends" | "industry_benchmark" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "threat_trends", label: "Threat Trends" },
  { id: "industry_benchmark", label: "Industry Benchmark" },
  { id: "metrics", label: "Metrics" },
];

const TRENDS = [
  { id: "TRD-001", category: "Ransomware", direction: "increasing", velocity: "+34%", severity: "critical" },
  { id: "TRD-002", category: "Supply Chain", direction: "increasing", velocity: "+22%", severity: "high" },
  { id: "TRD-003", category: "APT", direction: "stable", velocity: "+3%", severity: "high" },
  { id: "TRD-004", category: "Social Engineering", direction: "increasing", velocity: "+18%", severity: "medium" },
];

const BENCHMARKS = [
  { area: "Endpoint Protection", score: 82, peer: 74, delta: "+8" },
  { area: "Network Security", score: 68, peer: 71, delta: "-3" },
  { area: "Identity & Access", score: 75, peer: 69, delta: "+6" },
  { area: "Data Protection", score: 61, peer: 66, delta: "-5" },
];

export default function ThreatLandscapeAnalyzer() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Threat Landscape Analyzer" subtitle="Industry threat analysis, trends, and peer benchmarking" icon={<Globe className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Active Threats" value="142" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Trend Velocity" value="+18%" icon={<TrendingUp className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Peer Percentile" value="72nd" icon={<BarChart3 className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Posture Score" value="7.1" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Threat Categories</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Ransomware", v: "38", c: "text-red-400" }, { l: "APT", v: "24", c: "text-yellow-400" }, { l: "Supply Chain", v: "31", c: "text-cyan-400" }, { l: "Insider", v: "12", c: "text-white/70" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "threat_trends" && (<div className="space-y-3">{TRENDS.map((tr) => (<div key={tr.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{tr.id}</span><span className="ml-2 text-xs text-white/40">{tr.direction}</span></div><StatusBadge status={tr.severity} /></div><p className="text-white/90 text-sm">{tr.category}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>Velocity: <span className={tr.velocity.startsWith("+") ? "text-red-400" : "text-emerald-400"}>{tr.velocity}</span></span></div></div>))}</div>)}
      {tab === "industry_benchmark" && (<div className="space-y-3">{BENCHMARKS.map((b) => (<div key={b.area} className="card-interactive p-4"><div className="flex items-center justify-between mb-2"><p className="text-white/90 font-medium">{b.area}</p><span className={clsx("text-xs font-mono", b.delta.startsWith("+") ? "text-emerald-400" : "text-red-400")}>{b.delta} vs peers</span></div><div className="flex gap-2 items-center"><div className="flex-1"><div className="w-full bg-white/10 rounded-full h-2"><div className="bg-cyan-500 h-2 rounded-full" style={{ width: `${b.score}%` }} /></div></div><span className="text-xs text-cyan-400 font-mono w-12 text-right">{b.score}%</span></div><p className="text-xs text-white/40 mt-1">Peer avg: {b.peer}%</p></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Landscape Intelligence</h3>{[{ m: "Threat Coverage", v: "89%", t: "+4%" }, { m: "Intel Sources", v: "12", t: "+2" }, { m: "Avg Threat Velocity", v: "+18%/mo", t: "+3%" }, { m: "Peer Ranking", v: "72nd pctl", t: "+5" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
