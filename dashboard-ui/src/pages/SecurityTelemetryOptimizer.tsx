import { useState } from "react";
import { Activity, BarChart3, Filter, DollarSign, TrendingUp, Database } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "telemetry_sources" | "optimization_plan" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "telemetry_sources", label: "Telemetry Sources" },
  { id: "optimization_plan", label: "Optimization Plan" },
  { id: "metrics", label: "Metrics" },
];

const SOURCES = [
  { id: "TS-001", name: "EDR Agent Logs", type: "logs", volume_gb: 48.2, cost_day: 124, waste_pct: 22, status: "optimizable" },
  { id: "TS-002", name: "Cloud Audit Trail", type: "logs", volume_gb: 31.7, cost_day: 82, waste_pct: 8, status: "healthy" },
  { id: "TS-003", name: "OTel Metrics Pipeline", type: "metrics", volume_gb: 18.4, cost_day: 47, waste_pct: 35, status: "optimizable" },
  { id: "TS-004", name: "Network Flow Data", type: "traces", volume_gb: 92.1, cost_day: 238, waste_pct: 41, status: "critical" },
];

const OPTIMIZATIONS = [
  { id: "OPT-001", source: "TS-004", action: "Downsample network flows to 1:10", savings_gb: 37.8, savings_cost: 97, risk: "low" },
  { id: "OPT-002", source: "TS-003", action: "Reduce metric cardinality (drop unused labels)", savings_gb: 6.4, savings_cost: 16, risk: "low" },
  { id: "OPT-003", source: "TS-001", action: "Deduplicate EDR telemetry across agents", savings_gb: 10.6, savings_cost: 27, risk: "medium" },
];

export default function SecurityTelemetryOptimizer() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Security Telemetry Optimizer" subtitle="Reduce telemetry volume and cost without sacrificing detection" icon={<Activity className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Daily Volume" value="190 GB" icon={<Database className="h-5 w-5" />} />
        <MetricCard title="Monthly Savings" value="$4,200" icon={<DollarSign className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Waste Detected" value="28%" icon={<Filter className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Quality Score" value="97.1%" icon={<TrendingUp className="h-5 w-5 text-cyan-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Volume by Type</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Logs", v: "79.9 GB", c: "text-cyan-400" }, { l: "Metrics", v: "18.4 GB", c: "text-emerald-400" }, { l: "Traces", v: "92.1 GB", c: "text-yellow-400" }, { l: "Events", v: "4.2 GB", c: "text-white/70" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "telemetry_sources" && (<div className="space-y-3">{SOURCES.map((s) => (<div key={s.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{s.id}</span><span className="ml-2 text-xs text-white/40">{s.type}</span></div><StatusBadge status={s.status} /></div><p className="text-white/90 text-sm font-medium">{s.name}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>{s.volume_gb} GB/day</span><span>${s.cost_day}/day</span><span className={s.waste_pct > 20 ? "text-yellow-400" : "text-white/40"}>{s.waste_pct}% waste</span></div></div>))}</div>)}
      {tab === "optimization_plan" && (<div className="space-y-3">{OPTIMIZATIONS.map((o) => (<div key={o.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{o.id}</span><span className="ml-2 text-xs text-white/40">{o.source}</span></div><StatusBadge status={o.risk} /></div><p className="text-white/90 text-sm">{o.action}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span className="text-emerald-400">-{o.savings_gb} GB/day</span><span className="text-emerald-400">-${o.savings_cost}/day</span></div></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Optimization Metrics</h3>{[{ m: "Volume Reduction", v: "28%", t: "+4%" }, { m: "Cost Savings (30d)", v: "$4,200", t: "+$580" }, { m: "Detection Fidelity", v: "99.3%", t: "+0.1%" }, { m: "Cardinality Reduction", v: "42%", t: "+8%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
