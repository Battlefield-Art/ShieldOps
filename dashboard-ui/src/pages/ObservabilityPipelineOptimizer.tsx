import { useState } from "react";
import { Filter, TrendingUp, DollarSign, Activity, Zap } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "pipelines" | "optimizations" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "pipelines", label: "Pipelines" },
  { id: "optimizations", label: "Optimizations" },
  { id: "metrics", label: "Metrics" },
];

const PIPELINES = [
  { name: "Traces Pipeline", type: "TRACES", throughput: "45K spans/s", cardinality: "2.4M", cost: "$4,200/mo", status: "healthy" },
  { name: "Metrics Pipeline", type: "METRICS", throughput: "120K pts/s", cardinality: "890K", cost: "$2,800/mo", status: "warning" },
  { name: "Logs Pipeline", type: "LOGS", throughput: "8.2 GB/hr", cardinality: "N/A", cost: "$6,400/mo", status: "healthy" },
  { name: "Events Pipeline", type: "EVENTS", throughput: "12K evt/s", cardinality: "340K", cost: "$1,200/mo", status: "healthy" },
];

const OPTIMIZATIONS = [
  { id: "OPT-001", pipeline: "Metrics", action: "Drop unused metrics", savings: "$840/mo", status: "applied" },
  { id: "OPT-002", pipeline: "Traces", action: "Tail sampling (keep errors + slow)", savings: "$1,260/mo", status: "applied" },
  { id: "OPT-003", pipeline: "Logs", action: "Aggregate debug logs", savings: "$2,100/mo", status: "pending" },
  { id: "OPT-004", pipeline: "Metrics", action: "Reduce cardinality on labels", savings: "$420/mo", status: "applied" },
];

export default function ObservabilityPipelineOptimizer() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Observability Pipeline Optimizer" subtitle="Reduce telemetry costs while maintaining signal quality" icon={<Filter className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Pipelines" value="4" icon={<Activity className="h-5 w-5" />} />
        <MetricCard title="Monthly Cost" value="$14,600" icon={<DollarSign className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Savings Applied" value="$2,520" icon={<TrendingUp className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Signal Quality" value="99.2%" icon={<Zap className="h-5 w-5 text-cyan-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Cost Breakdown</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Traces", v: "$4,200", c: "text-cyan-400" }, { l: "Metrics", v: "$2,800", c: "text-emerald-400" }, { l: "Logs", v: "$6,400", c: "text-yellow-400" }, { l: "Events", v: "$1,200", c: "text-white/70" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "pipelines" && (<div className="space-y-3">{PIPELINES.map((p) => (<div key={p.name} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><span className="text-white/90 font-medium">{p.name}</span><StatusBadge status={p.status} /></div><div className="flex gap-4 text-sm text-white/50"><span>{p.type}</span><span>{p.throughput}</span><span>Cardinality: {p.cardinality}</span><span className="text-yellow-400">{p.cost}</span></div></div>))}</div>)}
      {tab === "optimizations" && (<div className="space-y-3">{OPTIMIZATIONS.map((o) => (<div key={o.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{o.id}</span><span className="ml-2 text-white/90">{o.pipeline}</span></div><StatusBadge status={o.status} /></div><p className="text-white/70 text-sm">{o.action}</p><p className="text-emerald-400 text-xs mt-1">Savings: {o.savings}</p></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Optimization Trends</h3>{[{ m: "Cost Reduction", v: "17.3%", t: "+4.2%" }, { m: "Cardinality Reduction", v: "34%", t: "+8%" }, { m: "Signal Quality", v: "99.2%", t: "+0.1%" }, { m: "Throughput Efficiency", v: "92%", t: "+3%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
