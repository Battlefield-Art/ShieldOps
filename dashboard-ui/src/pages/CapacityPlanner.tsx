import { useState } from "react";
import { Server, TrendingUp, AlertTriangle, BarChart3, Clock, Gauge } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "forecasts" | "bottlenecks" | "scaling";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "forecasts", label: "Demand Forecasts" }, { id: "bottlenecks", label: "Bottlenecks" }, { id: "scaling", label: "Scaling Plans" }];
export default function CapacityPlanner() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Capacity Planner" subtitle="Predict resource capacity needs and prevent outages" icon={<Server className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Resources Monitored" value="342" icon={<Server className="h-5 w-5" />} />
      <MetricCard title="Bottlenecks Active" value="4" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Days to Exhaustion (min)" value="18" icon={<Clock className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Auto-Scale Actions (7d)" value="12" icon={<TrendingUp className="h-5 w-5" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6 space-y-4"><h3 className="section-heading">Resource Utilization</h3>
      <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
        {[{ type: "Compute", pct: 72, status: "healthy" }, { type: "Memory", pct: 84, status: "warning" }, { type: "Storage", pct: 61, status: "healthy" }, { type: "Network", pct: 45, status: "healthy" }, { type: "Database", pct: 89, status: "critical" }].map((r) => (
          <div key={r.type} className="card-interactive p-3 text-center"><p className="text-xs text-white/50">{r.type}</p><p className={clsx("text-2xl font-bold mt-1", r.pct >= 85 ? "text-red-400" : r.pct >= 75 ? "text-yellow-400" : "text-emerald-400")}>{r.pct}%</p>
          <div className="h-1.5 bg-white/10 rounded-full mt-2"><div className={clsx("h-1.5 rounded-full", r.pct >= 85 ? "bg-red-500" : r.pct >= 75 ? "bg-yellow-500" : "bg-cyan-500")} style={{ width: `${r.pct}%` }} /></div></div>))}
      </div></div>)}
    {tab === "forecasts" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Demand Forecasts (30-day)</h3>
      {[{ resource: "rds-primary (Database)", current: 89, forecast: 96, days: 18, conf: 92 }, { resource: "worker-pool (Compute)", current: 72, forecast: 85, days: 42, conf: 88 }, { resource: "redis-cluster (Memory)", current: 84, forecast: 91, days: 28, conf: 85 }].map((f) => (
        <div key={f.resource} className="card-interactive p-4"><div className="flex items-center justify-between mb-2"><p className="text-white/90 font-medium">{f.resource}</p><span className={clsx("font-bold", f.days <= 21 ? "text-red-400" : "text-yellow-400")}>{f.days}d to exhaustion</span></div>
        <div className="flex gap-4 text-xs text-white/50"><span>Current: {f.current}%</span><span>Forecast: {f.forecast}%</span><span>Confidence: {f.conf}%</span></div></div>))}</div>)}
    {tab === "bottlenecks" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Active Bottlenecks</h3>
      {[{ resource: "rds-primary", type: "Connection Pool", desc: "Max connections reached during peak hours", sev: "critical" }, { resource: "api-gateway", type: "CPU", desc: "CPU saturation during batch processing", sev: "high" }].map((b, i) => (
        <div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{b.type}: {b.resource}</p><p className="text-xs text-white/50">{b.desc}</p></div><StatusBadge status={b.sev} /></div>))}</div>)}
    {tab === "scaling" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Recommended Scaling Plans</h3>
      {[{ resource: "rds-primary", action: "Upgrade to r6g.2xlarge", from: "r6g.xlarge", to: "r6g.2xlarge", cost: "+$420/mo", auto: false }, { resource: "worker-pool", action: "Add 2 nodes", from: "4 nodes", to: "6 nodes", cost: "+$280/mo", auto: true }].map((s, i) => (
        <div key={i} className="card-interactive p-4"><div className="flex items-center justify-between mb-2"><p className="text-white/90 font-medium">{s.action}</p><span className="text-xs text-yellow-400">{s.cost}</span></div>
        <p className="text-xs text-white/50">{s.resource}: {s.from} → {s.to} | {s.auto ? "Auto-scalable" : "Manual"}</p></div>))}</div>)}
  </div>);
}
