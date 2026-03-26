import { useState } from "react";
import { Activity, AlertTriangle, Clock, Cpu, Database, Zap } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "latency" | "bottlenecks" | "contention";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "latency", label: "Latency Analysis" }, { id: "bottlenecks", label: "Bottlenecks" }, { id: "contention", label: "Resource Contention" }];
export default function PerformanceProfiler() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Performance Profiler" subtitle="APM-style bottleneck detection and optimization recommendations" icon={<Activity className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Services Profiled" value="24" icon={<Activity className="h-5 w-5" />} />
      <MetricCard title="Bottlenecks" value="7" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Avg P99 Latency" value="245ms" icon={<Clock className="h-5 w-5" />} />
      <MetricCard title="Contentions" value="3" icon={<Cpu className="h-5 w-5 text-yellow-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Service Latency Overview</h3>
      <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
        {[{ svc: "api-gateway", p50: 45, p99: 180, err: 0.2 }, { svc: "user-service", p50: 32, p99: 420, err: 0.8 }, { svc: "billing", p50: 65, p99: 890, err: 1.2 }, { svc: "search", p50: 120, p99: 340, err: 0.1 }].map((s) => (
          <div key={s.svc} className="card-interactive p-3"><p className="font-mono text-xs text-cyan-400">{s.svc}</p><p className="text-lg font-bold text-white mt-1">P99: {s.p99}ms</p><p className="text-xs text-white/40">P50: {s.p50}ms | Err: {s.err}%</p></div>))}
      </div></div>)}
    {tab === "latency" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Service</th><th className="px-4 py-3">Endpoint</th><th className="px-4 py-3">P50</th><th className="px-4 py-3">P95</th><th className="px-4 py-3">P99</th><th className="px-4 py-3">RPS</th></tr></thead>
      <tbody>{[
        { svc: "billing", ep: "POST /charge", p50: 65, p95: 450, p99: 890, rps: 120 },
        { svc: "user-service", ep: "GET /users/{id}", p50: 32, p95: 180, p99: 420, rps: 450 },
        { svc: "search", ep: "POST /search", p50: 120, p95: 280, p99: 340, rps: 80 },
      ].map((l, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 font-mono text-xs text-cyan-400">{l.svc}</td><td className="px-4 py-3 text-white/80">{l.ep}</td><td className="px-4 py-3 text-white/70">{l.p50}ms</td><td className="px-4 py-3 text-white/70">{l.p95}ms</td><td className={clsx("px-4 py-3 font-bold", l.p99 > 500 ? "text-red-400" : "text-white/80")}>{l.p99}ms</td><td className="px-4 py-3 text-white/60">{l.rps}</td></tr>))}</tbody></table></div>)}
    {tab === "bottlenecks" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Detected Bottlenecks</h3>
      {[{ svc: "billing", type: "Database Query", desc: "N+1 query in charge endpoint — 45 queries per request", impact: "critical", improvement: "80% latency reduction" },
        { svc: "user-service", type: "External API", desc: "Synchronous call to auth provider in hot path", impact: "high", improvement: "60% latency reduction" },
        { svc: "search", type: "CPU Bound", desc: "Unoptimized regex in search ranking", impact: "medium", improvement: "40% latency reduction" },
      ].map((b, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><p className="text-white/90 font-medium">{b.type}: <span className="font-mono text-cyan-400">{b.svc}</span></p><p className="text-xs text-white/50">{b.desc}</p></div><StatusBadge status={b.impact} /></div>
        <p className="text-xs text-emerald-400">Est. improvement: {b.improvement}</p></div>))}</div>)}
    {tab === "contention" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Resource Contention</h3>
      {[{ svc: "billing", resource: "PostgreSQL connection pool", type: "Connection Pool", sev: "high", affected: ["POST /charge", "GET /invoices"] },
        { svc: "api-gateway", resource: "CPU cores", type: "CPU", sev: "medium", affected: ["Request routing", "TLS termination"] },
      ].map((c, i) => (<div key={i} className="card-interactive p-4"><p className="text-white/90 font-medium">{c.type}: <span className="font-mono text-cyan-400">{c.svc}</span></p><p className="text-xs text-white/50">{c.resource} | Affected: {c.affected.join(", ")}</p><StatusBadge status={c.sev} /></div>))}</div>)}
  </div>);
}
