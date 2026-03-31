import { useState } from "react";
import { Zap, Activity, GitBranch, AlertTriangle, BarChart3 } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "event_streams" | "correlations" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "event_streams", label: "Event Streams" },
  { id: "correlations", label: "Correlations" },
  { id: "metrics", label: "Metrics" },
];

const STREAMS = [
  { name: "security-events", format: "CEF", eps: 4200, status: "healthy", lag: "12ms" },
  { name: "auth-logs", format: "JSON", eps: 1800, status: "healthy", lag: "8ms" },
  { name: "network-flows", format: "LEEF", eps: 8500, status: "warning", lag: "340ms" },
  { name: "cloud-audit", format: "JSON", eps: 950, status: "healthy", lag: "15ms" },
  { name: "endpoint-telemetry", format: "CEF", eps: 3200, status: "healthy", lag: "22ms" },
];

export default function EventStreamProcessor() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Event Stream Processor" subtitle="Real-time security event stream processing" icon={<Zap className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Events/sec" value="18,650" icon={<Activity className="h-5 w-5" />} />
        <MetricCard title="Active Streams" value="12" icon={<Zap className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Correlations" value="847" icon={<GitBranch className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Alerts Routed" value="156" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Stream Health</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Healthy", v: "10", c: "text-emerald-400" }, { l: "Warning", v: "1", c: "text-yellow-400" }, { l: "Degraded", v: "1", c: "text-orange-400" }, { l: "Down", v: "0", c: "text-red-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "event_streams" && (<div className="space-y-3">{STREAMS.map((s) => (<div key={s.name} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="text-white/90 font-medium font-mono text-sm">{s.name}</span><span className="ml-2 text-xs text-white/40">{s.format}</span></div><StatusBadge status={s.status} /></div><div className="flex gap-4 text-xs text-white/40"><span>{s.eps.toLocaleString()} events/sec</span><span>Lag: {s.lag}</span></div></div>))}</div>)}
      {tab === "correlations" && (<div className="card-surface p-6"><h3 className="section-heading">Active Correlation Rules</h3><div className="space-y-2">{[{ rule: "Brute Force → Lateral Movement", matches: 23, severity: "critical" }, { rule: "Privilege Escalation Chain", matches: 8, severity: "high" }, { rule: "Data Exfil After Recon", matches: 5, severity: "high" }, { rule: "Anomalous DNS + Auth Failure", matches: 12, severity: "medium" }].map((r, i) => (<div key={i} className="card-interactive p-3 flex items-center justify-between text-sm"><div><span className="text-white/70">{r.rule}</span><span className="text-white/40 ml-2">({r.matches} matches)</span></div><StatusBadge status={r.severity} /></div>))}</div></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Processing Metrics</h3>{[{ m: "Throughput", v: "18,650 eps", t: "+2,100 vs yesterday" }, { m: "Parse Success Rate", v: "99.7%", t: "within SLA" }, { m: "Enrichment Latency", v: "4.2ms", t: "p99: 12ms" }, { m: "Correlation Hits", v: "847/day", t: "+120 vs last week" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
