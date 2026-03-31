import { useState } from "react";
import { BarChart3, Gauge, Target, TrendingUp, Shield, FileText } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "kpi_tracker" | "executive_view" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "kpi_tracker", label: "KPI Tracker" },
  { id: "executive_view", label: "Executive View" },
  { id: "metrics", label: "Metrics" },
];

const KPIS = [
  { name: "MTTD", value: "3.2h", target: "4h", status: "passing", trend: "+0.8h", domain: "Detection" },
  { name: "MTTR", value: "18.5h", target: "24h", status: "passing", trend: "-3.2h", domain: "Response" },
  { name: "Vuln SLA Compliance", value: "91%", target: "90%", status: "passing", trend: "+4%", domain: "Vulnerability" },
  { name: "MTTC", value: "6.8h", target: "4h", status: "failing", trend: "-1.1h", domain: "Response" },
  { name: "Endpoint Coverage", value: "87%", target: "95%", status: "failing", trend: "+3%", domain: "Coverage" },
];

const BENCHMARKS = [
  { kpi: "MTTD", org: "3.2h", median: "5.1h", p75: "2.8h", percentile: 72 },
  { kpi: "MTTR", org: "18.5h", median: "32h", p75: "12h", percentile: 65 },
  { kpi: "Vuln SLA", org: "91%", median: "82%", p75: "94%", percentile: 68 },
];

export default function SecurityMetricDashboard() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Security Metric Dashboard" subtitle="Security KPIs, benchmarking, and executive reporting" icon={<BarChart3 className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="MTTD" value="3.2h" icon={<Gauge className="h-5 w-5" />} />
        <MetricCard title="MTTR" value="18.5h" icon={<Target className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Vuln SLA" value="91%" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Industry Rank" value="68th" icon={<TrendingUp className="h-5 w-5 text-yellow-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">KPI Health</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">{[{ l: "Passing", v: "3", c: "text-emerald-400" }, { l: "Failing", v: "2", c: "text-red-400" }, { l: "Domains Covered", v: "5/6", c: "text-cyan-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "kpi_tracker" && (<div className="space-y-3">{KPIS.map((k) => (<div key={k.name} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-medium text-white/90">{k.name}</span><span className="ml-2 text-xs text-white/40">{k.domain}</span></div><StatusBadge status={k.status} /></div><div className="flex gap-4 mt-2 text-xs text-white/50"><span>Value: <span className="text-cyan-400 font-mono">{k.value}</span></span><span>Target: {k.target}</span><span className="text-emerald-400">{k.trend}</span></div></div>))}</div>)}
      {tab === "executive_view" && (<div className="space-y-4"><div className="card-surface p-6"><h3 className="section-heading">Industry Benchmarks</h3><div className="space-y-3">{BENCHMARKS.map((b) => (<div key={b.kpi} className="card-interactive p-4"><div className="flex items-center justify-between mb-2"><span className="font-medium text-white/90">{b.kpi}</span><span className="text-cyan-400 font-mono text-sm">{b.percentile}th pctl</span></div><div className="flex gap-4 text-xs text-white/50"><span>Org: <span className="text-white/90">{b.org}</span></span><span>Median: {b.median}</span><span>P75: {b.p75}</span></div></div>))}</div></div><div className="card-surface p-6"><h3 className="section-heading">Board Summary</h3><p className="text-white/70 text-sm">Security posture is <span className="text-emerald-400 font-medium">adequate</span> with MTTD and MTTR within targets. Endpoint coverage and MTTC require attention. Organization ranks in the <span className="text-cyan-400">68th percentile</span> against industry peers.</p></div></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Dashboard Metrics</h3>{[{ m: "Metrics Collected", v: "2,847", t: "+156" }, { m: "KPIs Computed", v: "12", t: "+2" }, { m: "Data Sources", v: "8", t: "+1" }, { m: "Report Frequency", v: "Weekly", t: "On schedule" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
