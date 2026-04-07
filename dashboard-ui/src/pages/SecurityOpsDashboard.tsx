import { useState } from "react";
import { BarChart3, AlertTriangle, Activity, Users, Zap } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "kpi_tracker" | "team_performance" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "kpi_tracker", label: "KPI Tracker" },
  { id: "team_performance", label: "Team Performance" },
  { id: "metrics", label: "Metrics" },
];

const KPIS = [
  { id: "KPI-001", name: "MTTD", value: "4.2 min", target: "5 min", status: "healthy", detail: "Mean time to detect — 16% below target" },
  { id: "KPI-002", name: "MTTR", value: "28.5 min", target: "30 min", status: "healthy", detail: "Mean time to respond — within SLA" },
  { id: "KPI-003", name: "MITRE Coverage", value: "73%", target: "80%", status: "warning", detail: "ATT&CK technique coverage — 7% gap to target" },
  { id: "KPI-004", name: "Compliance Score", value: "91%", target: "95%", status: "warning", detail: "Overall compliance posture — 37 overdue vulns" },
];

export default function SecurityOpsDashboard() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Security Ops Dashboard" subtitle="Unified security operations dashboard and KPI tracker" icon={<BarChart3 className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="MTTD" value="4.2m" icon={<Zap className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="MTTR" value="28.5m" icon={<Activity className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Alerts (24h)" value="1,247" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Analyst Utilization" value="78%" icon={<Users className="h-5 w-5 text-brand-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Operational Health</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Detection", v: "99.8%", c: "text-emerald-400" }, { l: "Response", v: "94%", c: "text-cyan-400" }, { l: "Prevention", v: "892 blocked", c: "text-yellow-400" }, { l: "Compliance", v: "91%", c: "text-orange-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "kpi_tracker" && (<div className="space-y-3">{KPIS.map((kpi) => (<div key={kpi.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{kpi.id}</span><span className="ml-2 text-white/90 font-medium">{kpi.name}</span></div><StatusBadge status={kpi.status} /></div><p className="text-white/70 text-sm">{kpi.value} / {kpi.target}</p><p className="text-white/50 text-xs mt-1">{kpi.detail}</p></div>))}</div>)}
      {tab === "team_performance" && (<div className="card-surface p-6"><p className="text-white/60">SOC team productivity metrics: 12.3 tickets/analyst/day, 78% utilization, balanced workload across 3 shifts.</p></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Trend Analysis</h3>{[{ m: "True Positive Rate", v: "82%", t: "+3%" }, { m: "Cost per Incident", v: "$3,200", t: "-$200" }, { m: "Monthly Spend", v: "$142K", t: "+2%" }, { m: "Alert Noise Ratio", v: "18%", t: "-3%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
