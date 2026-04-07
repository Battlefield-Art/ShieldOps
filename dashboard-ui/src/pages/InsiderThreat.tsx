import { useState } from "react";
import { UserX, Eye, AlertTriangle, TrendingUp, Users } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "risks" | "deviations" | "investigations";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "risks", label: "Risk Scores" }, { id: "deviations", label: "Deviations" }, { id: "investigations", label: "Investigations" }];
export default function InsiderThreat() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Insider Threat" subtitle="Identity + behavior + data access fusion for insider threat detection" icon={<UserX className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Users Monitored" value="2.4K" icon={<Users className="h-5 w-5" />} />
      <MetricCard title="High Risk" value="7" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Deviations (7d)" value="34" icon={<TrendingUp className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Active Investigations" value="3" icon={<Eye className="h-5 w-5 text-cyan-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Risk Categories</h3><div className="grid grid-cols-1 md:grid-cols-5 gap-3">
      {[{ cat: "Flight Risk", count: 2, color: "text-red-400" }, { cat: "Data Theft", count: 1, color: "text-red-400" }, { cat: "Negligence", count: 3, color: "text-yellow-400" }, { cat: "Privilege Abuse", count: 1, color: "text-yellow-400" }, { cat: "Espionage", count: 0, color: "text-white/40" }].map((c) => (
        <div key={c.cat} className="card-interactive p-3 text-center"><p className="text-xs text-white/60">{c.cat}</p><p className={clsx("text-2xl font-bold mt-1", c.color)}>{c.count}</p></div>))}</div></div>)}
    {tab === "risks" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">User</th><th className="px-4 py-3">Risk Score</th><th className="px-4 py-3">Category</th><th className="px-4 py-3">Indicators</th><th className="px-4 py-3">Status</th></tr></thead>
      <tbody>{[
        { user: "john.d@corp.com", score: 0.91, cat: "flight_risk", indicators: 5, status: "investigating" },
        { user: "sarah.k@corp.com", score: 0.84, cat: "data_theft", indicators: 4, status: "monitoring" },
        { user: "dev-contractor-3", score: 0.78, cat: "negligence", indicators: 3, status: "monitoring" },
      ].map((u, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90">{u.user}</td><td className="px-4 py-3"><span className={clsx("font-mono", u.score > 0.8 ? "text-red-400" : "text-yellow-400")}>{u.score}</span></td><td className="px-4 py-3"><StatusBadge status={u.cat} /></td><td className="px-4 py-3 text-white/80">{u.indicators}</td><td className="px-4 py-3"><StatusBadge status={u.status} /></td></tr>))}</tbody></table></div>)}
    {tab === "deviations" && (<div className="space-y-3">
      {[{ user: "john.d@corp.com", deviation: "Bulk download 2.3GB from shared drive", type: "data_hoarding", severity: "high", baseline: "Avg 50MB/day" },
        { user: "sarah.k@corp.com", deviation: "Accessed customer DB at 2am (never before)", type: "off_hours_access", severity: "high", baseline: "Always 9am-6pm" },
        { user: "dev-contractor-3", deviation: "Used personal email to send code files", type: "unauthorized_tool_use", severity: "medium", baseline: "Corporate email only" },
      ].map((d, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><p className="text-white/90 font-medium">{d.user}</p><StatusBadge status={d.severity} /></div>
        <p className="text-white/70 text-sm">{d.deviation}</p><p className="text-xs text-white/50">Type: {d.type} | Baseline: {d.baseline}</p></div>))}</div>)}
    {tab === "investigations" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Active Investigations</h3>
      {[{ user: "john.d@corp.com", reason: "Flight risk: resignation + data hoarding + after-hours access", status: "in_progress", started: "2d ago" },
        { user: "sarah.k@corp.com", reason: "Off-hours DB access + credential sharing detected", status: "in_progress", started: "1d ago" },
        { user: "ex-employee-42", reason: "Post-termination access attempt from personal device", status: "escalated", started: "3h ago" },
      ].map((inv, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{inv.user}</p><p className="text-xs text-white/50">{inv.reason} | Started: {inv.started}</p></div><StatusBadge status={inv.status} /></div>))}</div>)}
  </div>);
}
