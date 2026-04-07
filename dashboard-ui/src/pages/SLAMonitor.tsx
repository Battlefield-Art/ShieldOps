import { useState } from "react";
import { Gauge, AlertTriangle, TrendingUp, Activity } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "slos" | "budgets" | "alerts";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "slos", label: "SLO Status" }, { id: "budgets", label: "Error Budgets" }, { id: "alerts", label: "Burn Rate Alerts" }];
export default function SLAMonitor() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="SLA Monitor" subtitle="SLO/SLA monitoring with error budget tracking and burn rate alerts" icon={<Gauge className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="SLOs Tracked" value="24" icon={<Gauge className="h-5 w-5" />} />
      <MetricCard title="SLOs Breaching" value="2" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Avg Budget Remaining" value="62%" icon={<TrendingUp className="h-5 w-5" />} />
      <MetricCard title="Burn Rate Alerts" value="3" icon={<Activity className="h-5 w-5 text-yellow-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6 space-y-4"><h3 className="section-heading">SLO Health Summary</h3>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {[{ status: "Healthy", count: 18, color: "text-emerald-400" }, { status: "Warning", count: 4, color: "text-yellow-400" }, { status: "Critical", count: 2, color: "text-red-400" }].map((s) => (
          <div key={s.status} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.status}</p><p className={clsx("text-3xl font-bold mt-1", s.color)}>{s.count}</p></div>))}
      </div></div>)}
    {tab === "slos" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Service</th><th className="px-4 py-3">SLO</th><th className="px-4 py-3">Target</th><th className="px-4 py-3">Current</th><th className="px-4 py-3">Budget</th><th className="px-4 py-3">Status</th></tr></thead>
      <tbody>{[
        { svc: "api-gateway", slo: "Availability", target: "99.95%", current: "99.92%", budget: "38%", status: "warning" },
        { svc: "user-service", slo: "P99 Latency", target: "<200ms", current: "185ms", budget: "72%", status: "healthy" },
        { svc: "billing", slo: "Error Rate", target: "<0.1%", current: "0.15%", budget: "12%", status: "critical" },
        { svc: "auth-service", slo: "Availability", target: "99.99%", current: "99.995%", budget: "89%", status: "healthy" },
      ].map((s, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-cyan-400 font-mono text-sm">{s.svc}</td><td className="px-4 py-3 text-white/80">{s.slo}</td><td className="px-4 py-3 text-white/60">{s.target}</td><td className="px-4 py-3 text-white/90 font-medium">{s.current}</td><td className="px-4 py-3 text-white/70">{s.budget}</td><td className="px-4 py-3"><StatusBadge status={s.status} /></td></tr>))}</tbody></table></div>)}
    {tab === "budgets" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Error Budget Consumption</h3>
      {[{ svc: "api-gateway", budget: 38, burn: "2.1x", action: "Slow deploys" }, { svc: "billing", budget: 12, burn: "4.8x", action: "Deploy freeze" }, { svc: "user-service", budget: 72, burn: "0.8x", action: "None" }].map((b) => (
        <div key={b.svc} className="card-interactive p-4"><div className="flex items-center justify-between mb-2"><p className="text-white/90 font-medium">{b.svc}</p><span className={clsx("font-bold", b.budget <= 20 ? "text-red-400" : b.budget <= 50 ? "text-yellow-400" : "text-emerald-400")}>{b.budget}% remaining</span></div>
        <div className="h-2 bg-white/10 rounded-full"><div className={clsx("h-2 rounded-full", b.budget <= 20 ? "bg-red-500" : b.budget <= 50 ? "bg-yellow-500" : "bg-cyan-500")} style={{ width: `${b.budget}%` }} /></div>
        <p className="text-xs text-white/50 mt-1">Burn rate: {b.burn} | Action: {b.action}</p></div>))}</div>)}
    {tab === "alerts" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Active Burn Rate Alerts</h3>
      {[{ svc: "billing", sev: "page", burn1h: "8.2x", burn6h: "4.8x", exhaust: "6h", action: "Incident response" },
        { svc: "api-gateway", sev: "ticket", burn1h: "2.1x", burn6h: "1.8x", exhaust: "4d", action: "Investigate" },
      ].map((a, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-center justify-between mb-2"><p className="text-white/90 font-medium">{a.svc}</p><StatusBadge status={a.sev === "page" ? "critical" : "warning"} /></div>
        <div className="flex gap-4 text-xs text-white/50"><span>1h burn: {a.burn1h}</span><span>6h burn: {a.burn6h}</span><span>Exhaustion: {a.exhaust}</span><span className="text-cyan-400">{a.action}</span></div></div>))}</div>)}
  </div>);
}
