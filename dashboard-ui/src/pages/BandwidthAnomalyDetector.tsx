import { useState } from "react";
import { TrendingUp, AlertTriangle, Activity, Clock } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "anomalies" | "baselines" | "alerts";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "anomalies", label: "Anomalies" }, { id: "baselines", label: "Baselines" }, { id: "alerts", label: "Alerts" }];
export default function BandwidthAnomalyDetector() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Bandwidth Anomaly Detector" subtitle="Detect unusual traffic spikes, off-hours transfers, crypto-mining patterns" icon={<TrendingUp className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Anomalies (24h)" value="7" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Avg Bandwidth" value="2.3 Gbps" icon={<Activity className="h-5 w-5 text-cyan-400" />} />
      <MetricCard title="Peak Deviation" value="+340%" icon={<TrendingUp className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Detection Time" value="12 sec" icon={<Clock className="h-5 w-5 text-emerald-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Traffic Categories</h3><div className="grid grid-cols-2 md:grid-cols-4 gap-3">{[{ cat: "Normal", pct: "89%", color: "text-emerald-400" }, { cat: "Spike", pct: "6%", color: "text-yellow-400" }, { cat: "Off-Hours", pct: "3%", color: "text-yellow-400" }, { cat: "Suspicious", pct: "2%", color: "text-red-400" }].map((c) => (<div key={c.cat} className="card-interactive p-3 text-center"><p className="text-xs text-white/60">{c.cat}</p><p className={clsx("text-xl font-bold mt-1", c.color)}>{c.pct}</p></div>))}</div></div>)}
    {tab === "anomalies" && (<div className="space-y-3">{[{ id: "BW-071", type: "Traffic Spike", host: "db-primary-01", deviation: "+340%", time: "2:34 AM", severity: "high" }, { id: "BW-070", type: "Off-Hours Transfer", host: "dev-workstation-12", deviation: "+180%", time: "3:12 AM", severity: "medium" }].map((a) => (<div key={a.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><span className="font-mono text-xs text-cyan-400">{a.id}</span><StatusBadge status={a.severity} /></div><p className="text-white/90 font-medium">{a.type}</p><p className="text-xs text-white/50">{a.host} | Deviation: {a.deviation} | {a.time}</p></div>))}</div>)}
    {tab === "baselines" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Segment</th><th className="px-4 py-3">Avg (Mbps)</th><th className="px-4 py-3">Peak</th><th className="px-4 py-3">Status</th></tr></thead><tbody>{[{ seg: "Production", avg: 1200, peak: 2400, status: "normal" }, { seg: "Development", avg: 340, peak: 890, status: "normal" }, { seg: "DMZ", avg: 560, peak: 4200, status: "anomaly" }].map((b, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90">{b.seg}</td><td className="px-4 py-3 text-white/80">{b.avg}</td><td className="px-4 py-3 text-white/70">{b.peak}</td><td className="px-4 py-3"><StatusBadge status={b.status} /></td></tr>))}</tbody></table></div>)}
    {tab === "alerts" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Recent Alerts</h3>{[{ time: "2:34 AM", alert: "Traffic spike on db-primary-01 — 340% above baseline", status: "investigating" }, { time: "3:12 AM", alert: "Off-hours bulk transfer from dev-workstation-12", status: "resolved" }].map((a, i) => (<div key={i} className="card-interactive p-3 flex items-center justify-between"><div><p className="text-white/80 text-sm">{a.alert}</p><p className="text-xs text-white/40">{a.time}</p></div><StatusBadge status={a.status} /></div>))}</div>)}
  </div>);
}
