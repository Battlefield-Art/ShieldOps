import { useState } from "react";
import { Cpu, Shield, BarChart3, AlertTriangle } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "details" | "alerts" | "metrics";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "details", label: "Details" }, { id: "alerts", label: "Alerts" }, { id: "metrics", label: "Metrics" }];
export default function MobileDeviceManager() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Mobile Device Manager" subtitle="MDM enrollment compliance and security" icon={<Cpu className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Monitored" value="1,247" icon={<Cpu className="h-5 w-5" />} />
      <MetricCard title="Issues" value="12" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Compliant" value="96%" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Score" value="A" icon={<BarChart3 className="h-5 w-5 text-cyan-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Status Overview</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">{[{ label: "Healthy", value: "1,180", color: "text-emerald-400" }, { label: "Warning", value: "55", color: "text-yellow-400" }, { label: "Critical", value: "12", color: "text-red-400" }].map((s) => (<div key={s.label} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.label}</p><p className={clsx("text-2xl font-bold mt-1", s.color)}>{s.value}</p></div>))}</div></div>)}
    {tab === "details" && (<div className="card-surface p-6"><p className="text-white/60">Detailed view coming soon.</p></div>)}
    {tab === "alerts" && (<div className="space-y-3">{[{ id: "A-001", msg: "Anomalous behavior detected", severity: "high" }, { id: "A-002", msg: "Policy violation", severity: "medium" }].map((a) => (<div key={a.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><span className="font-mono text-xs text-cyan-400">{a.id}</span><StatusBadge status={a.severity} /></div><p className="text-white/90">{a.msg}</p></div>))}</div>)}
    {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Metrics</h3>{[{ metric: "Detection Rate", value: "99.2%", trend: "+0.3% vs last week" }, { metric: "Response Time", value: "1.2s", trend: "-15% vs last month" }].map((m, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{m.metric}</p><p className="text-xs text-white/50">{m.trend}</p></div><span className="text-cyan-400 font-mono">{m.value}</span></div>))}</div>)}
  </div>);
}
