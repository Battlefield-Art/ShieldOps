import { useState } from "react";
import { Key, Shield, BarChart3, CheckCircle } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "findings" | "details" | "metrics";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "findings", label: "Findings" }, { id: "details", label: "Details" }, { id: "metrics", label: "Metrics" }];
export default function SecretsInCodeDetector() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Secrets Detector" subtitle="Detect hardcoded secrets" icon={<Key className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Scans Run" value="24" icon={<Key className="h-5 w-5" />} />
      <MetricCard title="Issues Found" value="34" icon={<Shield className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Resolved" value="89%" icon={<CheckCircle className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Risk Score" value="Low" icon={<BarChart3 className="h-5 w-5 text-cyan-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Summary</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">{[{ label: "Critical", value: "3", color: "text-red-400" }, { label: "High", value: "12", color: "text-yellow-400" }, { label: "Medium", value: "19", color: "text-white/60" }].map((s) => (<div key={s.label} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.label}</p><p className={clsx("text-2xl font-bold mt-1", s.color)}>{s.value}</p></div>))}</div></div>)}
    {tab === "findings" && (<div className="space-y-3">{[{ id: "F-001", title: "Critical vulnerability detected", severity: "critical" }, { id: "F-002", title: "High-risk configuration", severity: "high" }, { id: "F-003", title: "Medium-risk finding", severity: "medium" }].map((f) => (<div key={f.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><span className="font-mono text-xs text-cyan-400">{f.id}</span><StatusBadge status={f.severity} /></div><p className="text-white/90">{f.title}</p></div>))}</div>)}
    {tab === "details" && (<div className="card-surface p-6"><h3 className="section-heading">Scan Details</h3><p className="text-white/60">Last scan completed 2 hours ago. Next scheduled in 4 hours.</p></div>)}
    {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Trend</h3>{[{ metric: "Issues/scan", value: "1.4", trend: "-23% vs last month" }, { metric: "Resolution time", value: "2.3 days", trend: "-45% vs last quarter" }].map((m, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{m.metric}</p><p className="text-xs text-white/50">{m.trend}</p></div><span className="text-cyan-400 font-mono">{m.value}</span></div>))}</div>)}
  </div>);
}
