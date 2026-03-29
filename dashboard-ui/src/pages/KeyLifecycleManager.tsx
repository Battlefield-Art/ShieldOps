import { useState } from "react";
import { TrendingUp, Shield, BarChart3, AlertTriangle } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "findings" | "details" | "metrics";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "findings", label: "Findings" }, { id: "details", label: "Details" }, { id: "metrics", label: "Metrics" }];
export default function KeyLifecycleManager() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Key Lifecycle Manager" subtitle="HSM/KMS key management and ceremony auditing" icon={<Shield className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Active Keys" value="1,204" icon={<TrendingUp className="h-5 w-5" />} />
      <MetricCard title="Expiring Soon" value="23" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Compliant" value="96%" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Ceremonies" value="18" icon={<BarChart3 className="h-5 w-5 text-cyan-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Summary</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">{[{ l: "Active", v: "1,204", c: "text-emerald-400" }, { l: "Expiring", v: "23", c: "text-yellow-400" }, { l: "Compromised", v: "0", c: "text-red-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
    {tab === "findings" && (<div className="space-y-3">{[{ id: "KLM-001", t: "23 keys approaching rotation deadline in production HSM", s: "high" }, { id: "KLM-002", t: "Key ceremony audit gap — last audit 47 days ago", s: "medium" }].map((f) => (<div key={f.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><span className="font-mono text-xs text-cyan-400">{f.id}</span><StatusBadge status={f.s} /></div><p className="text-white/90">{f.t}</p></div>))}</div>)}
    {tab === "details" && (<div className="card-surface p-6"><p className="text-white/60">Key inventory, rotation schedules, and HSM ceremony logs.</p></div>)}
    {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Trends</h3>{[{ m: "Rotation Compliance", v: "96.1%", t: "+0.8% this week" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
  </div>);
}
