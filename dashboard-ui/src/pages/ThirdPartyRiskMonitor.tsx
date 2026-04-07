import { useState } from "react";
import { Globe, Shield, AlertTriangle, Users, TrendingUp } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "vendor_risk" | "posture_changes" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "vendor_risk", label: "Vendor Risk" },
  { id: "posture_changes", label: "Posture Changes" },
  { id: "metrics", label: "Metrics" },
];

const VENDORS = [
  { id: "VND-001", name: "CloudAuth Inc.", tier: "Critical", score: 82, services: "SSO, MFA", status: "medium" },
  { id: "VND-002", name: "DataPipe Analytics", tier: "High", score: 45, services: "Data Processing", status: "critical" },
  { id: "VND-003", name: "SecureLog SaaS", tier: "Medium", score: 91, services: "Log Management", status: "low" },
  { id: "VND-004", name: "PayStream Corp", tier: "Critical", score: 67, services: "Payment Processing", status: "high" },
];

const CHANGES = [
  { id: "CHG-001", vendor: "DataPipe Analytics", change: "SOC 2 Type II certification expired", severity: "critical", delta: "-15 pts" },
  { id: "CHG-002", vendor: "PayStream Corp", change: "New data breach reported in SEC filing", severity: "high", delta: "-8 pts" },
  { id: "CHG-003", vendor: "CloudAuth Inc.", change: "Added ISO 27001 certification", severity: "info", delta: "+5 pts" },
];

export default function ThirdPartyRiskMonitor() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Third-Party Risk Monitor" subtitle="Continuous vendor risk monitoring and posture assessment" icon={<Globe className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Monitored Vendors" value="156" icon={<Users className="h-5 w-5" />} />
        <MetricCard title="High Risk" value="12" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Posture Changes (7d)" value="8" icon={<TrendingUp className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Avg Risk Score" value="74" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Vendor Tier Distribution</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Critical", v: "23", c: "text-red-400" }, { l: "High", v: "41", c: "text-yellow-400" }, { l: "Medium", v: "58", c: "text-cyan-400" }, { l: "Low", v: "34", c: "text-white/70" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "vendor_risk" && (<div className="space-y-3">{VENDORS.map((v) => (<div key={v.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{v.id}</span><span className="ml-2 text-xs text-white/40">{v.tier}</span></div><StatusBadge status={v.status} /></div><p className="text-white/90 text-sm">{v.name}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>Score: {v.score}/100</span><span>{v.services}</span></div></div>))}</div>)}
      {tab === "posture_changes" && (<div className="space-y-3">{CHANGES.map((c) => (<div key={c.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{c.id}</span><span className="ml-2 text-xs text-white/40">{c.vendor}</span></div><StatusBadge status={c.severity} /></div><p className="text-white/90 text-sm">{c.change}</p><span className={clsx("text-xs font-mono", c.delta.startsWith("+") ? "text-emerald-400" : "text-red-400")}>{c.delta}</span></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Risk Monitoring Metrics</h3>{[{ m: "Avg Risk Score", v: "74", t: "-3 pts" }, { m: "Vendors Assessed (30d)", v: "142", t: "+18" }, { m: "SLA Compliance", v: "89%", t: "+2%" }, { m: "Breach Notifications", v: "3", t: "-1" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
