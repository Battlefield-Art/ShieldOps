import { useState } from "react";
import { Box, Search, Users, AlertTriangle, Shield, Server, Database, Globe } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "assets" | "ownership" | "risk";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "assets", label: "Assets" }, { id: "ownership", label: "Ownership" }, { id: "risk", label: "Risk" }];
export default function AssetInventory() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Asset Inventory" subtitle="Dynamic asset discovery, classification, and ownership tracking" icon={<Box className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Total Assets" value="1,247" icon={<Server className="h-5 w-5" />} />
      <MetricCard title="Unmanaged" value="23" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Coverage" value="98.2%" icon={<Search className="h-5 w-5" />} />
      <MetricCard title="Owners Assigned" value="96%" icon={<Users className="h-5 w-5" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Asset Distribution</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-3">
      {[{ type: "Servers", count: 342, icon: <Server className="h-4 w-4 text-cyan-400" /> }, { type: "Containers", count: 518, icon: <Box className="h-4 w-4 text-emerald-400" /> }, { type: "Databases", count: 87, icon: <Database className="h-4 w-4 text-yellow-400" /> }, { type: "APIs", count: 300, icon: <Globe className="h-4 w-4 text-purple-400" /> }].map((s) => (
        <div key={s.type} className="card-interactive p-4 text-center"><div className="flex items-center justify-center gap-2 mb-2">{s.icon}<p className="text-xs text-white/50">{s.type}</p></div><p className="text-2xl font-bold text-white">{s.count}</p></div>))}</div></div>)}
    {tab === "assets" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Name</th><th className="px-4 py-3">Type</th><th className="px-4 py-3">Cloud</th><th className="px-4 py-3">Criticality</th><th className="px-4 py-3">Managed</th><th className="px-4 py-3">Owner</th></tr></thead>
      <tbody>{[
        { name: "web-api-01", type: "api_endpoint", cloud: "AWS", crit: "high", managed: true, owner: "backend" },
        { name: "postgres-primary", type: "database", cloud: "AWS", crit: "critical", managed: true, owner: "data-eng" },
        { name: "ml-inference-v2", type: "ai_model", cloud: "GCP", crit: "high", managed: true, owner: "ml-eng" },
        { name: "unknown-svc-8080", type: "unknown", cloud: "AWS", crit: "informational", managed: false, owner: "unassigned" },
        { name: "k8s-worker-pool", type: "container", cloud: "AWS", crit: "high", managed: true, owner: "platform" },
      ].map((a, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-cyan-400 font-mono text-xs">{a.name}</td><td className="px-4 py-3 text-white/80">{a.type}</td><td className="px-4 py-3 text-white/70">{a.cloud}</td><td className="px-4 py-3"><StatusBadge status={a.crit} /></td><td className="px-4 py-3">{a.managed ? <Shield className="h-4 w-4 text-emerald-400" /> : <AlertTriangle className="h-4 w-4 text-red-400" />}</td><td className="px-4 py-3 text-white/70">{a.owner}</td></tr>))}</tbody></table></div>)}
    {tab === "ownership" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Ownership Coverage by Team</h3>
      {[{ team: "Platform Eng", assets: 342, assigned: 340, coverage: 99 }, { team: "Backend Eng", assets: 300, assigned: 295, coverage: 98 }, { team: "Data Eng", assets: 87, assigned: 85, coverage: 98 }, { team: "ML Eng", assets: 45, assigned: 42, coverage: 93 }, { team: "Security Ops", assets: 23, assigned: 18, coverage: 78 }].map((t) => (
        <div key={t.team} className="card-interactive p-4"><div className="flex items-center justify-between mb-2"><p className="text-white/90 font-medium">{t.team}</p><span className="text-sm text-white/60">{t.assigned}/{t.assets} assigned ({t.coverage}%)</span></div>
        <div className="h-2 bg-white/10 rounded-full"><div className={clsx("h-2 rounded-full", t.coverage >= 95 ? "bg-emerald-500" : t.coverage >= 85 ? "bg-yellow-500" : "bg-red-500")} style={{ width: `${t.coverage}%` }} /></div></div>))}</div>)}
    {tab === "risk" && (<div className="card-surface p-6"><h3 className="section-heading">Risk Distribution</h3><div className="grid grid-cols-2 gap-4">
      {[{ level: "Critical Risk", count: 5, color: "text-red-400" }, { level: "High Risk", count: 18, color: "text-orange-400" }, { level: "Medium Risk", count: 47, color: "text-yellow-400" }, { level: "Low Risk", count: 1177, color: "text-emerald-400" }].map((r) => (
        <div key={r.level} className="card-interactive p-4"><p className="text-sm text-white/60">{r.level}</p><p className={clsx("text-2xl font-bold mt-1", r.color)}>{r.count}</p></div>))}</div></div>)}
  </div>);
}
