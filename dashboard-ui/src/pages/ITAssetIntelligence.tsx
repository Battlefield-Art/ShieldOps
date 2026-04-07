import { useState } from "react";
import { Server, Shield, AlertTriangle, Database, Target } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "assets" | "risks" | "posture";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "assets", label: "Assets" }, { id: "risks", label: "Risks" }, { id: "posture", label: "Posture" }];
export default function ITAssetIntelligence() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="IT Asset Intelligence" subtitle="Security + IT asset convergence with AI risk context" icon={<Server className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Total Assets" value="4.7K" icon={<Database className="h-5 w-5" />} />
      <MetricCard title="Critical Risk" value="23" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Unmanaged" value="47" icon={<Target className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Posture Score" value="87%" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Assets by Category</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {[{ cat: "Servers + Endpoints", count: "2.8K", risk: 12, color: "text-cyan-400" }, { cat: "Cloud Resources", count: "1.4K", risk: 8, color: "text-yellow-400" }, { cat: "AI Systems + IoT", count: 523, risk: 3, color: "text-emerald-400" }].map((c) => (
        <div key={c.cat} className="card-interactive p-4"><p className={clsx("font-bold", c.color)}>{c.cat}</p><p className="text-2xl font-bold text-white/80 mt-1">{c.count}</p><p className="text-xs text-white/40">{c.risk} critical risks</p></div>))}</div></div>)}
    {tab === "assets" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Asset</th><th className="px-4 py-3">Category</th><th className="px-4 py-3">Criticality</th><th className="px-4 py-3">Posture</th></tr></thead>
      <tbody>{[
        { name: "prod-db-primary", cat: "server", crit: "mission_critical", posture: "compliant" },
        { name: "claude-inference-gpu", cat: "ai_system", crit: "business_critical", posture: "at_risk" },
        { name: "unknown-device-34", cat: "iot_device", crit: "unknown", posture: "critical" },
      ].map((a, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90">{a.name}</td><td className="px-4 py-3"><StatusBadge status={a.cat} /></td><td className="px-4 py-3"><StatusBadge status={a.crit} /></td><td className="px-4 py-3"><StatusBadge status={a.posture} /></td></tr>))}</tbody></table></div>)}
    {tab === "risks" && (<div className="space-y-3">
      {[{ asset: "claude-inference-gpu", risk: "Unpatched CUDA driver CVE", severity: "critical", threat: "Active exploitation" },
        { asset: "unknown-device-34", risk: "Unmanaged device on production network", severity: "critical", threat: "No visibility" },
        { asset: "legacy-app-server", risk: "EOL OS with 12 unpatched CVEs", severity: "high", threat: "Exploit available" },
      ].map((r, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><p className="text-white/90 font-medium">{r.asset}</p><StatusBadge status={r.severity} /></div>
        <p className="text-white/70 text-sm">{r.risk}</p><p className="text-xs text-white/50">Threat: {r.threat}</p></div>))}</div>)}
    {tab === "posture" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Security Posture</h3>
      {[{ dim: "Patch Compliance", score: "89%", trend: "improving" }, { dim: "Config Compliance", score: "92%", trend: "stable" }, { dim: "Endpoint Protection", score: "97%", trend: "improving" }, { dim: "Access Control", score: "84%", trend: "at_risk" }].map((p, i) => (
        <div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{p.dim}</p><p className="text-emerald-400 text-2xl font-bold">{p.score}</p></div><StatusBadge status={p.trend} /></div>))}</div>)}
  </div>);
}
