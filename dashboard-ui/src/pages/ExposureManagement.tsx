import { useState } from "react";
import { Globe, Radar, AlertTriangle, Shield, Target, BarChart3 } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "surfaces" | "exposures" | "remediation";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "surfaces", label: "Attack Surfaces" }, { id: "exposures", label: "Exposures" }, { id: "remediation", label: "Remediation" }];
export default function ExposureManagement() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Exposure Management" subtitle="Unified attack surface across cloud, identity, AI endpoints, and code" icon={<Globe className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Attack Surfaces" value="6" icon={<Radar className="h-5 w-5" />} />
      <MetricCard title="Critical Exposures" value="14" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Assets Discovered" value="2.1K" icon={<Target className="h-5 w-5 text-cyan-400" />} />
      <MetricCard title="Exposure Score" value="34/100" icon={<BarChart3 className="h-5 w-5 text-yellow-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Exposure by Surface</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {[{ surface: "Cloud Infrastructure", exposures: 8, score: 42, color: "text-yellow-400" },
        { surface: "AI Endpoints", exposures: 3, score: 28, color: "text-cyan-400" },
        { surface: "External Network", exposures: 3, score: 35, color: "text-yellow-400" }].map((s) => (
        <div key={s.surface} className="card-interactive p-4"><p className={clsx("font-bold", s.color)}>{s.surface}</p><p className="text-2xl font-bold text-white/80 mt-1">{s.exposures} exposures</p><p className="text-xs text-white/40">Score: {s.score}/100</p></div>))}</div></div>)}
    {tab === "surfaces" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Surface</th><th className="px-4 py-3">Assets</th><th className="px-4 py-3">Exposures</th><th className="px-4 py-3">Critical</th><th className="px-4 py-3">Score</th></tr></thead>
      <tbody>{[
        { surface: "External Network", assets: 245, exposures: 3, critical: 1, score: 35 },
        { surface: "Cloud Infrastructure", assets: 890, exposures: 8, critical: 3, score: 42 },
        { surface: "Identity Surface", assets: 420, exposures: 2, critical: 1, score: 28 },
        { surface: "AI Endpoints", assets: 52, exposures: 3, critical: 2, score: 48 },
        { surface: "Code Repositories", assets: 340, exposures: 1, critical: 0, score: 15 },
        { surface: "API Surface", assets: 153, exposures: 2, critical: 1, score: 32 },
      ].map((s, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90 font-medium">{s.surface}</td><td className="px-4 py-3 text-white/80">{s.assets}</td><td className="px-4 py-3 text-yellow-400">{s.exposures}</td><td className="px-4 py-3 text-red-400">{s.critical}</td><td className="px-4 py-3 font-mono text-white/70">{s.score}</td></tr>))}</tbody></table></div>)}
    {tab === "exposures" && (<div className="space-y-3">
      {[{ id: "EXP-014", exposure: "Unprotected MCP server accepting any client", surface: "AI Endpoints", severity: "critical", epss: 0.89 },
        { id: "EXP-013", exposure: "Public S3 bucket with customer data", surface: "Cloud", severity: "critical", epss: 0.92 },
        { id: "EXP-012", exposure: "LLM endpoint without auth", surface: "AI Endpoints", severity: "critical", epss: 0.78 },
        { id: "EXP-011", exposure: "Stale service account with admin role", surface: "Identity", severity: "high", epss: 0.65 },
      ].map((e) => (<div key={e.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{e.id}</span><span className="text-xs text-white/40 ml-2">EPSS: {e.epss}</span></div><StatusBadge status={e.severity} /></div>
        <p className="text-white/90 font-medium">{e.exposure}</p><p className="text-xs text-white/50">Surface: {e.surface}</p></div>))}</div>)}
    {tab === "remediation" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Prioritized Remediation</h3>
      {[{ action: "Add auth to MCP server", exposure: "EXP-014", effort: "Low", impact: "Critical", status: "pending" },
        { action: "Restrict S3 bucket ACL", exposure: "EXP-013", effort: "Low", impact: "Critical", status: "in_progress" },
        { action: "Add API key to LLM endpoint", exposure: "EXP-012", effort: "Medium", impact: "Critical", status: "pending" },
      ].map((r, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{r.action}</p><p className="text-xs text-white/50">{r.exposure} | Effort: {r.effort} | Impact: {r.impact}</p></div><StatusBadge status={r.status} /></div>))}</div>)}
  </div>);
}
