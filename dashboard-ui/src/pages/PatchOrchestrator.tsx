import { useState } from "react";
import { Download, Shield, CheckCircle, AlertTriangle, RefreshCw, Server } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "patches" | "deployments" | "rollbacks";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "patches", label: "Patches" }, { id: "deployments", label: "Deployments" }, { id: "rollbacks", label: "Rollbacks" }];
export default function PatchOrchestrator() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Patch Orchestrator" subtitle="Automated patch prioritization, staged deployment, verification, and rollback" icon={<Download className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Systems Managed" value="847" icon={<Server className="h-5 w-5" />} />
      <MetricCard title="Patches Deployed (7d)" value="234" icon={<CheckCircle className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Pending Critical" value="7" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Rollbacks" value="2" icon={<RefreshCw className="h-5 w-5 text-yellow-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Patch Compliance</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {[{ window: "Within SLA", count: 812, pct: "95.9%", color: "text-emerald-400" }, { window: "Overdue", count: 28, pct: "3.3%", color: "text-yellow-400" }, { window: "Critical Overdue", count: 7, pct: "0.8%", color: "text-red-400" }].map((w) => (
        <div key={w.window} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{w.window}</p><p className={clsx("text-3xl font-bold mt-1", w.color)}>{w.pct}</p><p className="text-xs text-white/40">{w.count} systems</p></div>))}</div></div>)}
    {tab === "patches" && (<div className="space-y-3">
      {[{ id: "PATCH-234", cve: "CVE-2026-XXXX", package: "openssl 3.2.1", priority: "emergency", systems: 45, status: "deploying" },
        { id: "PATCH-233", cve: "CVE-2026-YYYY", package: "linux-kernel 6.8", priority: "critical", systems: 120, status: "canary" },
        { id: "PATCH-232", cve: "CVE-2025-ZZZZ", package: "nginx 1.26.0", priority: "high", systems: 34, status: "pending" },
      ].map((p) => (<div key={p.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{p.id}</span><span className="text-xs text-white/40 ml-2">{p.cve}</span></div><StatusBadge status={p.priority} /></div>
        <p className="text-white/90 font-medium">{p.package}</p><p className="text-xs text-white/50">{p.systems} systems | <StatusBadge status={p.status} /></p></div>))}</div>)}
    {tab === "deployments" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Deployment Pipeline</h3>
      {[{ phase: "Canary (1 system)", patch: "linux-kernel 6.8", status: "verifying", time: "12 min" },
        { phase: "Staged (10%)", patch: "openssl 3.2.1", status: "deploying", time: "45 min" },
        { phase: "Full rollout", patch: "curl 8.6.0", status: "completed", time: "2h" },
      ].map((d, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{d.phase}</p><p className="text-xs text-white/50">{d.patch} | {d.time}</p></div><StatusBadge status={d.status} /></div>))}</div>)}
    {tab === "rollbacks" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Recent Rollbacks</h3>
      {[{ patch: "java-17.0.10", reason: "Application startup failure on 3/10 canary hosts", systems: 10, status: "rolled_back" },
        { patch: "postgres-16.2", reason: "Query performance degradation detected", systems: 3, status: "rolled_back" },
      ].map((r, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{r.patch}</p><p className="text-xs text-white/50">{r.reason} | {r.systems} systems</p></div><StatusBadge status={r.status} /></div>))}</div>)}
  </div>);
}
