import { useState } from "react";
import { Download, Shield, AlertTriangle, CheckCircle, Server } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "patch_inventory" | "deployment_schedule" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "patch_inventory", label: "Patch Inventory" },
  { id: "deployment_schedule", label: "Deployment Schedule" },
  { id: "metrics", label: "Metrics" },
];

const PATCHES = [
  { id: "CVE-2026-1234", software: "Linux Kernel 6.8", severity: "critical", assets: 47, reboot: true, status: "pending" },
  { id: "CVE-2026-2345", software: "OpenSSL 3.2.1", severity: "high", assets: 128, reboot: false, status: "deployed" },
  { id: "CVE-2026-3456", software: "PostgreSQL 16.2", severity: "medium", assets: 12, reboot: false, status: "scheduled" },
  { id: "CVE-2026-4567", software: "nginx 1.25.4", severity: "high", assets: 34, reboot: false, status: "pending" },
  { id: "CVE-2026-5678", software: "Docker Engine 25.0", severity: "medium", assets: 89, reboot: true, status: "deployed" },
];

const SCHEDULES = [
  { id: "DEP-001", patches: 3, strategy: "Canary", window: "Sat 02:00-06:00", env: "production", status: "scheduled" },
  { id: "DEP-002", patches: 5, strategy: "Rolling", window: "Immediate", env: "staging", status: "active" },
  { id: "DEP-003", patches: 2, strategy: "Blue-Green", window: "Sun 00:00-04:00", env: "production", status: "pending" },
];

export default function AutonomousPatchManager() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Autonomous Patch Manager" subtitle="Risk-based autonomous patch management and deployment" icon={<Download className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Pending Patches" value="23" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Assets Scanned" value="1,247" icon={<Server className="h-5 w-5" />} />
        <MetricCard title="Deployed (30d)" value="89" icon={<CheckCircle className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Success Rate" value="99.2%" icon={<Shield className="h-5 w-5 text-cyan-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Patch Severity Distribution</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Critical", v: "3", c: "text-red-400" }, { l: "High", v: "8", c: "text-yellow-400" }, { l: "Medium", v: "9", c: "text-cyan-400" }, { l: "Low", v: "3", c: "text-white/70" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "patch_inventory" && (<div className="space-y-3">{PATCHES.map((p) => (<div key={p.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{p.id}</span><span className="ml-2 text-xs text-white/40">{p.software}</span></div><StatusBadge status={p.severity} /></div><div className="flex gap-4 mt-2 text-xs text-white/50"><span>{p.assets} assets</span><span className={p.reboot ? "text-yellow-400" : "text-white/40"}>Reboot: {p.reboot ? "Required" : "No"}</span><StatusBadge status={p.status} /></div></div>))}</div>)}
      {tab === "deployment_schedule" && (<div className="space-y-3">{SCHEDULES.map((s) => (<div key={s.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{s.id}</span><span className="ml-2 text-xs text-white/40">{s.strategy}</span></div><StatusBadge status={s.status} /></div><div className="flex gap-4 mt-2 text-xs text-white/50"><span>{s.patches} patches</span><span>Window: {s.window}</span><span>Env: {s.env}</span></div></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Patch Management Metrics</h3>{[{ m: "Mean Time to Patch (Critical)", v: "4.2h", t: "-1.8h" }, { m: "Deployment Success Rate", v: "99.2%", t: "+0.3%" }, { m: "Rollback Rate", v: "0.8%", t: "-0.2%" }, { m: "Compliance Coverage", v: "96%", t: "+3%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
