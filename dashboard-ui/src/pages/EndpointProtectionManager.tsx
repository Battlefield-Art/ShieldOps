import { useState } from "react";
import { Monitor, Shield, AlertTriangle, RefreshCw } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "endpoints" | "patches" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "endpoints", label: "Endpoints" },
  { id: "patches", label: "Patches" },
  { id: "metrics", label: "Metrics" },
];

const ENDPOINTS = [
  { name: "prod-web-01", os: "Linux", status: "protected", agent: "v4.2.1", patches: "Up to date" },
  { name: "dev-workstation-12", os: "macOS", status: "protected", agent: "v4.2.1", patches: "1 pending" },
  { name: "win-dc-01", os: "Windows", status: "partially_protected", agent: "v4.1.0 (outdated)", patches: "5 critical pending" },
  { name: "k8s-node-03", os: "Container", status: "protected", agent: "v4.2.1", patches: "Up to date" },
  { name: "legacy-server-07", os: "Windows", status: "unprotected", agent: "Not installed", patches: "12 critical" },
];

export default function EndpointProtectionManager() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Endpoint Protection Manager" subtitle="Endpoint security monitoring and patch management" icon={<Monitor className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Endpoints" value="2,847" icon={<Monitor className="h-5 w-5" />} />
        <MetricCard title="Protected" value="2,791" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Unprotected" value="12" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Patch Compliance" value="94.7%" icon={<RefreshCw className="h-5 w-5 text-cyan-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Protection Status</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Protected", v: "2,791", c: "text-emerald-400" }, { l: "Partial", v: "44", c: "text-yellow-400" }, { l: "Unprotected", v: "12", c: "text-red-400" }, { l: "Offline", v: "8", c: "text-white/40" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "endpoints" && (<div className="space-y-3">{ENDPOINTS.map((e) => (<div key={e.name} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><span className="text-white/90 font-medium">{e.name}</span><StatusBadge status={e.status} /></div><div className="flex gap-4 text-sm text-white/50"><span>{e.os}</span><span>Agent: {e.agent}</span><span>{e.patches}</span></div></div>))}</div>)}
      {tab === "patches" && (<div className="card-surface p-6"><h3 className="section-heading">Patch Queue</h3><p className="text-white/60">147 patches pending across 56 endpoints.</p></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Protection Trends</h3>{[{ m: "Coverage", v: "98.0%", t: "+0.5%" }, { m: "Patch Compliance", v: "94.7%", t: "+2.3%" }, { m: "Agent Health", v: "99.1%", t: "+0.2%" }, { m: "Threats Blocked (7d)", v: "47", t: "+8" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
