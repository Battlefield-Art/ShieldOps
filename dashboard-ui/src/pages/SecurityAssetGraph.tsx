import { useState } from "react";
import { Network, Search, Shield, AlertTriangle, GitBranch, BarChart3 } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "asset_graph" | "critical_paths" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "asset_graph", label: "Asset Graph" },
  { id: "critical_paths", label: "Critical Paths" },
  { id: "metrics", label: "Metrics" },
];

const ASSETS = [
  { id: "AST-001", name: "prod-api-gateway", type: "Application", deps: 14, criticality: "critical", risk: 8.2 },
  { id: "AST-002", name: "primary-db-cluster", type: "Database", deps: 9, criticality: "critical", risk: 7.8 },
  { id: "AST-003", name: "auth-service", type: "Application", deps: 22, criticality: "high", risk: 6.5 },
  { id: "AST-004", name: "cdn-edge-nodes", type: "Network", deps: 5, criticality: "medium", risk: 3.1 },
];

const PATHS = [
  { id: "CP-001", nodes: "api-gw -> auth -> db-primary -> cache", spof: "db-primary", redundancy: 0.2, risk: "critical" },
  { id: "CP-002", nodes: "lb -> api -> queue -> worker", spof: "queue", redundancy: 0.4, risk: "high" },
  { id: "CP-003", nodes: "dns -> cdn -> origin -> storage", spof: "none", redundancy: 0.8, risk: "low" },
];

export default function SecurityAssetGraph() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Security Asset Graph" subtitle="Asset dependency mapping and blast radius analysis" icon={<Network className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Total Assets" value="347" icon={<Search className="h-5 w-5" />} />
        <MetricCard title="Dependencies" value="1,204" icon={<GitBranch className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Critical Paths" value="12" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Risk Score" value="6.4" icon={<Shield className="h-5 w-5 text-red-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Asset Distribution</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Applications", v: "142", c: "text-cyan-400" }, { l: "Databases", v: "38", c: "text-emerald-400" }, { l: "Network", v: "89", c: "text-yellow-400" }, { l: "Identity", v: "78", c: "text-white/70" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "asset_graph" && (<div className="space-y-3">{ASSETS.map((a) => (<div key={a.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{a.id}</span><span className="ml-2 text-xs text-white/40">{a.type}</span></div><StatusBadge status={a.criticality} /></div><p className="text-white/90 text-sm font-mono">{a.name}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>{a.deps} dependencies</span><span className={a.risk > 7 ? "text-red-400" : "text-yellow-400"}>Risk: {a.risk}</span></div></div>))}</div>)}
      {tab === "critical_paths" && (<div className="space-y-3">{PATHS.map((p) => (<div key={p.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><span className="font-mono text-xs text-cyan-400">{p.id}</span><StatusBadge status={p.risk} /></div><p className="text-white/90 text-sm font-mono mb-1">{p.nodes}</p><div className="flex gap-4 text-xs text-white/50"><span>SPOF: <span className={p.spof !== "none" ? "text-red-400" : "text-emerald-400"}>{p.spof}</span></span><span>Redundancy: {(p.redundancy * 100).toFixed(0)}%</span></div></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Graph Analytics</h3>{[{ m: "Avg Dependencies/Asset", v: "3.5", t: "+0.4" }, { m: "Single Points of Failure", v: "8", t: "-2" }, { m: "Redundancy Score", v: "62%", t: "+5%" }, { m: "Blast Radius (avg)", v: "14 assets", t: "-3" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
