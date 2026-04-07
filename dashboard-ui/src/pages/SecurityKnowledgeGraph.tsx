import { useState } from "react";
import { GitBranch, AlertTriangle, Target, Layers } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "entity_map" | "attack_paths" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "entity_map", label: "Entity Map" },
  { id: "attack_paths", label: "Attack Paths" },
  { id: "metrics", label: "Metrics" },
];

const PATHS = [
  { id: "AP-001", from: "APT-29", to: "web-server-01", risk: 0.92, impact: "critical", detail: "Nation-state actor to public-facing web server via CVE-2026-1234" },
  { id: "AP-002", from: "CVE-2026-5678", to: "db-primary", risk: 0.87, impact: "critical", detail: "SQL injection chain to PII database through internal subnet" },
  { id: "AP-003", from: "svc-account-deploy", to: "db-primary", risk: 0.75, impact: "high", detail: "Over-privileged service account with lateral movement to database" },
  { id: "AP-004", from: "APT-29", to: "svc-account-deploy", risk: 0.68, impact: "high", detail: "Credential compromise path via CI/CD pipeline exposure" },
];

export default function SecurityKnowledgeGraph() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Security Knowledge Graph" subtitle="Entity-relationship mapping for attack path discovery and threat intelligence" icon={<GitBranch className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Total Entities" value="2,847" icon={<Layers className="h-5 w-5" />} />
        <MetricCard title="Relationships" value="12,340" icon={<GitBranch className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Attack Paths" value="47" icon={<Target className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Risk Patterns" value="12" icon={<AlertTriangle className="h-5 w-5 text-amber-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Graph Summary</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Assets", v: "1,240", c: "text-cyan-400" }, { l: "Vulnerabilities", v: "389", c: "text-red-400" }, { l: "Threats", v: "67", c: "text-amber-400" }, { l: "Controls", v: "1,151", c: "text-emerald-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "entity_map" && (<div className="card-surface p-6"><h3 className="section-heading">Entity Relationship Map</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">{[{ type: "Identity", count: 342, risk: "medium" }, { type: "Network", count: 156, risk: "high" }, { type: "Asset", count: 1240, risk: "low" }].map((e) => (<div key={e.type} className="card-interactive p-4"><div className="flex items-center justify-between"><span className="text-white/90 font-medium">{e.type}</span><StatusBadge status={e.risk} /></div><p className="text-2xl font-bold text-cyan-400 mt-2">{e.count}</p></div>))}</div></div>)}
      {tab === "attack_paths" && (<div className="space-y-3">{PATHS.map((p) => (<div key={p.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{p.id}</span><span className="ml-2 text-white/90 font-medium">{p.from} → {p.to}</span></div><StatusBadge status={p.impact} /></div><p className="text-white/50 text-xs">{p.detail}</p><div className="mt-2 flex items-center gap-2"><span className="text-xs text-white/40">Risk:</span><div className="flex-1 h-1.5 bg-white/10 rounded-full"><div className="h-1.5 bg-red-400 rounded-full" style={{ width: `${p.risk * 100}%` }} /></div><span className="text-xs font-mono text-white/60">{(p.risk * 100).toFixed(0)}%</span></div></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Graph Analytics</h3>{[{ m: "Graph Density", v: "0.34", t: "+0.02" }, { m: "Avg Path Length", v: "3.2", t: "-0.1" }, { m: "Critical Clusters", v: "5", t: "+1" }, { m: "Coverage", v: "94%", t: "+3%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
