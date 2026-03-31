import { useState } from "react";
import { Database, Layers, Activity, Shield, BarChart3, Search } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "data_domains" | "data_products" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "data_domains", label: "Data Domains" },
  { id: "data_products", label: "Data Products" },
  { id: "metrics", label: "Metrics" },
];

const DOMAINS = [
  { id: "SD-001", name: "Threat Intelligence", owner: "threat-intel-team", status: "active", products: 8, freshness: "2m" },
  { id: "SD-002", name: "Vulnerability Management", owner: "vuln-team", status: "active", products: 6, freshness: "5m" },
  { id: "SD-003", name: "Identity & Access", owner: "iam-team", status: "active", products: 5, freshness: "3m" },
  { id: "SD-004", name: "Endpoint Telemetry", owner: "edr-team", status: "degraded", products: 7, freshness: "45m" },
  { id: "SD-005", name: "Cloud Security", owner: "cloud-sec-team", status: "active", products: 9, freshness: "4m" },
  { id: "SD-006", name: "Compliance Evidence", owner: "grc-team", status: "active", products: 4, freshness: "10m" },
];

export default function SecurityDataMesh() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Security Data Mesh" subtitle="Federated security analytics across data domains" icon={<Database className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Data Domains" value="6" icon={<Layers className="h-5 w-5" />} />
        <MetricCard title="Data Products" value="39" icon={<Database className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Quality Score" value="87%" icon={<BarChart3 className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Cross-Domain Insights" value="14" icon={<Search className="h-5 w-5 text-yellow-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Mesh Health</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Active Domains", v: "5", c: "text-emerald-400" }, { l: "Degraded", v: "1", c: "text-yellow-400" }, { l: "SLA Breaches", v: "2", c: "text-red-400" }, { l: "Avg Freshness", v: "11m", c: "text-cyan-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "data_domains" && (<div className="space-y-3">{DOMAINS.map((d) => (<div key={d.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{d.id}</span><span className="ml-2 text-white/90 font-medium">{d.name}</span></div><StatusBadge status={d.status === "degraded" ? "warning" : "active"} /></div><div className="flex gap-4 text-sm text-white/60"><span>Owner: {d.owner}</span><span>Products: {d.products}</span><span>Freshness: {d.freshness}</span></div></div>))}</div>)}
      {tab === "data_products" && (<div className="card-surface p-6"><h3 className="section-heading">Product Catalog</h3><p className="text-white/60">39 data products across 6 security domains with schema versioning, quality scoring, and consumer tracking.</p><div className="mt-4 grid grid-cols-1 md:grid-cols-3 gap-4">{[{ l: "Excellent Quality", v: "22", c: "text-emerald-400" }, { l: "Good Quality", v: "12", c: "text-cyan-400" }, { l: "Needs Attention", v: "5", c: "text-yellow-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Mesh Performance</h3>{[{ m: "Federated Query Latency", v: "340ms", t: "-120ms" }, { m: "Cross-Domain Coverage", v: "94%", t: "+3%" }, { m: "Data Freshness SLA", v: "96%", t: "+1%" }, { m: "Product Quality Avg", v: "87%", t: "+2%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
