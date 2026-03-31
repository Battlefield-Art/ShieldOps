import { useState } from "react";
import { Database, Shield, AlertTriangle, Lock, Eye, FileCheck } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "data_catalog" | "access_violations" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "data_catalog", label: "Data Catalog" },
  { id: "access_violations", label: "Access Violations" },
  { id: "metrics", label: "Metrics" },
];

const CATALOG_ITEMS = [
  { id: "DC-001", name: "Customer PII Store", classification: "Confidential", owner: "data-eng", access_count: 142, status: "protected" },
  { id: "DC-002", name: "Financial Transactions DB", classification: "Restricted", owner: "finance-team", access_count: 89, status: "protected" },
  { id: "DC-003", name: "ML Training Dataset", classification: "Internal", owner: "ml-platform", access_count: 312, status: "review" },
  { id: "DC-004", name: "Audit Log Archive", classification: "Confidential", owner: "security-ops", access_count: 27, status: "protected" },
];

const VIOLATIONS = [
  { id: "AV-001", catalog: "DC-001", actor: "svc-analytics", action: "bulk_export", severity: "critical", time: "12m ago" },
  { id: "AV-002", catalog: "DC-003", actor: "dev-user-47", action: "schema_modify", severity: "high", time: "1h ago" },
  { id: "AV-003", catalog: "DC-002", actor: "svc-reporting", action: "unmasked_read", severity: "medium", time: "3h ago" },
];

export default function DataCatalogProtector() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Data Catalog Protector" subtitle="Secure data catalogs with classification-aware access controls" icon={<Database className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Catalogs Protected" value="18" icon={<Shield className="h-5 w-5" />} />
        <MetricCard title="Access Violations (24h)" value="7" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Classified Assets" value="2,341" icon={<Lock className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Policy Coverage" value="94%" icon={<FileCheck className="h-5 w-5 text-emerald-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Classification Distribution</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Restricted", v: "312", c: "text-red-400" }, { l: "Confidential", v: "891", c: "text-yellow-400" }, { l: "Internal", v: "1,024", c: "text-cyan-400" }, { l: "Public", v: "114", c: "text-white/70" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "data_catalog" && (<div className="space-y-3">{CATALOG_ITEMS.map((c) => (<div key={c.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{c.id}</span><span className="ml-2 text-xs text-white/40">{c.classification}</span></div><StatusBadge status={c.status} /></div><p className="text-white/90 text-sm font-medium">{c.name}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>Owner: {c.owner}</span><span>{c.access_count} accesses/day</span></div></div>))}</div>)}
      {tab === "access_violations" && (<div className="space-y-3">{VIOLATIONS.map((v) => (<div key={v.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{v.id}</span><span className="ml-2 text-xs text-white/40">{v.catalog}</span></div><StatusBadge status={v.severity} /></div><p className="text-white/90 text-sm"><Eye className="inline h-3 w-3 mr-1" />{v.actor} performed <span className="text-yellow-400">{v.action}</span></p><span className="text-xs text-white/40">{v.time}</span></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Catalog Protection Metrics</h3>{[{ m: "Policy Compliance Rate", v: "94%", t: "+2%" }, { m: "Avg Detection Latency", v: "1.8s", t: "-0.4s" }, { m: "False Positive Rate", v: "3.1%", t: "-0.7%" }, { m: "Assets Auto-Classified", v: "87%", t: "+5%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
