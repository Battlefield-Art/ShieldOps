import { useState } from "react";
import { FileCode, Shield, AlertTriangle, Wrench } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "schema_inventory" | "breaking_changes" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "schema_inventory", label: "Schema Inventory" },
  { id: "breaking_changes", label: "Breaking Changes" },
  { id: "metrics", label: "Metrics" },
];

const SCHEMAS = [
  { name: "user-service", version: "3.1.0", format: "OpenAPI 3.1", endpoints: 42, status: "healthy", detail: "All contracts valid, no breaking changes" },
  { name: "payment-api", version: "2.4.1", format: "OpenAPI 3.0", endpoints: 18, status: "warning", detail: "2 contract violations detected in POST /charges" },
  { name: "notification-svc", version: "1.8.0", format: "OpenAPI 3.0", endpoints: 12, status: "critical", detail: "Breaking change: removed field in /templates response" },
  { name: "analytics-engine", version: "4.0.0", format: "GraphQL", endpoints: 8, status: "healthy", detail: "Schema fully validated, 0 drift" },
  { name: "auth-gateway", version: "2.1.3", format: "OpenAPI 3.1", endpoints: 24, status: "warning", detail: "Undocumented endpoint /internal/refresh detected" },
];

export default function APISchemaValidator() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="API Schema Validator" subtitle="API schema validation, contract testing, and breaking change detection" icon={<FileCode className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Schemas Tracked" value="156" icon={<FileCode className="h-5 w-5" />} />
        <MetricCard title="Contract Violations" value="14" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Breaking Changes" value="3" icon={<Shield className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Auto-Fixed" value="8" icon={<Wrench className="h-5 w-5 text-emerald-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Validation Summary</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Valid", v: "139", c: "text-emerald-400" }, { l: "Warnings", v: "12", c: "text-yellow-400" }, { l: "Violations", v: "14", c: "text-orange-400" }, { l: "Breaking", v: "3", c: "text-red-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "schema_inventory" && (<div className="space-y-3">{SCHEMAS.map((s) => (<div key={s.name} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="text-white/90 font-medium font-mono text-sm">{s.name}</span><span className="ml-2 text-xs text-white/40">{s.format} v{s.version}</span></div><StatusBadge status={s.status} /></div><p className="text-white/50 text-sm">{s.detail}</p><span className="text-xs text-white/40">{s.endpoints} endpoints</span></div>))}</div>)}
      {tab === "breaking_changes" && (<div className="card-surface p-6"><h3 className="section-heading">Detected Breaking Changes</h3><div className="space-y-2">{[{ change: "notification-svc: removed 'template_id' from GET /templates response", severity: "critical", consumers: 7 }, { change: "payment-api: changed 'amount' type from string to number in POST /charges", severity: "high", consumers: 4 }, { change: "auth-gateway: added required field 'mfa_token' to POST /login", severity: "high", consumers: 12 }].map((c, i) => (<div key={i} className="card-interactive p-3 flex items-center justify-between text-sm"><span className="text-white/70 flex-1">{c.change}</span><div className="flex gap-3 items-center"><span className="text-white/40">{c.consumers} consumers</span><StatusBadge status={c.severity} /></div></div>))}</div></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Validation Trends</h3>{[{ m: "Schema Coverage", v: "94.2%", t: "+1.8% this week" }, { m: "Avg Validation Time", v: "340ms", t: "-50ms" }, { m: "Breaking Changes / Month", v: "3.2", t: "-1.1" }, { m: "Auto-Fix Success Rate", v: "82%", t: "+4%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
