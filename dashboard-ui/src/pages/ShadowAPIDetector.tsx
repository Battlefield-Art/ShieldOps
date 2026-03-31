import { useState } from "react";
import { Globe, Shield, AlertTriangle, Activity, Eye, FileText } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "api_inventory" | "shadow_apis" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "api_inventory", label: "API Inventory" },
  { id: "shadow_apis", label: "Shadow APIs" },
  { id: "metrics", label: "Metrics" },
];

const SHADOW_APIS = [
  { id: "SA-001", method: "POST", path: "/api/v1/users/export", host: "api.internal.corp", risk: "critical", detail: "Unauthenticated bulk user export — PII exposure risk" },
  { id: "SA-002", method: "GET", path: "/debug/vars", host: "api.internal.corp", risk: "high", detail: "Debug endpoint exposed, leaking runtime variables" },
  { id: "SA-003", method: "GET", path: "/api/v2/admin/config", host: "api.internal.corp", risk: "critical", detail: "Admin config endpoint without authentication" },
  { id: "SA-004", method: "DELETE", path: "/api/old/cleanup", host: "api.internal.corp", risk: "medium", detail: "Deprecated cleanup endpoint still active, no auth" },
  { id: "SA-005", method: "GET", path: "/api/internal/metrics", host: "api.internal.corp", risk: "high", detail: "Internal metrics exposed without access control" },
];

export default function ShadowAPIDetector() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Shadow API Detector" subtitle="Discover undocumented and shadow APIs across your infrastructure" icon={<Globe className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Endpoints Scanned" value="1,247" icon={<Activity className="h-5 w-5" />} />
        <MetricCard title="Shadow APIs Found" value="23" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Auto-Documented" value="18" icon={<FileText className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Risk Score" value="72/100" icon={<Shield className="h-5 w-5 text-yellow-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">API Surface Health</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Documented", v: "1,224", c: "text-emerald-400" }, { l: "Shadow", v: "15", c: "text-red-400" }, { l: "Deprecated", v: "5", c: "text-yellow-400" }, { l: "Internal Exposed", v: "3", c: "text-orange-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "api_inventory" && (<div className="card-surface p-6"><h3 className="section-heading">Endpoint Inventory</h3><p className="text-white/60">Full API inventory with documentation status, authentication requirements, and traffic patterns across 1,247 discovered endpoints.</p><div className="mt-4 grid grid-cols-1 md:grid-cols-3 gap-4">{[{ l: "Authenticated", v: "89%", c: "text-emerald-400" }, { l: "Rate-Limited", v: "76%", c: "text-cyan-400" }, { l: "Versioned", v: "92%", c: "text-blue-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "shadow_apis" && (<div className="space-y-3">{SHADOW_APIS.map((a) => (<div key={a.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{a.id}</span><span className="ml-2 text-white/90 font-medium">{a.method} {a.path}</span></div><StatusBadge status={a.risk} /></div><p className="text-white/70 text-sm font-mono">{a.host}</p><p className="text-white/50 text-xs mt-1">{a.detail}</p></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Detection Trends</h3>{[{ m: "Discovery Rate", v: "99.2%", t: "+0.5%" }, { m: "False Positive Rate", v: "1.8%", t: "-0.4%" }, { m: "Auto-Doc Coverage", v: "78%", t: "+5%" }, { m: "Avg Scan Time", v: "4.2s", t: "-0.8s" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
