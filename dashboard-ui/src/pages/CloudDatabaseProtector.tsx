import { useState } from "react";
import { Database, Lock, Shield, AlertTriangle, Eye, FileText } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "database_inventory" | "access_anomalies" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "database_inventory", label: "Database Inventory" },
  { id: "access_anomalies", label: "Access Anomalies" },
  { id: "metrics", label: "Metrics" },
];

const DATABASES = [
  { id: "DB-001", name: "prod-users-rds", engine: "PostgreSQL", provider: "AWS", encrypted: true, public: false, risk: "low" },
  { id: "DB-002", name: "analytics-bq", engine: "BigQuery", provider: "GCP", encrypted: true, public: false, risk: "medium" },
  { id: "DB-003", name: "legacy-mysql-01", engine: "MySQL", provider: "AWS", encrypted: false, public: true, risk: "critical" },
  { id: "DB-004", name: "cosmos-sessions", engine: "CosmosDB", provider: "Azure", encrypted: true, public: false, risk: "low" },
  { id: "DB-005", name: "cache-redis-prod", engine: "Redis", provider: "AWS", encrypted: false, public: false, risk: "high" },
];

const ANOMALIES = [
  { id: "AN-001", db: "legacy-mysql-01", type: "Bulk data export", user: "app-svc-legacy", risk: "critical", description: "120GB exported to unknown IP at 3AM" },
  { id: "AN-002", db: "prod-users-rds", type: "Privilege escalation", user: "developer-3", risk: "high", description: "ALTER TABLE attempted on production schema" },
  { id: "AN-003", db: "cache-redis-prod", type: "Unencrypted connection", user: "monitoring-svc", risk: "medium", description: "Plaintext Redis protocol from new source" },
];

export default function CloudDatabaseProtector() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Cloud Database Protector" subtitle="Cloud database security, access monitoring, and encryption enforcement" icon={<Database className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Databases" value="48" icon={<Database className="h-5 w-5" />} />
        <MetricCard title="At Risk" value="7" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Anomalies (24h)" value="12" icon={<Eye className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Encrypted" value="85%" icon={<Lock className="h-5 w-5 text-emerald-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Database Security by Provider</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">{[{ l: "AWS", v: "28", r: "4", c: "text-yellow-400" }, { l: "GCP", v: "12", r: "1", c: "text-cyan-400" }, { l: "Azure", v: "8", r: "2", c: "text-emerald-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p><p className="text-xs text-white/40 mt-1">{s.r} at risk</p></div>))}</div></div>)}
      {tab === "database_inventory" && (<div className="space-y-3">{DATABASES.map((d) => (<div key={d.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{d.id}</span><span className="ml-2 text-xs text-white/40">{d.provider} / {d.engine}</span></div><StatusBadge status={d.risk} /></div><p className="text-white/90 text-sm font-mono">{d.name}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span className={d.encrypted ? "text-emerald-400" : "text-red-400"}>{d.encrypted ? "Encrypted" : "Not encrypted"}</span><span className={d.public ? "text-red-400" : "text-emerald-400"}>{d.public ? "Publicly accessible" : "Private"}</span></div></div>))}</div>)}
      {tab === "access_anomalies" && (<div className="space-y-3">{ANOMALIES.map((a) => (<div key={a.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{a.id}</span><span className="ml-2 text-xs text-white/40">{a.db}</span></div><StatusBadge status={a.risk} /></div><p className="text-white/90 text-sm">{a.type}: {a.description}</p><span className="text-xs text-white/50 mt-1">User: {a.user}</span></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Protection Metrics</h3>{[{ m: "Encryption Coverage", v: "85%", t: "+10%" }, { m: "Anomaly Detection Rate", v: "94%", t: "+3%" }, { m: "Policy Compliance", v: "91%", t: "+7%" }, { m: "Avg Remediation Time", v: "2.1h", t: "-0.8h" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
