import { useState } from "react";
import { Database, Shield, AlertTriangle, Lock } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "findings" | "databases" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "findings", label: "Findings" },
  { id: "databases", label: "Databases" },
  { id: "metrics", label: "Metrics" },
];

const FINDINGS = [
  { id: "DB-001", db: "prod-postgres-main", engine: "PostgreSQL", severity: "critical", issue: "Public network access enabled, no VPC restriction" },
  { id: "DB-002", db: "analytics-mongo", engine: "MongoDB", severity: "high", issue: "Authentication disabled, anonymous access allowed" },
  { id: "DB-003", db: "cache-redis-01", engine: "Redis", severity: "high", issue: "No TLS encryption, password authentication only" },
  { id: "DB-004", db: "search-elastic", engine: "Elasticsearch", severity: "medium", issue: "Default admin credentials not rotated" },
  { id: "DB-005", db: "staging-mysql", engine: "MySQL", severity: "medium", issue: "SSL mode set to PREFERRED instead of REQUIRED" },
];

export default function DatabaseSecurityScanner() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Database Security Scanner" subtitle="Scan databases for misconfigurations and vulnerabilities" icon={<Database className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Databases Scanned" value="47" icon={<Database className="h-5 w-5" />} />
        <MetricCard title="Findings" value="23" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Encrypted" value="89%" icon={<Lock className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Score" value="B+" icon={<Shield className="h-5 w-5 text-cyan-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Security Posture</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Secure", v: "24", c: "text-emerald-400" }, { l: "Needs Attention", v: "15", c: "text-yellow-400" }, { l: "Critical", v: "5", c: "text-red-400" }, { l: "Not Scanned", v: "3", c: "text-white/40" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "findings" && (<div className="space-y-3">{FINDINGS.map((f) => (<div key={f.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{f.id}</span><span className="ml-2 text-white/90 font-medium">{f.db}</span><span className="ml-2 text-xs text-white/40">{f.engine}</span></div><StatusBadge status={f.severity} /></div><p className="text-white/70 text-sm">{f.issue}</p></div>))}</div>)}
      {tab === "databases" && (<div className="card-surface p-6"><p className="text-white/60">Database inventory across PostgreSQL, MySQL, MongoDB, Redis, Elasticsearch, and DynamoDB.</p></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Security Trends</h3>{[{ m: "Overall Score", v: "B+", t: "Up from B-" }, { m: "Critical Findings", v: "5", t: "-3 vs last scan" }, { m: "Encryption Coverage", v: "89%", t: "+7%" }, { m: "Avg Fix Time", v: "1.8 days", t: "-0.4 days" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
