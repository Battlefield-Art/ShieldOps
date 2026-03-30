import { useState } from "react";
import { Database, Shield, AlertTriangle, Activity, Lock, Zap } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "pipelines" | "threats" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "pipelines", label: "Pipelines" },
  { id: "threats", label: "Threats" },
  { id: "metrics", label: "Metrics" },
];

const PIPELINES = [
  { name: "prod-etl-main", type: "ETL", sources: 4, status: "healthy", lastScan: "5m ago" },
  { name: "ml-training-pipeline", type: "ML Dataset", sources: 3, status: "warning", lastScan: "12m ago" },
  { name: "kafka-stream-ingest", type: "Streaming", sources: 8, status: "healthy", lastScan: "2m ago" },
  { name: "s3-data-lake-loader", type: "Cloud Storage", sources: 6, status: "healthy", lastScan: "8m ago" },
  { name: "legacy-batch-import", type: "Database", sources: 2, status: "critical", lastScan: "1h ago" },
];

const THREATS = [
  { id: "DP-001", pipeline: "legacy-batch-import", type: "SQL Injection", severity: "critical", detail: "Unparameterized query in ETL transform stage" },
  { id: "DP-002", pipeline: "ml-training-pipeline", type: "Data Poisoning", severity: "high", detail: "Anomalous distribution shift in training labels (12% deviation)" },
  { id: "DP-003", pipeline: "kafka-stream-ingest", type: "Schema Drift", severity: "medium", detail: "3 new fields detected in event payload, not in schema registry" },
  { id: "DP-004", pipeline: "s3-data-lake-loader", type: "Unauthorized Access", severity: "medium", detail: "IAM role with broader permissions than needed" },
];

export default function DataPipelineProtector() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Data Pipeline Protector" subtitle="Protect ETL, streaming, and ML pipelines from injection and poisoning" icon={<Database className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Pipelines" value="23" icon={<Activity className="h-5 w-5" />} />
        <MetricCard title="Protected" value="21" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Threats (24h)" value="7" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Schema Compliance" value="94%" icon={<Lock className="h-5 w-5 text-cyan-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Pipeline Health</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Healthy", v: "18", c: "text-emerald-400" }, { l: "Warning", v: "3", c: "text-yellow-400" }, { l: "Critical", v: "2", c: "text-red-400" }, { l: "Data Volume", v: "4.2 TB/day", c: "text-cyan-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "pipelines" && (<div className="space-y-3">{PIPELINES.map((p) => (<div key={p.name} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><span className="text-white/90 font-medium">{p.name}</span><StatusBadge status={p.status} /></div><div className="flex gap-4 text-sm text-white/50"><span>{p.type}</span><span>{p.sources} sources</span><span>Last scan: {p.lastScan}</span></div></div>))}</div>)}
      {tab === "threats" && (<div className="space-y-3">{THREATS.map((t) => (<div key={t.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{t.id}</span><span className="ml-2 text-white/90 font-medium">{t.pipeline}</span></div><StatusBadge status={t.severity} /></div><p className="text-white/70 text-sm">{t.type}: {t.detail}</p></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Protection Trends</h3>{[{ m: "Threats Blocked", v: "147", t: "+23 this week" }, { m: "Schema Violations", v: "12", t: "-5" }, { m: "Scan Coverage", v: "94%", t: "+3%" }, { m: "Avg Scan Time", v: "2.3s", t: "-0.4s" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
