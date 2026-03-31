import { useState } from "react";
import { Database, Activity, AlertTriangle, CheckCircle, Zap, Shield } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "pipeline_status" | "data_quality" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "pipeline_status", label: "Pipeline Status" },
  { id: "data_quality", label: "Data Quality" },
  { id: "metrics", label: "Metrics" },
];

const PIPELINES = [
  { id: "PL-001", source: "CrowdStrike EDR", status: "active", records: "1.2M", latency: "340ms", enrichment: "94%" },
  { id: "PL-002", source: "Splunk SIEM", status: "active", records: "3.8M", latency: "520ms", enrichment: "91%" },
  { id: "PL-003", source: "AWS CloudTrail", status: "active", records: "8.4M", latency: "180ms", enrichment: "87%" },
  { id: "PL-004", source: "Azure AD Identity", status: "degraded", records: "640K", latency: "1.2s", enrichment: "78%" },
];

export default function SecurityDataPipeline() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Security Data Pipeline" subtitle="Security data ETL, enrichment, and quality validation across all sources" icon={<Database className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Records Processed" value="14.1M" icon={<Activity className="h-5 w-5" />} />
        <MetricCard title="IOC Matches" value="2,847" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Quality Score" value="96.2%" icon={<CheckCircle className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Avg Latency" value="410ms" icon={<Zap className="h-5 w-5 text-cyan-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Pipeline Health</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Active Sources", v: "6", c: "text-emerald-400" }, { l: "OCSF Normalized", v: "99.1%", c: "text-cyan-400" }, { l: "Enrichment Rate", v: "89%", c: "text-yellow-400" }, { l: "Destinations", v: "3", c: "text-blue-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "pipeline_status" && (<div className="space-y-3">{PIPELINES.map((p) => (<div key={p.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{p.id}</span><span className="ml-2 text-white/90 font-medium">{p.source}</span></div><StatusBadge status={p.status} /></div><div className="grid grid-cols-3 gap-2 text-sm"><div><span className="text-white/50">Records:</span> <span className="text-white/80">{p.records}</span></div><div><span className="text-white/50">Latency:</span> <span className="text-white/80">{p.latency}</span></div><div><span className="text-white/50">Enrichment:</span> <span className="text-white/80">{p.enrichment}</span></div></div></div>))}</div>)}
      {tab === "data_quality" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Quality Checks</h3>{[{ n: "Schema Completeness", p: "99.4%", s: "passing" }, { n: "Timestamp Validity", p: "98.9%", s: "passing" }, { n: "Field Type Check", p: "97.1%", s: "passing" }, { n: "Duplicate Detection", p: "0.3% dupes", s: "warning" }].map((q, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{q.n}</p><p className="text-xs text-white/50">{q.p}</p></div><StatusBadge status={q.s} /></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Pipeline Trends</h3>{[{ m: "Throughput", v: "2.3M rec/hr", t: "+12%" }, { m: "IOC Hit Rate", v: "2.01%", t: "+0.3%" }, { m: "Transform Latency", v: "85ms", t: "-15ms" }, { m: "Load Success", v: "99.97%", t: "+0.02%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
