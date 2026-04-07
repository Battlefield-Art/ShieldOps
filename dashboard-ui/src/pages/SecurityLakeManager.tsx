import { useState } from "react";
import { Database, Activity, ArrowRightLeft, TrendingUp, DollarSign } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "data_sources" | "storage_tiers" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "data_sources", label: "Data Sources" },
  { id: "storage_tiers", label: "Storage Tiers" },
  { id: "metrics", label: "Metrics" },
];

const SOURCES = [
  { id: "SRC-001", name: "CrowdStrike EDR", type: "edr", format: "OCSF", epd: "1.2M", status: "active" },
  { id: "SRC-002", name: "Splunk SIEM", type: "siem", format: "CEF", epd: "4.8M", status: "active" },
  { id: "SRC-003", name: "AWS CloudTrail", type: "cloud", format: "RAW", epd: "890K", status: "active" },
  { id: "SRC-004", name: "Palo Alto FW", type: "network", format: "LEEF", epd: "2.1M", status: "degraded" },
];

const TIERS = [
  { tier: "Hot", volume: "2.4 TB", cost: "$1,200/day", retention: "30 days", pct: 15 },
  { tier: "Warm", volume: "12.8 TB", cost: "$640/day", retention: "90 days", pct: 35 },
  { tier: "Cold", volume: "48.2 TB", cost: "$120/day", retention: "1 year", pct: 40 },
  { tier: "Archive", volume: "124 TB", cost: "$24/day", retention: "7 years", pct: 10 },
];

export default function SecurityLakeManager() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Security Lake Manager" subtitle="Security data lake management and optimization" icon={<Database className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Data Sources" value="17" icon={<Activity className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Daily Volume" value="8.9M events" icon={<ArrowRightLeft className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Storage Cost" value="$1,984/day" icon={<DollarSign className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Cost Savings" value="32%" icon={<TrendingUp className="h-5 w-5 text-emerald-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Schema Normalization</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "OCSF", v: "8", c: "text-cyan-400" }, { l: "ECS", v: "4", c: "text-emerald-400" }, { l: "CEF", v: "3", c: "text-yellow-400" }, { l: "RAW", v: "2", c: "text-white/70" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "data_sources" && (<div className="space-y-3">{SOURCES.map((s) => (<div key={s.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{s.id}</span><span className="ml-2 text-xs text-white/40">{s.type}</span></div><StatusBadge status={s.status} /></div><p className="text-white/90 text-sm font-medium">{s.name}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>Format: {s.format}</span><span>{s.epd} events/day</span></div></div>))}</div>)}
      {tab === "storage_tiers" && (<div className="space-y-3">{TIERS.map((t) => (<div key={t.tier} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><span className="text-white/90 font-medium">{t.tier}</span><span className="text-xs text-white/40">{t.pct}% of data</span></div><div className="flex gap-4 mt-2 text-xs text-white/50"><span>Volume: {t.volume}</span><span>Cost: {t.cost}</span><span>Retention: {t.retention}</span></div></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Lake Performance</h3>{[{ m: "Ingestion Latency", v: "120ms", t: "-15ms" }, { m: "Normalization Rate", v: "94.2%", t: "+1.8%" }, { m: "Query P95", v: "3.2s", t: "-0.4s" }, { m: "Monthly Savings", v: "$18,400", t: "+$2,100" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
