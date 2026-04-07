import { useState } from "react";
import { Radio, Shield, Filter, Zap, RefreshCw } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "feed_status" | "indicator_pipeline" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "feed_status", label: "Feed Status" },
  { id: "indicator_pipeline", label: "Indicator Pipeline" },
  { id: "metrics", label: "Metrics" },
];

const FEEDS = [
  { id: "FEED-001", name: "AlienVault OTX", format: "STIX 2.1", status: "active", indicators: 12450, lastPoll: "2 min ago" },
  { id: "FEED-002", name: "MISP Community", format: "MISP", status: "active", indicators: 8920, lastPoll: "5 min ago" },
  { id: "FEED-003", name: "Abuse.ch URLhaus", format: "CSV", status: "active", indicators: 34200, lastPoll: "1 min ago" },
  { id: "FEED-004", name: "Internal TI Team", format: "STIX 2.1", status: "degraded", indicators: 1240, lastPoll: "15 min ago" },
];

const PIPELINE_STAGES = [
  { stage: "Ingested", count: 56810, color: "text-white/70" },
  { stage: "Normalized", count: 54320, color: "text-cyan-400" },
  { stage: "Deduplicated", count: 31450, color: "text-yellow-400" },
  { stage: "Enriched", count: 28900, color: "text-emerald-400" },
  { stage: "Distributed", count: 28900, color: "text-cyan-400" },
];

export default function ThreatFeedOrchestrator() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Threat Feed Orchestrator" subtitle="Multi-source threat intelligence feed management" icon={<Radio className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Active Feeds" value="4" icon={<Radio className="h-5 w-5" />} />
        <MetricCard title="Unique IOCs" value="31.4K" icon={<Shield className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Dedup Ratio" value="44.6%" icon={<Filter className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Consumers" value="7" icon={<Zap className="h-5 w-5 text-emerald-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Pipeline Funnel</h3><div className="space-y-3">{PIPELINE_STAGES.map((s) => (<div key={s.stage} className="card-interactive p-4 flex items-center justify-between"><span className="text-white/90 font-medium">{s.stage}</span><span className={clsx("font-mono", s.color)}>{s.count.toLocaleString()}</span></div>))}</div></div>)}
      {tab === "feed_status" && (<div className="space-y-3">{FEEDS.map((f) => (<div key={f.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{f.id}</span><span className="ml-2 text-xs text-white/40">{f.format}</span></div><StatusBadge status={f.status} /></div><p className="text-white/90 text-sm font-medium">{f.name}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>{f.indicators.toLocaleString()} indicators</span><span><RefreshCw className="inline h-3 w-3 mr-1" />{f.lastPoll}</span></div></div>))}</div>)}
      {tab === "indicator_pipeline" && (<div className="card-surface p-6"><h3 className="section-heading">IOC Type Distribution</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">{[{ l: "IP Addresses", v: "12,340", c: "text-red-400" }, { l: "Domains", v: "8,920", c: "text-yellow-400" }, { l: "File Hashes", v: "6,120", c: "text-cyan-400" }, { l: "URLs", v: "3,450", c: "text-emerald-400" }, { l: "CVEs", v: "480", c: "text-white/70" }, { l: "Email", v: "140", c: "text-white/50" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Feed Pipeline Metrics</h3>{[{ m: "Dedup Ratio", v: "44.6%", t: "+2.1%" }, { m: "Avg Enrichment Time", v: "1.8s", t: "-0.4s" }, { m: "Feed Uptime", v: "99.2%", t: "+0.5%" }, { m: "IOCs per Minute", v: "342", t: "+28" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
