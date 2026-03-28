import { useState } from "react";
import { Rss, Shield, Activity, BarChart3, CheckCircle, AlertTriangle } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "feeds" | "iocs" | "metrics";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "feeds", label: "Feeds" }, { id: "iocs", label: "IOCs" }, { id: "metrics", label: "Metrics" }];
export default function ThreatFeedManager() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Threat Feed Manager" subtitle="Aggregate, normalize, and score threat intelligence feeds" icon={<Rss className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Active Feeds" value="12" icon={<Rss className="h-5 w-5" />} />
      <MetricCard title="Total IOCs" value="48.2K" icon={<Shield className="h-5 w-5 text-cyan-400" />} />
      <MetricCard title="Feed Health" value="91%" icon={<Activity className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Dedup Rate" value="34%" icon={<BarChart3 className="h-5 w-5 text-yellow-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Feed Sources by Type</h3><div className="grid grid-cols-2 md:grid-cols-3 gap-3">
      {[{ type: "STIX/TAXII", count: 3, iocs: "12.4K", color: "text-cyan-400" }, { type: "MISP", count: 2, iocs: "8.1K", color: "text-cyan-400" }, { type: "Commercial", count: 2, iocs: "15.6K", color: "text-emerald-400" }, { type: "OSINT", count: 3, iocs: "9.3K", color: "text-yellow-400" }, { type: "ISAC", count: 1, iocs: "2.1K", color: "text-white/60" }, { type: "Custom", count: 1, iocs: "0.7K", color: "text-white/60" }].map((f) => (
        <div key={f.type} className="card-interactive p-3 text-center"><p className="text-xs text-white/60">{f.type}</p><p className={clsx("text-xl font-bold mt-1", f.color)}>{f.count}</p><p className="text-xs text-white/30">{f.iocs} IOCs</p></div>))}</div></div>)}
    {tab === "feeds" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Feed</th><th className="px-4 py-3">Type</th><th className="px-4 py-3">Health</th><th className="px-4 py-3">IOCs</th><th className="px-4 py-3">Score</th></tr></thead>
      <tbody>{[
        { name: "AlienVault OTX", type: "osint", health: "healthy", iocs: "9.3K", score: "0.87" },
        { name: "MISP Community", type: "misp", health: "healthy", iocs: "5.2K", score: "0.82" },
        { name: "TAXII Server", type: "stix_taxii", health: "degraded", iocs: "12.4K", score: "0.71" },
        { name: "Recorded Future", type: "commercial", health: "healthy", iocs: "15.6K", score: "0.93" },
        { name: "FS-ISAC", type: "isac", health: "stale", iocs: "2.1K", score: "0.54" },
      ].map((f, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90 font-medium">{f.name}</td><td className="px-4 py-3"><StatusBadge status={f.type} /></td><td className="px-4 py-3"><StatusBadge status={f.health} /></td><td className="px-4 py-3 text-white/80">{f.iocs}</td><td className="px-4 py-3 text-cyan-400 font-mono">{f.score}</td></tr>))}</tbody></table></div>)}
    {tab === "iocs" && (<div className="space-y-3">
      {[{ value: "185.220.101.45", type: "ip", severity: "critical", source: "AlienVault OTX", tags: "c2, cobalt-strike", confidence: "0.95" },
        { value: "evil-domain.xyz", type: "domain", severity: "high", source: "MISP Community", tags: "phishing, credential-harvest", confidence: "0.88" },
        { value: "d41d8cd98f00b204e9800998ecf8427e", type: "hash", severity: "high", source: "Recorded Future", tags: "ransomware, lockbit", confidence: "0.91" },
        { value: "CVE-2024-3400", type: "cve", severity: "critical", source: "TAXII Server", tags: "palo-alto, rce", confidence: "0.99" },
      ].map((ioc) => (<div key={ioc.value} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-sm text-cyan-400">{ioc.value}</span><span className="text-xs text-white/40 ml-2">{ioc.type}</span></div><StatusBadge status={ioc.severity} /></div>
        <p className="text-xs text-white/50">Source: {ioc.source} | Tags: {ioc.tags} | Confidence: {ioc.confidence}</p></div>))}</div>)}
    {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Feed Management Metrics</h3>
      {[{ metric: "Feed Ingestion Rate", value: "48.2K/day", trend: "+12% vs last week" },
        { metric: "Deduplication Rate", value: "34%", trend: "Avg duplicates removed per cycle" },
        { metric: "Mean Feed Latency", value: "2.3 sec", trend: "Poll-to-normalize pipeline" },
        { metric: "IOC Enrichment Coverage", value: "89%", trend: "IOCs with threat context" },
      ].map((m, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{m.metric}</p><p className="text-xs text-white/50">{m.trend}</p></div><span className="text-cyan-400 font-mono">{m.value}</span></div>))}</div>)}
  </div>);
}
