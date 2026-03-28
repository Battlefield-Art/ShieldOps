import { useState } from "react";
import { Crosshair, Activity, ShieldAlert, Clock, AlertTriangle } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "active" | "enrichment" | "aging";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "active", label: "Active IOCs" }, { id: "enrichment", label: "Enrichment" }, { id: "aging", label: "Aging & Expiry" }];
export default function IOCLifecycle() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="IOC Lifecycle" subtitle="Indicator of Compromise management — creation, enrichment, aging, expiry, false-positive tracking" icon={<Crosshair className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Active IOCs" value="1,247" icon={<Activity className="h-5 w-5" />} />
      <MetricCard title="False Positives" value="23" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Enriched Today" value="89" icon={<ShieldAlert className="h-5 w-5 text-cyan-400" />} />
      <MetricCard title="Avg Age" value="34 days" icon={<Clock className="h-5 w-5 text-cyan-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">IOCs by Type</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {[{ type: "IP Addresses", count: 534, status: "active", color: "text-cyan-400" }, { type: "Domains", count: 312, status: "active", color: "text-emerald-400" }, { type: "File Hashes", count: 401, status: "active", color: "text-yellow-400" }].map((e) => (
        <div key={e.type} className="card-interactive p-4"><p className={clsx("font-bold", e.color)}>{e.type}</p><p className="text-2xl font-bold text-white/80 mt-1">{e.count}</p><p className="text-xs text-white/40">{e.status}</p></div>))}</div></div>)}
    {tab === "active" && (<div className="space-y-3">
      {[{ id: "IOC-1247", type: "IP", value: "198.51.100.23", source: "Threat Feed", severity: "critical", confidence: "95%" },
        { id: "IOC-1246", type: "Domain", value: "malware-c2.example.com", source: "SIEM Alert", severity: "high", confidence: "90%" },
        { id: "IOC-1245", type: "SHA256", value: "e3b0c442...b855", source: "Sandbox", severity: "critical", confidence: "98%" },
        { id: "IOC-1244", type: "URL", value: "https://evil.example.com/payload", source: "SIEM Alert", severity: "medium", confidence: "75%" },
      ].map((ioc) => (<div key={ioc.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{ioc.id}</span><span className="text-xs text-white/40 ml-2">{ioc.type}</span></div><StatusBadge status={ioc.severity} /></div>
        <p className="text-white/90 font-medium font-mono text-sm">{ioc.value}</p><div className="flex gap-4 mt-1"><span className="text-xs text-white/50">Source: {ioc.source}</span><span className="text-xs text-white/50">Confidence: {ioc.confidence}</span></div></div>))}</div>)}
    {tab === "enrichment" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Enrichment Pipeline</h3>
      {[{ ioc: "198.51.100.23", threat_score: 0.92, geo: "RU", asn: "AS12345", families: "Emotet, TrickBot", campaigns: "APT29-Spring2026" },
        { ioc: "malware-c2.example.com", threat_score: 0.87, geo: "CN", asn: "AS9808", families: "Cobalt Strike", campaigns: "UNC2452" },
        { ioc: "e3b0c442...b855", threat_score: 0.95, geo: "N/A", asn: "N/A", families: "Ransomware", campaigns: "BlackCat" },
      ].map((e, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><span className="font-mono text-sm text-white/90">{e.ioc}</span><span className={clsx("text-xs font-bold", e.threat_score >= 0.9 ? "text-red-400" : "text-yellow-400")}>Score: {e.threat_score}</span></div>
        <div className="grid grid-cols-2 gap-2 text-xs text-white/50"><span>Geo: {e.geo}</span><span>ASN: {e.asn}</span><span>Families: {e.families}</span><span>Campaigns: {e.campaigns}</span></div></div>))}</div>)}
    {tab === "aging" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">IOC</th><th className="px-4 py-3">Type</th><th className="px-4 py-3">Age (days)</th><th className="px-4 py-3">Status</th><th className="px-4 py-3">Action</th></tr></thead>
      <tbody>{[
        { ioc: "192.0.2.55", type: "IP", age: 182, status: "expired", action: "Retire" },
        { ioc: "old-c2.example.com", type: "Domain", age: 95, status: "aged", action: "Re-validate" },
        { ioc: "8.8.8.8", type: "IP", age: 12, status: "false_positive", action: "Remove" },
        { ioc: "203.0.113.42", type: "IP", age: 45, status: "active", action: "Monitor" },
      ].map((r, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 font-mono text-cyan-400">{r.ioc}</td><td className="px-4 py-3 text-white/80">{r.type}</td><td className="px-4 py-3 text-white/60">{r.age}</td><td className="px-4 py-3"><StatusBadge status={r.status} /></td><td className="px-4 py-3 text-white/60">{r.action}</td></tr>))}</tbody></table></div>)}
  </div>);
}
