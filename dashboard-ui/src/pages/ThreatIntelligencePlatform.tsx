import { useState } from "react";
import { Globe, Database, AlertTriangle, Target, Eye } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "intelligence" | "advisories" | "sources";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "intelligence", label: "Intelligence" }, { id: "advisories", label: "Advisories" }, { id: "sources", label: "Sources" }];
export default function ThreatIntelligencePlatform() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Threat Intelligence Platform" subtitle="Multi-source threat intel with digital risk protection — OSINT, dark web, ISAC" icon={<Globe className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Intel Items (7d)" value="1.2K" icon={<Database className="h-5 w-5" />} />
      <MetricCard title="Actionable" value="47" icon={<Target className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Advisories" value="8" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Sources Active" value="12" icon={<Eye className="h-5 w-5 text-emerald-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Intel by Relevance</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">
      {[{ level: "Immediate", count: 5, color: "text-red-400" }, { level: "High", count: 42, color: "text-yellow-400" }, { level: "Moderate", count: 187, color: "text-white/70" }, { level: "Low", count: 966, color: "text-white/40" }].map((l) => (
        <div key={l.level} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{l.level}</p><p className={clsx("text-3xl font-bold mt-1", l.color)}>{l.count}</p></div>))}</div></div>)}
    {tab === "intelligence" && (<div className="space-y-3">
      {[{ id: "TI-047", title: "Active exploitation of CVE-2026-XXXX", source: "CISA KEV", relevance: "immediate", iocs: 12 },
        { id: "TI-046", title: "New LockBit variant targeting cloud backups", source: "Dark Web", relevance: "immediate", iocs: 8 },
        { id: "TI-045", title: "APT group targeting AI/ML companies", source: "ISAC", relevance: "high", iocs: 23 },
        { id: "TI-044", title: "Credential dump matching corporate domain", source: "Dark Web", relevance: "immediate", iocs: 156 },
      ].map((t) => (<div key={t.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{t.id}</span><span className="text-xs text-white/40 ml-2">{t.source}</span></div><StatusBadge status={t.relevance} /></div>
        <p className="text-white/90 font-medium">{t.title}</p><p className="text-xs text-white/50">{t.iocs} IOCs extracted</p></div>))}</div>)}
    {tab === "advisories" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Generated Advisories</h3>
      {[{ title: "Immediate: Patch CVE-2026-XXXX on all web servers", severity: "critical", actions: 3, status: "active" },
        { title: "Alert: Corporate credentials found on dark web forum", severity: "critical", actions: 2, status: "active" },
        { title: "Warning: APT campaign targeting AI/ML infrastructure", severity: "high", actions: 4, status: "active" },
      ].map((a, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{a.title}</p><p className="text-xs text-white/50">{a.actions} recommended actions</p></div><StatusBadge status={a.severity} /></div>))}</div>)}
    {tab === "sources" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Source</th><th className="px-4 py-3">Type</th><th className="px-4 py-3">Items (7d)</th><th className="px-4 py-3">Status</th></tr></thead>
      <tbody>{[
        { src: "CISA KEV", type: "Government", items: 34, status: "active" },
        { src: "Dark Web Monitor", type: "Dark Web", items: 156, status: "active" },
        { src: "FS-ISAC", type: "ISAC", items: 89, status: "active" },
        { src: "AlienVault OTX", type: "OSINT", items: 445, status: "active" },
        { src: "Internal Telemetry", type: "Internal", items: 312, status: "active" },
        { src: "Recorded Future", type: "Commercial", items: 164, status: "active" },
      ].map((s, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90 font-medium">{s.src}</td><td className="px-4 py-3 text-white/60">{s.type}</td><td className="px-4 py-3 text-white/80">{s.items}</td><td className="px-4 py-3"><StatusBadge status={s.status} /></td></tr>))}</tbody></table></div>)}
  </div>);
}
