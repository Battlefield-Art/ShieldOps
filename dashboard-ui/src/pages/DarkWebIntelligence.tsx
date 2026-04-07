import { useState } from "react";
import { Eye, AlertTriangle, Globe, Users, Bell } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "mentions_feed" | "threat_actors" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "mentions_feed", label: "Mentions Feed" },
  { id: "threat_actors", label: "Threat Actors" },
  { id: "metrics", label: "Metrics" },
];

const MENTIONS = [
  { id: "DW-001", source: "RaidForums", category: "Credential Leak", snippet: "Employee credentials for [redacted].com posted", credibility: "high", severity: "critical" },
  { id: "DW-002", source: "BreachForums", category: "Data Breach", snippet: "Customer database dump offered for sale", credibility: "medium", severity: "high" },
  { id: "DW-003", source: "Telegram Channel", category: "Exploit Sale", snippet: "Zero-day for [vendor] product discussed", credibility: "low", severity: "medium" },
  { id: "DW-004", source: "Paste Site", category: "Brand Abuse", snippet: "Phishing kit mimicking corporate login", credibility: "verified", severity: "high" },
];

const ACTORS = [
  { alias: "ShadowBroker_2", tier: "Organized Crime", mentions: 8, credibility: "high", active: true },
  { alias: "GhostData", tier: "Hacktivist", mentions: 3, credibility: "medium", active: true },
  { alias: "DarkPulse", tier: "APT", mentions: 12, credibility: "verified", active: false },
];

export default function DarkWebIntelligence() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Dark Web Intelligence" subtitle="Dark web monitoring and threat intelligence" icon={<Eye className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Active Mentions" value="23" icon={<Globe className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Critical Threats" value="4" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Threat Actors" value="8" icon={<Users className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Alerts (30d)" value="12" icon={<Bell className="h-5 w-5 text-emerald-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Threat Categories</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Credential Leaks", v: "8", c: "text-red-400" }, { l: "Data Breaches", v: "5", c: "text-orange-400" }, { l: "Exploit Sales", v: "6", c: "text-yellow-400" }, { l: "Brand Abuse", v: "4", c: "text-cyan-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "mentions_feed" && (<div className="space-y-3">{MENTIONS.map((m) => (<div key={m.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{m.id}</span><span className="ml-2 text-xs text-white/40">{m.source}</span></div><StatusBadge status={m.severity} /></div><p className="text-white/90 text-sm">{m.snippet}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>{m.category}</span><span>Credibility: {m.credibility}</span></div></div>))}</div>)}
      {tab === "threat_actors" && (<div className="space-y-3">{ACTORS.map((a) => (<div key={a.alias} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><span className="text-white/90 font-medium font-mono">{a.alias}</span><StatusBadge status={a.active ? "active" : "inactive"} /></div><div className="flex gap-4 mt-2 text-xs text-white/50"><span>Tier: {a.tier}</span><span>{a.mentions} mentions</span><span>Credibility: {a.credibility}</span></div></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Intelligence Metrics</h3>{[{ m: "Mentions (30d)", v: "23", t: "+8" }, { m: "Verified Threats", v: "7", t: "+2" }, { m: "Avg Response Time", v: "2.4 hrs", t: "-0.6 hrs" }, { m: "False Positive Rate", v: "12%", t: "-3%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
