import { useState } from "react";
import { Globe, Shield, AlertTriangle, Activity, Lock, Zap } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "threats" | "domains" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "threats", label: "Threats" },
  { id: "domains", label: "Domains" },
  { id: "metrics", label: "Metrics" },
];

const THREATS = [
  { id: "DNS-001", type: "DNS Tunneling", domain: "enc.data-exfil.xyz", severity: "critical", detail: "High-entropy TXT queries, avg 4.2KB/query, 340 queries/min" },
  { id: "DNS-002", type: "DGA Domain", domain: "x7kf9p2m.example.com", severity: "high", detail: "Algorithmically generated domain, matches Emotet DGA pattern" },
  { id: "DNS-003", type: "Typosquat", domain: "shie1dops.io", severity: "medium", detail: "Homoglyph of shieldops.io — registered 2 days ago" },
  { id: "DNS-004", type: "Fast Flux", domain: "cdn-rotate.suspicious.net", severity: "high", detail: "12 different A records in 1 hour, TTL=30s" },
];

export default function DNSThreatAnalyzer() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="DNS Threat Analyzer" subtitle="DNS traffic analysis for tunneling, DGA, and domain threats" icon={<Globe className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Queries Analyzed" value="4.7M" icon={<Activity className="h-5 w-5" />} />
        <MetricCard title="Threats Detected" value="18" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Domains Blocked" value="2,340" icon={<Lock className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Resolution Time" value="1.2ms" icon={<Zap className="h-5 w-5 text-cyan-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">DNS Health</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Clean", v: "4.69M", c: "text-emerald-400" }, { l: "Suspicious", v: "847", c: "text-yellow-400" }, { l: "Blocked", v: "2,340", c: "text-red-400" }, { l: "DGA Detected", v: "34", c: "text-orange-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "threats" && (<div className="space-y-3">{THREATS.map((t) => (<div key={t.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{t.id}</span><span className="ml-2 text-white/90 font-medium">{t.type}</span></div><StatusBadge status={t.severity} /></div><p className="text-white/70 text-sm font-mono">{t.domain}</p><p className="text-white/50 text-xs mt-1">{t.detail}</p></div>))}</div>)}
      {tab === "domains" && (<div className="card-surface p-6"><p className="text-white/60">Domain classification and reputation tracking across 4.7M queries.</p></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Detection Trends</h3>{[{ m: "Detection Rate", v: "99.8%", t: "+0.2%" }, { m: "False Positive Rate", v: "0.3%", t: "-0.1%" }, { m: "DGA Detection", v: "97%", t: "+2%" }, { m: "Avg Block Time", v: "0.8ms", t: "-0.2ms" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
