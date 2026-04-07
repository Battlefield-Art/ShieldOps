import { useState } from "react";
import { Radio, AlertTriangle, Link, Target } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "ioc_feed" | "correlations" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "ioc_feed", label: "IOC Feed" },
  { id: "correlations", label: "Correlations" },
  { id: "metrics", label: "Metrics" },
];

const IOCS = [
  { value: "185.220.101.42", type: "IP", sources: 4, level: "critical", actor: "APT29", detail: "C2 server, active in SolarWinds campaign" },
  { value: "evil-updates.com", type: "Domain", sources: 3, level: "high", actor: "Lazarus", detail: "Watering hole domain, crypto-targeting" },
  { value: "d41d8cd98f00b204e9800998ecf8427e", type: "Hash", sources: 5, level: "critical", actor: "FIN7", detail: "Cobalt Strike beacon, retail POS targeting" },
  { value: "https://phish.example.com/login", type: "URL", sources: 2, level: "high", actor: "Unknown", detail: "Credential harvesting, mimics Office 365" },
  { value: "CVE-2024-3400", type: "CVE", sources: 6, level: "critical", actor: "Sandworm", detail: "PAN-OS RCE, actively exploited in the wild" },
];

const CORRELATIONS = [
  { campaign: "APT29-Solar", actors: "APT29 / Cozy Bear", iocs: 47, confidence: 0.92, techniques: "T1190, T1078, T1059" },
  { campaign: "Lazarus-Crypto", actors: "Lazarus Group", iocs: 23, confidence: 0.87, techniques: "T1566, T1204, T1486" },
  { campaign: "FIN7-Retail", actors: "FIN7 / Carbanak", iocs: 31, confidence: 0.84, techniques: "T1195, T1059, T1071" },
  { campaign: "Sandworm-Energy", actors: "Sandworm / Voodoo Bear", iocs: 18, confidence: 0.79, techniques: "T1190, T1105, T1489" },
];

export default function ThreatIntelligenceFusion() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Threat Intelligence Fusion" subtitle="Multi-source threat intel correlation and IOC scoring" icon={<Radio className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Active Feeds" value="24" icon={<Radio className="h-5 w-5" />} />
        <MetricCard title="Unique IOCs" value="14,823" icon={<Target className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Correlations" value="89" icon={<Link className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Critical Threats" value="127" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">IOC Distribution by Type</h3><div className="grid grid-cols-1 md:grid-cols-5 gap-4">{[{ l: "IP Address", v: "4,231", c: "text-red-400" }, { l: "Domain", v: "3,892", c: "text-orange-400" }, { l: "File Hash", v: "3,456", c: "text-yellow-400" }, { l: "URL", v: "2,104", c: "text-blue-400" }, { l: "CVE", v: "1,140", c: "text-emerald-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "ioc_feed" && (<div className="space-y-3">{IOCS.map((ioc) => (<div key={ioc.value} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="text-white/90 font-medium font-mono text-sm">{ioc.value}</span><span className="ml-2 text-xs text-white/40">{ioc.type}</span></div><StatusBadge status={ioc.level} /></div><p className="text-white/50 text-sm">{ioc.detail}</p><div className="flex gap-4 text-xs text-white/40 mt-1"><span>Sources: {ioc.sources}</span><span>Actor: {ioc.actor}</span></div></div>))}</div>)}
      {tab === "correlations" && (<div className="card-surface p-6"><h3 className="section-heading">Campaign Correlations</h3><div className="space-y-2">{CORRELATIONS.map((c) => (<div key={c.campaign} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="text-white/90 font-medium">{c.campaign}</span><span className="ml-2 text-xs text-white/40">{c.actors}</span></div><span className="text-cyan-400 font-mono text-sm">{(c.confidence * 100).toFixed(0)}%</span></div><div className="flex gap-4 text-xs text-white/50"><span>IOCs: {c.iocs}</span><span>Techniques: {c.techniques}</span></div></div>))}</div></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Intel Metrics</h3>{[{ m: "Feed Freshness", v: "< 5 min", t: "All feeds current" }, { m: "Dedup Rate", v: "34%", t: "+2% vs last week" }, { m: "Correlation Accuracy", v: "91%", t: "+3%" }, { m: "Actionable Intel", v: "68%", t: "+5%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
