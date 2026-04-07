import { useState } from "react";
import { Crosshair, Shield, Target, AlertTriangle, CheckCircle } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "ttps" | "actors" | "assessments";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "ttps", label: "TTP Mappings" }, { id: "actors", label: "Actor Profiles" }, { id: "assessments", label: "Assessments" }];
export default function ThreatAttribution() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Threat Attribution" subtitle="Campaign attribution, threat actor profiling, MITRE ATT&CK TTP mapping" icon={<Crosshair className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Attributions" value="18" icon={<Target className="h-5 w-5" />} />
      <MetricCard title="TTPs Mapped" value="142" icon={<Shield className="h-5 w-5 text-cyan-400" />} />
      <MetricCard title="High Confidence" value="72%" icon={<CheckCircle className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Active Campaigns" value="5" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Attribution by Actor Type</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">
      {[{ cat: "APT", count: 7, pct: "39%", color: "text-red-400" }, { cat: "Cybercrime", count: 5, pct: "28%", color: "text-yellow-400" }, { cat: "Nation State", count: 4, pct: "22%", color: "text-red-400" }, { cat: "Unknown", count: 2, pct: "11%", color: "text-white/60" }].map((c) => (
        <div key={c.cat} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{c.cat}</p><p className={clsx("text-3xl font-bold mt-1", c.color)}>{c.pct}</p></div>))}</div></div>)}
    {tab === "ttps" && (<div className="space-y-3">
      {[{ id: "T1566.001", name: "Spearphishing Attachment", tactic: "Initial Access", incidents: 8, confidence: "high" },
        { id: "T1059.001", name: "PowerShell", tactic: "Execution", incidents: 12, confidence: "high" },
        { id: "T1003", name: "OS Credential Dumping", tactic: "Credential Access", incidents: 6, confidence: "medium" },
        { id: "T1071", name: "Application Layer Protocol", tactic: "Command and Control", incidents: 9, confidence: "high" },
        { id: "T1486", name: "Data Encrypted for Impact", tactic: "Impact", incidents: 3, confidence: "medium" },
      ].map((t) => (<div key={t.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><span className="font-mono text-xs text-cyan-400">{t.id}</span><StatusBadge status={t.confidence} /></div>
        <p className="text-white/90 font-medium">{t.name}</p><p className="text-xs text-white/50">{t.tactic} | {t.incidents} incidents</p></div>))}</div>)}
    {tab === "actors" && (<div className="space-y-3">
      {[{ name: "APT29 (Cozy Bear)", type: "apt", origin: "Russia", motivation: "Espionage", ttps: 14, campaigns: 3, confidence: "high" },
        { name: "FIN7 (Carbanak)", type: "cybercrime", origin: "Unknown", motivation: "Financial", ttps: 9, campaigns: 2, confidence: "medium" },
        { name: "Lazarus (HIDDEN COBRA)", type: "nation_state", origin: "North Korea", motivation: "Financial, Disruption", ttps: 11, campaigns: 2, confidence: "high" },
      ].map((a) => (<div key={a.name} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><span className="text-white/90 font-medium">{a.name}</span><StatusBadge status={a.confidence} /></div>
        <div className="flex gap-4 text-xs text-white/50"><span>Type: {a.type}</span><span>Origin: {a.origin}</span><span>TTPs: {a.ttps}</span><span>Campaigns: {a.campaigns}</span></div>
        <p className="text-xs text-white/50 mt-1">Motivation: {a.motivation}</p></div>))}</div>)}
    {tab === "assessments" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Recent Attribution Assessments</h3>
      {[{ incident: "IR-102", actor: "APT29", confidence: "high", ttps: 6, summary: "Supply chain compromise targeting government contractor — TTP overlap with SolarWinds campaign" },
        { incident: "IR-098", actor: "FIN7", confidence: "medium", ttps: 4, summary: "Point-of-sale malware targeting retail chain — Carbanak-style credential harvesting" },
        { incident: "IR-095", actor: "Unknown", confidence: "low", ttps: 2, summary: "Ransomware deployment with limited TTP visibility — insufficient evidence for attribution" },
      ].map((a, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div className="flex gap-3 items-center"><span className="font-mono text-xs text-cyan-400">{a.incident}</span><span className="text-white/90 font-medium">{a.actor}</span></div><StatusBadge status={a.confidence} /></div>
        <p className="text-sm text-white/70">{a.summary}</p><p className="text-xs text-white/40 mt-1">{a.ttps} MITRE ATT&CK techniques matched</p></div>))}</div>)}
  </div>);
}
