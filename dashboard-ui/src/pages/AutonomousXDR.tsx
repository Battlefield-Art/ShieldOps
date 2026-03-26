import { useState } from "react";
import { Radar, Layers, AlertTriangle, Shield, Activity, Crosshair } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "signals" | "campaigns" | "investigations";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "signals", label: "Signals" }, { id: "campaigns", label: "Campaigns" }, { id: "investigations", label: "Investigations" }];
export default function AutonomousXDR() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Autonomous XDR" subtitle="Vendor-neutral detection and response across endpoint, network, cloud, and identity" icon={<Radar className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Signals Correlated (24h)" value="4.7K" icon={<Layers className="h-5 w-5" />} />
      <MetricCard title="Campaigns Detected" value="4" icon={<Crosshair className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Detection Coverage" value="96.2%" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Auto-Investigated" value="89%" icon={<Activity className="h-5 w-5 text-cyan-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Cross-Domain Coverage</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {[{ domain: "Endpoint", sources: "Falcon, Defender, SentinelOne", signals: 1840, color: "text-cyan-400" },
        { domain: "Identity", sources: "Okta, Entra ID, IAM", signals: 1230, color: "text-emerald-400" },
        { domain: "Cloud", sources: "AWS, GCP, Azure, K8s", signals: 1630, color: "text-yellow-400" }].map((d) => (
        <div key={d.domain} className="card-interactive p-4"><p className={clsx("text-lg font-bold", d.color)}>{d.domain}</p><p className="text-xs text-white/50 mt-1">{d.sources}</p><p className="text-2xl font-bold text-white/80 mt-2">{d.signals} signals</p></div>))}</div></div>)}
    {tab === "signals" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Source</th><th className="px-4 py-3">Domain</th><th className="px-4 py-3">Signal</th><th className="px-4 py-3">MITRE</th><th className="px-4 py-3">Correlated</th></tr></thead>
      <tbody>{[
        { src: "CrowdStrike", domain: "Endpoint", signal: "Credential dump detected", mitre: "T1003", corr: "yes" },
        { src: "Okta", domain: "Identity", signal: "Impossible travel login", mitre: "T1078", corr: "yes" },
        { src: "AWS CloudTrail", domain: "Cloud", signal: "IAM role assumption chain", mitre: "T1550", corr: "yes" },
        { src: "Defender", domain: "Endpoint", signal: "PowerShell obfuscation", mitre: "T1059.001", corr: "no" },
      ].map((s, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90">{s.src}</td><td className="px-4 py-3"><StatusBadge status={s.domain.toLowerCase()} /></td><td className="px-4 py-3 text-white/80">{s.signal}</td><td className="px-4 py-3 font-mono text-cyan-400 text-xs">{s.mitre}</td><td className="px-4 py-3"><StatusBadge status={s.corr === "yes" ? "correlated" : "standalone"} /></td></tr>))}</tbody></table></div>)}
    {tab === "campaigns" && (<div className="space-y-3">
      {[{ id: "CPG-004", name: "Credential Harvest → Cloud Pivot", domains: ["Endpoint", "Identity", "Cloud"], techniques: 5, severity: "critical", status: "active" },
        { id: "CPG-003", name: "Ransomware Pre-staging", domains: ["Endpoint", "Network"], techniques: 3, severity: "high", status: "contained" },
        { id: "CPG-002", name: "Data Exfil via SaaS", domains: ["Identity", "Cloud"], techniques: 4, severity: "high", status: "resolved" },
      ].map((c) => (<div key={c.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{c.id}</span><span className="text-xs text-white/40 ml-2">{c.techniques} techniques</span></div><StatusBadge status={c.severity} /></div>
        <p className="text-white/90 font-medium">{c.name}</p><div className="flex gap-1 mt-1">{c.domains.map((d) => <span key={d} className="text-xs px-2 py-0.5 rounded bg-white/10 text-white/60">{d}</span>)}</div></div>))}</div>)}
    {tab === "investigations" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Auto-Investigations</h3>
      {[{ campaign: "Credential Harvest → Cloud Pivot", blast_radius: "12 hosts, 3 accounts, 2 cloud roles", duration: "3.4 min", verdict: "true_positive" },
        { campaign: "Ransomware Pre-staging", blast_radius: "4 hosts, 1 share", duration: "2.1 min", verdict: "true_positive" },
        { campaign: "PowerShell Obfuscation", blast_radius: "1 host", duration: "0.8 min", verdict: "false_positive" },
      ].map((inv, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{inv.campaign}</p><p className="text-xs text-white/50">Blast radius: {inv.blast_radius} | {inv.duration}</p></div><StatusBadge status={inv.verdict} /></div>))}</div>)}
  </div>);
}
