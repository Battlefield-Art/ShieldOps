import { useState } from "react";
import { Search, Shield, AlertTriangle, Target, Zap, Eye } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "simulations" | "blind_spots" | "priorities";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "simulations", label: "Simulations" }, { id: "blind_spots", label: "Blind Spots" }, { id: "priorities", label: "Priorities" }];
export default function DetectionGapFinder() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Detection Gap Finder" subtitle="Simulate attacks, verify detections fire, find blind spots" icon={<Search className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Techniques Tested" value="89" icon={<Target className="h-5 w-5" />} />
      <MetricCard title="Detection Rate" value="82.0%" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Blind Spots" value="16" icon={<Eye className="h-5 w-5 text-red-400" />} />
      <MetricCard title="False Negatives" value="7" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Detection Outcomes</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">
      {[{ outcome: "Detected", count: 73, pct: "82%", color: "text-emerald-400" }, { outcome: "Partial", count: 5, pct: "5.6%", color: "text-yellow-400" }, { outcome: "Missed", count: 9, pct: "10.1%", color: "text-red-400" }, { outcome: "False Negative", count: 2, pct: "2.2%", color: "text-red-400" }].map((o) => (
        <div key={o.outcome} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{o.outcome}</p><p className={clsx("text-3xl font-bold mt-1", o.color)}>{o.pct}</p></div>))}</div></div>)}
    {tab === "simulations" && (<div className="space-y-3">
      {[{ technique: "T1059.001 — PowerShell", method: "Obfuscated PS command", result: "detected", alert: "Suspicious PowerShell execution" },
        { technique: "T1055 — Process Injection", method: "CreateRemoteThread simulation", result: "missed", alert: "No alert generated" },
        { technique: "T1003 — Credential Dumping", method: "Mimikatz-style memory access", result: "detected", alert: "LSASS memory access" },
        { technique: "T1048 — DNS Exfiltration", method: "High-entropy DNS queries", result: "missed", alert: "No DNS monitoring" },
      ].map((s, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><p className="text-white/90 font-medium">{s.technique}</p><StatusBadge status={s.result} /></div>
        <p className="text-xs text-white/50">Method: {s.method} | Alert: {s.alert}</p></div>))}</div>)}
    {tab === "blind_spots" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Critical Blind Spots</h3>
      {[{ area: "Process injection (DLL, hollowing)", risk: "Ransomware initial execution path", severity: "critical" },
        { area: "DNS tunneling exfiltration", risk: "Data theft via covert channel", severity: "high" },
        { area: "Living-off-the-land binaries", risk: "Evasion of endpoint controls", severity: "high" },
      ].map((b, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{b.area}</p><p className="text-xs text-white/50">Risk: {b.risk}</p></div><StatusBadge status={b.severity} /></div>))}</div>)}
    {tab === "priorities" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Gap</th><th className="px-4 py-3">Risk</th><th className="px-4 py-3">Fix Effort</th><th className="px-4 py-3">Priority</th></tr></thead>
      <tbody>{[
        { gap: "Process injection detection", risk: "critical", effort: "Medium", priority: "P0" },
        { gap: "DNS exfil monitoring", risk: "high", effort: "Low", priority: "P1" },
        { gap: "LOLBin abuse detection", risk: "high", effort: "Medium", priority: "P1" },
        { gap: "Scheduled task monitoring", risk: "medium", effort: "Low", priority: "P2" },
      ].map((p, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90">{p.gap}</td><td className="px-4 py-3"><StatusBadge status={p.risk} /></td><td className="px-4 py-3 text-white/70">{p.effort}</td><td className="px-4 py-3 text-cyan-400 font-mono">{p.priority}</td></tr>))}</tbody></table></div>)}
  </div>);
}
