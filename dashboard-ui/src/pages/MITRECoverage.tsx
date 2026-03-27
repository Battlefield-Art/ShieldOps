import { useState } from "react";
import { Grid3X3, Shield, AlertTriangle, Target, BarChart3, CheckCircle } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "matrix" | "gaps" | "recommendations";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "matrix", label: "Coverage Matrix" }, { id: "gaps", label: "Gaps" }, { id: "recommendations", label: "Recommendations" }];
export default function MITRECoverage() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="MITRE ATT&CK Coverage" subtitle="Map detections to techniques, find uncovered gaps, generate missing rules" icon={<Grid3X3 className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Overall Coverage" value="78.4%" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Techniques Covered" value="156/199" icon={<CheckCircle className="h-5 w-5 text-cyan-400" />} />
      <MetricCard title="Gaps Found" value="43" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Rules Generated" value="28" icon={<Target className="h-5 w-5 text-cyan-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Coverage by Tactic</h3><div className="grid grid-cols-2 md:grid-cols-4 gap-3">
      {[{ tactic: "Initial Access", pct: 89, color: "text-emerald-400" }, { tactic: "Execution", pct: 82, color: "text-emerald-400" }, { tactic: "Persistence", pct: 74, color: "text-yellow-400" }, { tactic: "Priv Escalation", pct: 71, color: "text-yellow-400" }, { tactic: "Defense Evasion", pct: 65, color: "text-yellow-400" }, { tactic: "Credential Access", pct: 83, color: "text-emerald-400" }, { tactic: "Lateral Movement", pct: 78, color: "text-cyan-400" }, { tactic: "Exfiltration", pct: 67, color: "text-yellow-400" }].map((t) => (
        <div key={t.tactic} className="card-interactive p-3 text-center"><p className="text-xs text-white/60">{t.tactic}</p><p className={clsx("text-2xl font-bold mt-1", t.color)}>{t.pct}%</p></div>))}</div></div>)}
    {tab === "matrix" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Tactic</th><th className="px-4 py-3">Techniques</th><th className="px-4 py-3">Covered</th><th className="px-4 py-3">Coverage</th></tr></thead>
      <tbody>{[
        { tactic: "Initial Access", total: 9, covered: 8, pct: "89%" },
        { tactic: "Execution", total: 14, covered: 11, pct: "79%" },
        { tactic: "Persistence", total: 19, covered: 14, pct: "74%" },
        { tactic: "Privilege Escalation", total: 13, covered: 9, pct: "69%" },
        { tactic: "Defense Evasion", total: 42, covered: 27, pct: "64%" },
        { tactic: "Lateral Movement", total: 9, covered: 7, pct: "78%" },
        { tactic: "Exfiltration", total: 9, covered: 6, pct: "67%" },
      ].map((t, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90">{t.tactic}</td><td className="px-4 py-3 text-white/80">{t.total}</td><td className="px-4 py-3 text-white/70">{t.covered}</td><td className="px-4 py-3"><span className={clsx("font-mono", parseInt(t.pct) > 80 ? "text-emerald-400" : parseInt(t.pct) > 70 ? "text-cyan-400" : "text-yellow-400")}>{t.pct}</span></td></tr>))}</tbody></table></div>)}
    {tab === "gaps" && (<div className="space-y-3">
      {[{ id: "T1055", name: "Process Injection", tactic: "Defense Evasion", priority: "critical", detail: "No detection for DLL injection, process hollowing" },
        { id: "T1053", name: "Scheduled Task/Job", tactic: "Persistence", priority: "high", detail: "Only cron monitored, missing Windows Task Scheduler" },
        { id: "T1048", name: "Exfiltration Over Alternative Protocol", tactic: "Exfiltration", priority: "high", detail: "DNS tunneling not monitored" },
      ].map((g) => (<div key={g.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{g.id}</span><span className="text-xs text-white/40 ml-2">{g.tactic}</span></div><StatusBadge status={g.priority} /></div>
        <p className="text-white/90 font-medium">{g.name}</p><p className="text-xs text-white/50">{g.detail}</p></div>))}</div>)}
    {tab === "recommendations" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Recommended Detection Rules</h3>
      {[{ technique: "T1055 — Process Injection", rule: "Monitor for CreateRemoteThread + WriteProcessMemory API calls", priority: "critical", effort: "medium" },
        { technique: "T1048 — DNS Tunneling", rule: "Alert on DNS queries with high entropy or unusual TXT records", priority: "high", effort: "low" },
        { technique: "T1053 — Scheduled Tasks", rule: "Monitor Windows Event ID 4698 (task created) from non-admin", priority: "high", effort: "low" },
      ].map((r, i) => (<div key={i} className="card-interactive p-4"><p className="text-white/90 font-medium">{r.technique}</p><p className="text-xs text-white/70 mt-1">{r.rule}</p><p className="text-xs text-white/50">Priority: {r.priority} | Effort: {r.effort}</p></div>))}</div>)}
  </div>);
}
