import { useState } from "react";
import { Shield, Target, AlertTriangle, Crosshair, CheckCircle, BarChart3 } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "scenarios" | "readiness" | "weaknesses";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "scenarios", label: "Scenarios" }, { id: "readiness", label: "Readiness Scores" }, { id: "weaknesses", label: "Weaknesses" }];
export default function AttackReadiness() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Attack Readiness" subtitle="Assess readiness against ransomware, APT, insider threat, and more" icon={<Shield className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Overall Readiness" value="Good" icon={<CheckCircle className="h-5 w-5 text-cyan-400" />} />
      <MetricCard title="Scenarios Assessed" value="8" icon={<Target className="h-5 w-5" />} />
      <MetricCard title="Score" value="76/100" icon={<BarChart3 className="h-5 w-5 text-cyan-400" />} />
      <MetricCard title="Weakest Area" value="Response" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Readiness by Capability</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {[{ cap: "Prevention", score: 82, color: "text-cyan-400" }, { cap: "Detection", score: 78, color: "text-cyan-400" }, { cap: "Response", score: 68, color: "text-yellow-400" }].map((c) => (
        <div key={c.cap} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{c.cap}</p><p className={clsx("text-3xl font-bold mt-1", c.color)}>{c.score}/100</p></div>))}</div></div>)}
    {tab === "scenarios" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Scenario</th><th className="px-4 py-3">Prevent</th><th className="px-4 py-3">Detect</th><th className="px-4 py-3">Respond</th><th className="px-4 py-3">Readiness</th></tr></thead>
      <tbody>{[
        { scenario: "Ransomware", prevent: 85, detect: 82, respond: 71, readiness: "good" },
        { scenario: "APT Campaign", prevent: 72, detect: 78, respond: 65, readiness: "adequate" },
        { scenario: "Insider Threat", prevent: 68, detect: 74, respond: 62, readiness: "adequate" },
        { scenario: "Supply Chain", prevent: 78, detect: 70, respond: 55, readiness: "insufficient" },
        { scenario: "Credential Compromise", prevent: 91, detect: 88, respond: 82, readiness: "excellent" },
        { scenario: "Cloud Breach", prevent: 84, detect: 80, respond: 72, readiness: "good" },
        { scenario: "DDoS", prevent: 88, detect: 92, respond: 85, readiness: "excellent" },
        { scenario: "Data Exfiltration", prevent: 76, detect: 72, respond: 64, readiness: "adequate" },
      ].map((s, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90">{s.scenario}</td><td className="px-4 py-3 font-mono text-white/70">{s.prevent}</td><td className="px-4 py-3 font-mono text-white/70">{s.detect}</td><td className="px-4 py-3 font-mono text-white/70">{s.respond}</td><td className="px-4 py-3"><StatusBadge status={s.readiness} /></td></tr>))}</tbody></table></div>)}
    {tab === "readiness" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Readiness Summary</h3>
      {[{ level: "Excellent", scenarios: ["Credential Compromise", "DDoS"], count: 2, color: "text-emerald-400" },
        { level: "Good", scenarios: ["Ransomware", "Cloud Breach"], count: 2, color: "text-cyan-400" },
        { level: "Adequate", scenarios: ["APT", "Insider", "Data Exfil"], count: 3, color: "text-yellow-400" },
        { level: "Insufficient", scenarios: ["Supply Chain"], count: 1, color: "text-red-400" },
      ].map((r, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-center justify-between"><p className={clsx("font-bold", r.color)}>{r.level} ({r.count})</p></div><p className="text-xs text-white/50 mt-1">{r.scenarios.join(", ")}</p></div>))}</div>)}
    {tab === "weaknesses" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Key Weaknesses</h3>
      {[{ area: "Supply chain response", detail: "No automated containment for compromised dependencies", recommendation: "Deploy supply_chain_scanner + vulnerability_remediation chain" },
        { area: "Insider threat response", detail: "Manual investigation takes 48+ hours", recommendation: "Enable insider_threat + access_remediation auto-workflow" },
        { area: "APT lateral movement", detail: "Limited east-west traffic monitoring", recommendation: "Deploy network segmentation + continuous network pentest" },
      ].map((w, i) => (<div key={i} className="card-interactive p-4"><p className="text-white/90 font-medium">{w.area}</p><p className="text-xs text-white/50">{w.detail}</p><p className="text-xs text-cyan-400 mt-1">Fix: {w.recommendation}</p></div>))}</div>)}
  </div>);
}
