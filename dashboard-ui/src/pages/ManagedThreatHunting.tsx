import { useState } from "react";
import { Crosshair, Shield, Clock, Target, Activity } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "hunts" | "findings" | "coverage";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "hunts", label: "Active Hunts" }, { id: "findings", label: "Findings" }, { id: "coverage", label: "Coverage" }];
export default function ManagedThreatHunting() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Managed Threat Hunting" subtitle="Autonomous 24/7 threat hunting — no human analyst dependency" icon={<Crosshair className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Hunts/Day" value="48" icon={<Activity className="h-5 w-5 text-cyan-400" />} />
      <MetricCard title="Threats Found (7d)" value="7" icon={<Target className="h-5 w-5 text-red-400" />} />
      <MetricCard title="MITRE Coverage" value="94%" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="24/7 Uptime" value="100%" icon={<Clock className="h-5 w-5 text-emerald-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Hunting vs OverWatch</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {[{ label: "Coverage", ours: "24/7 autonomous", theirs: "Business hours + on-call", color: "text-emerald-400" },
        { label: "Cost", ours: "Included in platform", theirs: "$250K+/year", color: "text-cyan-400" },
        { label: "Data Sources", ours: "Any vendor", theirs: "Falcon only", color: "text-cyan-400" }].map((c) => (
        <div key={c.label} className="card-interactive p-4"><p className="text-sm text-white/60">{c.label}</p><div className="flex justify-between mt-2"><div><p className="text-white/40 text-xs">ShieldOps</p><p className={clsx("font-bold", c.color)}>{c.ours}</p></div><div className="text-right"><p className="text-white/40 text-xs">OverWatch</p><p className="text-white/30">{c.theirs}</p></div></div></div>))}</div></div>)}
    {tab === "hunts" && (<div className="space-y-3">
      {[{ id: "HNT-048", technique: "TTP Hunt: T1078 — Valid Accounts", method: "ttp_hunt", sources: "Okta + Entra + CloudTrail", status: "running" },
        { id: "HNT-047", technique: "Anomaly: Unusual DNS resolution patterns", method: "anomaly_hunt", sources: "DNS logs + NDR", status: "running" },
        { id: "HNT-046", technique: "IOC Sweep: APT29 indicators", method: "ioc_sweep", sources: "All endpoints + SIEM", status: "completed" },
      ].map((h) => (<div key={h.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{h.id}</span><span className="text-xs text-white/40 ml-2">{h.method}</span></div><StatusBadge status={h.status} /></div>
        <p className="text-white/90 font-medium">{h.technique}</p><p className="text-xs text-white/50">Sources: {h.sources}</p></div>))}</div>)}
    {tab === "findings" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Confirmed Threats (7d)</h3>
      {[{ finding: "Cobalt Strike C2 beacon via DNS tunneling", assessment: "confirmed", mitre: "T1071.004", escalated: true },
        { finding: "Credential harvesting via phishing kit", assessment: "confirmed", mitre: "T1566.001", escalated: true },
        { finding: "Living-off-the-land binary abuse (LOLBin)", assessment: "probable", mitre: "T1218", escalated: false },
      ].map((f, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{f.finding}</p><p className="text-xs text-white/50">{f.mitre} | {f.escalated ? "Escalated" : "Monitoring"}</p></div><StatusBadge status={f.assessment} /></div>))}</div>)}
    {tab === "coverage" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">MITRE Tactic</th><th className="px-4 py-3">Techniques</th><th className="px-4 py-3">Hunted</th><th className="px-4 py-3">Coverage</th></tr></thead>
      <tbody>{[
        { tactic: "Initial Access", techniques: 9, hunted: 9, coverage: "100%" },
        { tactic: "Execution", techniques: 14, hunted: 13, coverage: "93%" },
        { tactic: "Persistence", techniques: 19, hunted: 18, coverage: "95%" },
        { tactic: "Lateral Movement", techniques: 9, hunted: 9, coverage: "100%" },
        { tactic: "Exfiltration", techniques: 9, hunted: 8, coverage: "89%" },
      ].map((t, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90">{t.tactic}</td><td className="px-4 py-3 text-white/80">{t.techniques}</td><td className="px-4 py-3 text-white/70">{t.hunted}</td><td className="px-4 py-3 text-emerald-400">{t.coverage}</td></tr>))}</tbody></table></div>)}
  </div>);
}
