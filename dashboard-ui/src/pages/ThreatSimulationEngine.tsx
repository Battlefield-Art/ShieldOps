import { useState } from "react";
import { Swords, Target, Shield, AlertTriangle, Eye } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "scenarios" | "detection_gaps" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "scenarios", label: "Scenarios" },
  { id: "detection_gaps", label: "Detection Gaps" },
  { id: "metrics", label: "Metrics" },
];

const SCENARIOS = [
  { id: "SIM-001", name: "APT29 Credential Harvesting", type: "Purple Team", techniques: 6, status: "running", detection_rate: 0.67 },
  { id: "SIM-002", name: "Ransomware Kill Chain", type: "Red Team", techniques: 8, status: "completed", detection_rate: 0.88 },
  { id: "SIM-003", name: "Supply Chain Compromise", type: "TTP Replay", techniques: 4, status: "completed", detection_rate: 0.50 },
  { id: "SIM-004", name: "Insider Threat Exfiltration", type: "Automated BAS", techniques: 5, status: "pending", detection_rate: 0 },
];

const GAPS = [
  { id: "GAP-001", technique: "T1055 — Process Injection", tactic: "Defense Evasion", severity: "critical", detection: "None" },
  { id: "GAP-002", technique: "T1134 — Access Token Manipulation", tactic: "Privilege Escalation", severity: "high", detection: "Partial" },
  { id: "GAP-003", technique: "T1048 — Exfiltration Over C2", tactic: "Exfiltration", severity: "high", detection: "Partial" },
  { id: "GAP-004", technique: "T1562 — Impair Defenses", tactic: "Defense Evasion", severity: "medium", detection: "None" },
];

export default function ThreatSimulationEngine() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Threat Simulation Engine" subtitle="Automated adversary simulation and purple teaming" icon={<Swords className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Active Simulations" value="3" icon={<Target className="h-5 w-5" />} />
        <MetricCard title="Detection Rate" value="72%" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Detection Gaps" value="12" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Techniques Tested" value="23" icon={<Eye className="h-5 w-5 text-cyan-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Simulation Coverage</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Red Team", v: "4", c: "text-red-400" }, { l: "Purple Team", v: "6", c: "text-purple-400" }, { l: "TTP Replay", v: "3", c: "text-cyan-400" }, { l: "Automated BAS", v: "5", c: "text-emerald-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "scenarios" && (<div className="space-y-3">{SCENARIOS.map((s) => (<div key={s.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{s.id}</span><span className="ml-2 text-xs text-white/40">{s.type}</span></div><StatusBadge status={s.status} /></div><p className="text-white/90 text-sm">{s.name}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>{s.techniques} techniques</span><span className={s.detection_rate >= 0.75 ? "text-emerald-400" : s.detection_rate > 0 ? "text-yellow-400" : "text-white/40"}>{s.detection_rate > 0 ? `${Math.round(s.detection_rate * 100)}% detected` : "Pending"}</span></div></div>))}</div>)}
      {tab === "detection_gaps" && (<div className="space-y-3">{GAPS.map((g) => (<div key={g.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{g.id}</span><span className="ml-2 text-xs text-white/40">{g.tactic}</span></div><StatusBadge status={g.severity} /></div><p className="text-white/90 text-sm">{g.technique}</p><span className="text-xs text-white/50">Detection: {g.detection}</span></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Simulation Performance</h3>{[{ m: "Overall Detection Rate", v: "72%", t: "+5%" }, { m: "Avg Response Time", v: "4.8 min", t: "-1.2 min" }, { m: "Gaps Closed (30d)", v: "7", t: "+3" }, { m: "MITRE Coverage", v: "64%", t: "+9%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
