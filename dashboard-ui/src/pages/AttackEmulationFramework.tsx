import { useState } from "react";
import { Crosshair, Shield, Target, AlertTriangle, Activity } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "campaigns" | "detection_gaps" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "campaigns", label: "Campaigns" },
  { id: "detection_gaps", label: "Detection Gaps" },
  { id: "metrics", label: "Metrics" },
];

const CAMPAIGNS = [
  { id: "AE-001", adversary: "APT29 (Cozy Bear)", techniques: 18, detected: 14, status: "completed", coverage: "78%" },
  { id: "AE-002", adversary: "FIN7", techniques: 12, detected: 9, status: "active", coverage: "75%" },
  { id: "AE-003", adversary: "Lazarus Group", techniques: 22, detected: 15, status: "completed", coverage: "68%" },
  { id: "AE-004", adversary: "ALPHV/BlackCat", techniques: 8, detected: 7, status: "active", coverage: "88%" },
];

const GAPS = [
  { id: "GAP-001", technique: "T1055 - Process Injection", tactic: "Defense Evasion", severity: "critical", source: "AE-003" },
  { id: "GAP-002", technique: "T1134 - Access Token Manipulation", tactic: "Privilege Escalation", severity: "high", source: "AE-001" },
  { id: "GAP-003", technique: "T1027 - Obfuscated Files", tactic: "Defense Evasion", severity: "high", source: "AE-002" },
];

export default function AttackEmulationFramework() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Attack Emulation Framework" subtitle="Adversary emulation and purple team operations" icon={<Crosshair className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Active Campaigns" value="2" icon={<Target className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Detection Coverage" value="77%" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Techniques Tested" value="60" icon={<Activity className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Gaps Found" value="12" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Adversary Tier Coverage</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "APT", v: "3", c: "text-red-400" }, { l: "Organized Crime", v: "2", c: "text-orange-400" }, { l: "Hacktivist", v: "1", c: "text-yellow-400" }, { l: "Insider", v: "1", c: "text-cyan-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "campaigns" && (<div className="space-y-3">{CAMPAIGNS.map((c) => (<div key={c.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{c.id}</span><span className="ml-2 text-xs text-white/40">{c.coverage} coverage</span></div><StatusBadge status={c.status} /></div><p className="text-white/90 text-sm font-medium">{c.adversary}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>{c.techniques} techniques</span><span className={c.detected < c.techniques ? "text-yellow-400" : "text-emerald-400"}>{c.detected} detected</span></div></div>))}</div>)}
      {tab === "detection_gaps" && (<div className="space-y-3">{GAPS.map((g) => (<div key={g.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{g.id}</span><span className="ml-2 text-xs text-white/40">{g.source}</span></div><StatusBadge status={g.severity} /></div><p className="text-white/90 text-sm">{g.technique}</p><span className="text-xs text-white/50">{g.tactic}</span></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Emulation Metrics</h3>{[{ m: "Detection Coverage", v: "77%", t: "+5%" }, { m: "Avg Detection Latency", v: "4.2s", t: "-1.1s" }, { m: "Techniques per Campaign", v: "15", t: "+2" }, { m: "Gap Remediation Rate", v: "68%", t: "+12%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
