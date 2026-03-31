import { useState } from "react";
import { BookOpen, Shield, AlertTriangle, Activity, Target, Clock } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "timeline" | "kill_chain" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "timeline", label: "Timeline" },
  { id: "kill_chain", label: "Kill Chain" },
  { id: "metrics", label: "Metrics" },
];

const TIMELINE = [
  { id: "TL-001", time: "01:12:00Z", host: "WORKSTATION-14", event: "Phishing email opened", severity: "high", source: "email_gateway" },
  { id: "TL-002", time: "01:15:00Z", host: "WORKSTATION-14", event: "PowerShell with encoded command", severity: "medium", source: "edr" },
  { id: "TL-003", time: "02:08:00Z", host: "WORKSTATION-14", event: "Suspicious DLL dropped to Temp", severity: "high", source: "edr" },
  { id: "TL-004", time: "03:22:00Z", host: "DC-01", event: "Kerberos TGT with forged ticket", severity: "critical", source: "siem" },
  { id: "TL-005", time: "04:45:00Z", host: "FILESERVER-02", event: "PsExec lateral movement", severity: "critical", source: "ndr" },
  { id: "TL-006", time: "05:30:00Z", host: "FILESERVER-02", event: "Bulk archive of financial docs", severity: "critical", source: "dlp" },
  { id: "TL-007", time: "06:10:00Z", host: "WORKSTATION-14", event: "Large upload to external storage", severity: "critical", source: "proxy" },
];

const KILL_CHAIN = [
  { phase: "Initial Access", technique: "T1566.001", name: "Spearphishing Attachment", confidence: "92%" },
  { phase: "Execution", technique: "T1059.001", name: "PowerShell", confidence: "88%" },
  { phase: "Persistence", technique: "T1053.005", name: "Scheduled Task", confidence: "85%" },
  { phase: "Privilege Escalation", technique: "T1558.001", name: "Golden Ticket", confidence: "79%" },
  { phase: "Lateral Movement", technique: "T1570", name: "Lateral Tool Transfer", confidence: "91%" },
  { phase: "Collection", technique: "T1560.001", name: "Archive via Utility", confidence: "87%" },
  { phase: "Exfiltration", technique: "T1567.002", name: "Exfil to Cloud Storage", confidence: "94%" },
];

export default function AttackNarrativeBuilder() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Attack Narrative Builder" subtitle="Reconstruct attack timelines with MITRE ATT&CK mapping" icon={<BookOpen className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Events Collected" value="847" icon={<Activity className="h-5 w-5" />} />
        <MetricCard title="Attack Phases" value="7" icon={<Target className="h-5 w-5 text-red-400" />} />
        <MetricCard title="MITRE Techniques" value="12" icon={<Shield className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Time Span" value="5h 58m" icon={<Clock className="h-5 w-5 text-yellow-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Attack Summary</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Critical Events", v: "4", c: "text-red-400" }, { l: "High Events", v: "3", c: "text-orange-400" }, { l: "Hosts Affected", v: "3", c: "text-yellow-400" }, { l: "Users Involved", v: "2", c: "text-cyan-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "timeline" && (<div className="space-y-3">{TIMELINE.map((t) => (<div key={t.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{t.id}</span><span className="ml-2 font-mono text-xs text-white/50">{t.time}</span><span className="ml-2 text-white/90 font-medium">{t.event}</span></div><StatusBadge status={t.severity} /></div><div className="flex gap-4 text-sm text-white/60"><span>{t.host}</span><span>Source: {t.source}</span></div></div>))}</div>)}
      {tab === "kill_chain" && (<div className="space-y-3">{KILL_CHAIN.map((k, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-red-400">{k.technique}</span><span className="ml-2 text-white/90 font-medium">{k.name}</span></div><span className="text-xs text-cyan-400 font-mono">{k.confidence}</span></div><p className="text-white/50 text-xs">Phase: {k.phase}</p></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Reconstruction Quality</h3>{[{ m: "Timeline Accuracy", v: "96%", t: "+2%" }, { m: "Chain Completeness", v: "88%", t: "+5%" }, { m: "MITRE Coverage", v: "92%", t: "+3%" }, { m: "Avg Confidence", v: "87%", t: "+1%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
