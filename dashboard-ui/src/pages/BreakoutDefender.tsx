import { useState } from "react";
import { Timer, Shield, AlertTriangle, Activity, Crosshair, Ban } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "signals" | "containment" | "timeline";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "signals", label: "Breakout Signals" }, { id: "containment", label: "Containment" }, { id: "timeline", label: "Timeline" }];
export default function BreakoutDefender() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Breakout Defender" subtitle="Sub-5-minute breakout detection and automated containment" icon={<Timer className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Avg Containment Time" value="2.8 min" icon={<Timer className="h-5 w-5 text-cyan-400" />} />
      <MetricCard title="Breakouts Prevented (7d)" value="5" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Active Signals" value="3" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Kill Chain Coverage" value="94%" icon={<Crosshair className="h-5 w-5" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Breakout Defense (7d)</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {[{ label: "Prevented", count: 5, color: "text-emerald-400" }, { label: "Contained <5min", count: 4, color: "text-cyan-400" }, { label: "Escalated", count: 1, color: "text-yellow-400" }].map((s) => (
        <div key={s.label} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.label}</p><p className={clsx("text-3xl font-bold mt-1", s.color)}>{s.count}</p></div>))}</div></div>)}
    {tab === "signals" && (<div className="space-y-3">
      {[{ id: "BRK-005", phase: "Lateral Movement", tactic: "T1021 — Remote Services", source: "AWS→GCP pivot", severity: "critical", time: "Active" },
        { id: "BRK-004", phase: "Privilege Escalation", tactic: "T1548 — Abuse Elevation", source: "K8s pod escape", severity: "high", time: "2h ago" },
        { id: "BRK-003", phase: "Initial Access", tactic: "T1078 — Valid Accounts", source: "Stolen OAuth token", severity: "high", time: "6h ago" },
      ].map((s) => (<div key={s.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{s.id}</span><span className="text-xs text-white/40 ml-2">{s.phase}</span></div><StatusBadge status={s.severity} /></div>
        <p className="text-white/90 font-medium">{s.tactic}</p><p className="text-xs text-white/50">Source: {s.source} | {s.time}</p></div>))}</div>)}
    {tab === "containment" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Recent Containment Actions</h3>
      {[{ action: "Network Isolation", target: "gcp-worker-12", type: "isolate_host", time: "1.2 min", status: "completed" },
        { action: "Credential Revocation", target: "sa-admin@aws", type: "revoke_credentials", time: "0.4 min", status: "completed" },
        { action: "Process Quarantine", target: "cryptominer.exe", type: "quarantine_process", time: "0.2 min", status: "completed" },
      ].map((c, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{c.action}</p><p className="text-xs text-white/50">Target: {c.target} | Response: {c.time}</p></div><StatusBadge status={c.status} /></div>))}</div>)}
    {tab === "timeline" && (<div className="card-surface p-6"><h3 className="section-heading">Latest Breakout Timeline</h3><div className="space-y-2">
      {[{ time: "00:00", event: "Initial access detected — stolen credential", phase: "initial_access" },
        { time: "00:12", event: "Privilege escalation attempt — pod escape", phase: "privilege_escalation" },
        { time: "00:45", event: "Lateral movement — cross-cloud pivot AWS→GCP", phase: "lateral_movement" },
        { time: "01:30", event: "ShieldOps auto-containment triggered", phase: "containment" },
        { time: "02:48", event: "All attack paths blocked — breakout prevented", phase: "resolved" },
      ].map((e, i) => (<div key={i} className="flex gap-4 p-2 rounded bg-white/5"><span className="font-mono text-xs text-cyan-400 w-12">{e.time}</span><div><p className="text-white/80 text-sm">{e.event}</p><StatusBadge status={e.phase} /></div></div>))}</div></div>)}
  </div>);
}
