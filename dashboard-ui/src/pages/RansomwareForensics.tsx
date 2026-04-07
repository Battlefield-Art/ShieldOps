import { useState } from "react";
import { Shield, Lock, AlertTriangle, Search, Database } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "attack_chain" | "blast_radius" | "recovery";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "attack_chain", label: "Attack Chain" }, { id: "blast_radius", label: "Blast Radius" }, { id: "recovery", label: "Recovery Plan" }];
export default function RansomwareForensics() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Ransomware Forensics" subtitle="LLM-powered forensic analysis with predictive blast radius modeling" icon={<Shield className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Incidents Analyzed" value="3" icon={<Search className="h-5 w-5" />} />
      <MetricCard title="Variant Identified" value="LockBit 3.0" icon={<Lock className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Systems Affected" value="47" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Data Encrypted" value="2.3 TB" icon={<Database className="h-5 w-5 text-yellow-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Forensic Analysis Summary</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {[{ label: "Initial Access", detail: "Phishing → RDP → Cobalt Strike", time: "T-72h" },
        { label: "Lateral Movement", detail: "SMB → WMI → PsExec across 12 hosts", time: "T-24h" },
        { label: "Encryption", detail: "LockBit 3.0 deployed to 47 systems", time: "T-0" }].map((s) => (
        <div key={s.label} className="card-interactive p-4"><p className="text-cyan-400 font-medium">{s.label}</p><p className="text-white/80 text-sm mt-1">{s.detail}</p><p className="text-xs text-white/40">{s.time}</p></div>))}</div></div>)}
    {tab === "attack_chain" && (<div className="card-surface p-6"><h3 className="section-heading">Reconstructed Attack Chain</h3><div className="space-y-2">
      {[{ time: "T-72h", event: "Phishing email with macro document", mitre: "T1566.001", phase: "initial_access" },
        { time: "T-68h", event: "Cobalt Strike beacon established via RDP", mitre: "T1021.001", phase: "execution" },
        { time: "T-48h", event: "Credential dumping with Mimikatz", mitre: "T1003.001", phase: "credential_access" },
        { time: "T-24h", event: "Lateral movement via SMB to 12 hosts", mitre: "T1021.002", phase: "lateral_movement" },
        { time: "T-6h", event: "Shadow copy deletion on all targets", mitre: "T1490", phase: "impact_prep" },
        { time: "T-0", event: "LockBit 3.0 encryption executed", mitre: "T1486", phase: "impact" },
      ].map((e, i) => (<div key={i} className="flex gap-4 p-2 rounded bg-white/5"><span className="font-mono text-xs text-cyan-400 w-12 shrink-0">{e.time}</span><div className="flex-1"><p className="text-white/80 text-sm">{e.event}</p><div className="flex gap-2 mt-1"><span className="text-xs font-mono text-white/40">{e.mitre}</span><StatusBadge status={e.phase} /></div></div></div>))}</div></div>)}
    {tab === "blast_radius" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Blast Radius Assessment</h3>
      {[{ zone: "Endpoint Tier", systems: 47, encrypted: "2.3 TB", status: "widespread" },
        { zone: "Database Tier", systems: 3, encrypted: "0 TB", status: "contained" },
        { zone: "Cloud Storage", systems: 0, encrypted: "0 TB", status: "unaffected" },
        { zone: "Backup Systems", systems: 0, encrypted: "0 TB", status: "unaffected" },
      ].map((z, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{z.zone}</p><p className="text-xs text-white/50">{z.systems} systems | {z.encrypted} encrypted</p></div><StatusBadge status={z.status} /></div>))}</div>)}
    {tab === "recovery" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Recovery Recommendations</h3>
      {[{ step: 1, action: "Isolate remaining unaffected systems", priority: "P0", status: "completed" },
        { step: 2, action: "Restore from clean backup (validated T-96h snapshot)", priority: "P0", status: "in_progress" },
        { step: 3, action: "Patch RDP and disable macro execution", priority: "P1", status: "pending" },
        { step: 4, action: "Reset all domain credentials", priority: "P1", status: "pending" },
        { step: 5, action: "Deploy EDR on all recovered systems", priority: "P2", status: "pending" },
      ].map((r) => (<div key={r.step} className="card-interactive p-4 flex items-center justify-between"><div className="flex items-center gap-3"><span className="text-cyan-400 font-mono text-lg">#{r.step}</span><div><p className="text-white/90 font-medium">{r.action}</p><p className="text-xs text-white/50">Priority: {r.priority}</p></div></div><StatusBadge status={r.status} /></div>))}</div>)}
  </div>);
}
