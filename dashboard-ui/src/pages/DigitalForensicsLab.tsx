import { useState } from "react";
import { FileSearch, HardDrive, Shield, Clock, AlertTriangle, Database } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "evidence_vault" | "forensic_timeline" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "evidence_vault", label: "Evidence Vault" },
  { id: "forensic_timeline", label: "Timeline" },
  { id: "metrics", label: "Metrics" },
];

const EVIDENCE = [
  { id: "EV-001", type: "Disk Image", host: "web-prod-03", hash: "a3f2...b91c", size: "42 GB", status: "analyzed", custody: "verified" },
  { id: "EV-002", type: "Memory Dump", host: "api-node-07", hash: "d8e1...4f2a", size: "16 GB", status: "analyzing", custody: "verified" },
  { id: "EV-003", type: "Network Capture", host: "fw-edge-01", hash: "c7b3...e5d8", size: "8.3 GB", status: "acquired", custody: "verified" },
  { id: "EV-004", type: "Log File", host: "auth-svc-02", hash: "f1a9...c3b7", size: "2.1 GB", status: "analyzed", custody: "verified" },
];

const TIMELINE = [
  { time: "2026-03-28 02:14:33 UTC", event: "Initial access via compromised SSH key", phase: "Initial Access", severity: "critical" },
  { time: "2026-03-28 02:18:01 UTC", event: "Reverse shell established to C2 server", phase: "Execution", severity: "critical" },
  { time: "2026-03-28 02:31:47 UTC", event: "Crontab persistence mechanism installed", phase: "Persistence", severity: "high" },
  { time: "2026-03-28 03:05:22 UTC", event: "Lateral movement to database server via stolen creds", phase: "Lateral Movement", severity: "critical" },
  { time: "2026-03-28 04:42:18 UTC", event: "Database dump staged in /tmp directory", phase: "Collection", severity: "high" },
];

export default function DigitalForensicsLab() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Digital Forensics Lab" subtitle="Forensic analysis, evidence management, and IOC extraction" icon={<FileSearch className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Active Cases" value="3" icon={<HardDrive className="h-5 w-5" />} />
        <MetricCard title="Evidence Items" value="47" icon={<Database className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="IOCs Extracted" value="156" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Chain of Custody" value="100%" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Evidence by Type</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Disk Images", v: "12", c: "text-cyan-400" }, { l: "Memory Dumps", v: "8", c: "text-emerald-400" }, { l: "Network Captures", v: "15", c: "text-yellow-400" }, { l: "Log Files", v: "12", c: "text-white/70" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "evidence_vault" && (<div className="space-y-3">{EVIDENCE.map((e) => (<div key={e.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{e.id}</span><span className="ml-2 text-xs text-white/40">{e.type}</span></div><StatusBadge status={e.status} /></div><p className="text-white/90 text-sm font-medium">{e.host}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>SHA256: {e.hash}</span><span>{e.size}</span><span className="text-emerald-400">Custody: {e.custody}</span></div></div>))}</div>)}
      {tab === "forensic_timeline" && (<div className="space-y-3">{TIMELINE.map((t, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div className="flex items-center gap-2"><Clock className="h-3.5 w-3.5 text-white/40" /><span className="font-mono text-xs text-white/60">{t.time}</span></div><StatusBadge status={t.severity} /></div><p className="text-white/90 text-sm">{t.event}</p><span className="text-xs text-cyan-400">{t.phase}</span></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Forensics Metrics</h3>{[{ m: "Avg Evidence Acquisition", v: "12 min", t: "-3 min" }, { m: "IOCs per Case", v: "52", t: "+8" }, { m: "Timeline Accuracy", v: "96%", t: "+2%" }, { m: "Cases Closed (30d)", v: "7", t: "+2" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
