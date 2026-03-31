import { useState } from "react";
import { FileSearch, Cloud, Shield, AlertTriangle, Database, Lock } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "evidence_collection" | "forensic_analysis" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "evidence_collection", label: "Evidence Collection" },
  { id: "forensic_analysis", label: "Forensic Analysis" },
  { id: "metrics", label: "Metrics" },
];

const EVIDENCE = [
  { id: "EVD-001", type: "CloudTrail Logs", provider: "AWS", records: 24500, size: "1.2 GB", status: "preserved", integrity: true },
  { id: "EVD-002", type: "Disk Snapshot", provider: "AWS", records: 1, size: "50 GB", status: "capturing", integrity: true },
  { id: "EVD-003", type: "GCP Audit Logs", provider: "GCP", records: 8200, size: "420 MB", status: "preserved", integrity: true },
  { id: "EVD-004", type: "Azure Activity", provider: "Azure", records: 5600, size: "310 MB", status: "collecting", integrity: true },
  { id: "EVD-005", type: "Memory Dump", provider: "AWS", records: 1, size: "16 GB", status: "preserved", integrity: true },
];

const FINDINGS = [
  { id: "IOC-001", type: "Suspicious API Call", detail: "AssumeRole from unknown IP 198.51.100.42", severity: "critical", provider: "AWS" },
  { id: "IOC-002", type: "Data Exfiltration", detail: "Large S3 GetObject from compromised role", severity: "high", provider: "AWS" },
  { id: "IOC-003", type: "Persistence", detail: "IAM user created with admin policy", severity: "critical", provider: "AWS" },
];

export default function CloudForensicsCollector() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Cloud Forensics Collector" subtitle="Cloud-native forensics evidence collection and analysis" icon={<FileSearch className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Active Cases" value="3" icon={<FileSearch className="h-5 w-5" />} />
        <MetricCard title="Evidence Items" value="47" icon={<Database className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="IOCs Found" value="12" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Chain of Custody" value="100%" icon={<Lock className="h-5 w-5 text-emerald-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Evidence by Provider</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "AWS", v: "28", c: "text-yellow-400" }, { l: "GCP", v: "11", c: "text-cyan-400" }, { l: "Azure", v: "6", c: "text-blue-400" }, { l: "Multi-Cloud", v: "2", c: "text-white/70" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "evidence_collection" && (<div className="space-y-3">{EVIDENCE.map((e) => (<div key={e.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{e.id}</span><span className="ml-2 text-xs text-white/40">{e.type}</span></div><StatusBadge status={e.status} /></div><div className="flex gap-4 mt-2 text-xs text-white/50"><span>Provider: {e.provider}</span><span>{e.records.toLocaleString()} records</span><span>{e.size}</span><span className={e.integrity ? "text-emerald-400" : "text-red-400"}>Integrity: {e.integrity ? "Valid" : "Failed"}</span></div></div>))}</div>)}
      {tab === "forensic_analysis" && (<div className="space-y-3">{FINDINGS.map((f) => (<div key={f.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{f.id}</span><span className="ml-2 text-xs text-white/40">{f.type}</span></div><StatusBadge status={f.severity} /></div><p className="text-white/90 text-sm">{f.detail}</p><span className="text-xs text-white/40">Provider: {f.provider}</span></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Forensics Metrics</h3>{[{ m: "Avg Collection Time", v: "18 min", t: "-4 min" }, { m: "Evidence Integrity Rate", v: "100%", t: "Maintained" }, { m: "IOC Detection Rate", v: "87%", t: "+5%" }, { m: "Cases Closed (30d)", v: "8", t: "+2" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
