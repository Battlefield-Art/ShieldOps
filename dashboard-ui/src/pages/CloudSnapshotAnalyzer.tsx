import { useState } from "react";
import { HardDrive, Lock, Globe, AlertTriangle } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "snapshot_inventory" | "exposure_findings" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "snapshot_inventory", label: "Snapshot Inventory" },
  { id: "exposure_findings", label: "Exposure Findings" },
  { id: "metrics", label: "Metrics" },
];

const SNAPSHOTS = [
  { id: "snap-0a1b2c3d", type: "EBS Volume", region: "us-east-1", size: "500 GB", age: "142 days", encrypted: true, exposed: false, status: "compliant" },
  { id: "snap-4e5f6a7b", type: "RDS Snapshot", region: "us-west-2", size: "1.2 TB", age: "89 days", encrypted: false, exposed: false, status: "warning" },
  { id: "snap-8c9d0e1f", type: "EBS Volume", region: "eu-west-1", size: "250 GB", age: "203 days", encrypted: true, exposed: true, status: "critical" },
  { id: "snap-2a3b4c5d", type: "AMI", region: "us-east-1", size: "80 GB", age: "312 days", encrypted: false, exposed: true, status: "critical" },
  { id: "snap-6e7f8a9b", type: "Disk Snapshot", region: "gcp-us-central1", size: "200 GB", age: "45 days", encrypted: true, exposed: false, status: "compliant" },
];

const FINDINGS = [
  { id: "EXP-001", snapshot: "snap-8c9d0e1f", type: "Public Access", severity: "critical", detail: "Snapshot shared with all AWS accounts via CreateVolumePermission" },
  { id: "EXP-002", snapshot: "snap-2a3b4c5d", type: "Public AMI", severity: "critical", detail: "AMI publicly launchable, contains unencrypted root volume" },
  { id: "EXP-003", snapshot: "snap-4e5f6a7b", type: "No Encryption", severity: "high", detail: "RDS snapshot without encryption at rest, contains PII data" },
];

export default function CloudSnapshotAnalyzer() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Cloud Snapshot Analyzer" subtitle="Cloud snapshot and backup security analysis across AWS, GCP, Azure" icon={<HardDrive className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Total Snapshots" value="2,847" icon={<HardDrive className="h-5 w-5" />} />
        <MetricCard title="Unencrypted" value="124" icon={<Lock className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Publicly Exposed" value="8" icon={<Globe className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Stale (>90d)" value="342" icon={<AlertTriangle className="h-5 w-5 text-white/70" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Snapshot Health by Provider</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">{[{ l: "AWS", v: "1,842", c: "text-cyan-400", sub: "94 unencrypted" }, { l: "GCP", v: "612", c: "text-emerald-400", sub: "18 unencrypted" }, { l: "Azure", v: "393", c: "text-blue-400", sub: "12 unencrypted" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p><p className="text-xs text-white/40 mt-1">{s.sub}</p></div>))}</div></div>)}
      {tab === "snapshot_inventory" && (<div className="space-y-3">{SNAPSHOTS.map((s) => (<div key={s.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{s.id}</span><span className="ml-2 text-xs text-white/40">{s.type}</span></div><StatusBadge status={s.status} /></div><div className="flex gap-4 mt-1 text-xs text-white/50"><span>{s.region}</span><span>{s.size}</span><span>{s.age}</span><span>{s.encrypted ? <Lock className="inline h-3 w-3 text-emerald-400" /> : <Lock className="inline h-3 w-3 text-red-400" />} {s.encrypted ? "Encrypted" : "Unencrypted"}</span>{s.exposed && <span className="text-red-400"><Globe className="inline h-3 w-3" /> Public</span>}</div></div>))}</div>)}
      {tab === "exposure_findings" && (<div className="space-y-3">{FINDINGS.map((f) => (<div key={f.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{f.id}</span><span className="ml-2 text-xs text-white/40">{f.snapshot}</span></div><StatusBadge status={f.severity} /></div><p className="text-white/90 text-sm">{f.detail}</p><span className="text-xs text-white/50">{f.type}</span></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Snapshot Security Metrics</h3>{[{ m: "Encryption Coverage", v: "95.6%", t: "+2.1%" }, { m: "Stale Cleanup Rate", v: "78%", t: "+12%" }, { m: "Public Exposure", v: "0.3%", t: "-0.1%" }, { m: "Monthly Cost Savings", v: "$4,280", t: "+$820" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
