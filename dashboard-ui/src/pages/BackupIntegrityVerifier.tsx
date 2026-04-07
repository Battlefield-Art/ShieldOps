import { useState } from "react";
import { HardDrive, Shield, CheckCircle, AlertTriangle } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "backup_status" | "integrity_checks" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "backup_status", label: "Backup Status" },
  { id: "integrity_checks", label: "Integrity Checks" },
  { id: "metrics", label: "Metrics" },
];

const BACKUPS = [
  { name: "prod-db-daily", target: "PostgreSQL", lastRun: "2h ago", size: "142 GB", status: "verified" },
  { name: "k8s-etcd-hourly", target: "etcd", lastRun: "45m ago", size: "8.2 GB", status: "verified" },
  { name: "s3-critical-weekly", target: "S3 Buckets", lastRun: "3d ago", size: "2.1 TB", status: "warning" },
  { name: "vault-secrets-daily", target: "Vault", lastRun: "6h ago", size: "340 MB", status: "verified" },
  { name: "config-maps-daily", target: "ConfigMaps", lastRun: "1d ago", size: "12 MB", status: "failed" },
];

export default function BackupIntegrityVerifier() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Backup Integrity Verifier" subtitle="Backup verification and integrity checking" icon={<HardDrive className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Total Backups" value="89" icon={<HardDrive className="h-5 w-5" />} />
        <MetricCard title="Verified" value="82" icon={<CheckCircle className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Integrity Issues" value="4" icon={<AlertTriangle className="h-5 w-5 text-orange-400" />} />
        <MetricCard title="Restore Tested" value="76%" icon={<Shield className="h-5 w-5 text-cyan-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Backup Health</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Verified", v: "82", c: "text-emerald-400" }, { l: "Pending", v: "3", c: "text-yellow-400" }, { l: "Warning", v: "3", c: "text-orange-400" }, { l: "Failed", v: "1", c: "text-red-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "backup_status" && (<div className="space-y-3">{BACKUPS.map((b) => (<div key={b.name} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="text-white/90 font-medium font-mono text-sm">{b.name}</span><span className="ml-2 text-xs text-white/40">{b.target}</span></div><StatusBadge status={b.status === "verified" ? "healthy" : b.status === "warning" ? "warning" : "critical"} /></div><div className="flex gap-4 text-xs text-white/40"><span>Last: {b.lastRun}</span><span>Size: {b.size}</span></div></div>))}</div>)}
      {tab === "integrity_checks" && (<div className="card-surface p-6"><h3 className="section-heading">Recent Integrity Checks</h3><div className="space-y-2">{[{ backup: "prod-db-daily", check: "SHA-256 hash verified", result: "pass" }, { backup: "k8s-etcd-hourly", check: "Restore test completed", result: "pass" }, { backup: "s3-critical-weekly", check: "Encryption key rotation overdue", result: "warning" }, { backup: "config-maps-daily", check: "Checksum mismatch detected", result: "fail" }].map((c, i) => (<div key={i} className="card-interactive p-3 flex items-center justify-between text-sm"><div><span className="text-white/70 font-mono">{c.backup}</span><span className="text-white/40 ml-2">— {c.check}</span></div><StatusBadge status={c.result === "pass" ? "healthy" : c.result === "warning" ? "medium" : "critical"} /></div>))}</div></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Backup Metrics</h3>{[{ m: "Integrity Score", v: "94.4%", t: "+1.2% vs last week" }, { m: "RPO Compliance", v: "97%", t: "3 backups overdue" }, { m: "RTO Validated", v: "89%", t: "avg restore: 12 min" }, { m: "Encryption Coverage", v: "100%", t: "AES-256 + KMS" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
