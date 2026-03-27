import { useState } from "react";
import { HardDrive, Shield, AlertTriangle, CheckCircle, Lock, RefreshCw } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "infrastructure" | "vulnerabilities" | "hardening";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "infrastructure", label: "Infrastructure" }, { id: "vulnerabilities", label: "Vulnerabilities" }, { id: "hardening", label: "Hardening" }];
export default function BackupSecurityPosture() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Backup Security Posture" subtitle="Backup infrastructure security assessment and hardening" icon={<HardDrive className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Backup Systems" value="12" icon={<HardDrive className="h-5 w-5" />} />
      <MetricCard title="Posture Score" value="84%" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Vulnerabilities" value="7" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Recovery Tested" value="91%" icon={<RefreshCw className="h-5 w-5 text-cyan-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Backup Security by Component</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {[{ comp: "Storage Security", score: 89, issues: 2, color: "text-emerald-400" }, { comp: "Access Controls", score: 78, issues: 3, color: "text-yellow-400" }, { comp: "Encryption", score: 94, issues: 1, color: "text-emerald-400" }].map((c) => (
        <div key={c.comp} className="card-interactive p-4"><p className={clsx("font-bold", c.color)}>{c.comp}</p><p className="text-2xl font-bold text-white/80 mt-1">{c.score}%</p><p className="text-xs text-white/40">{c.issues} issues</p></div>))}</div></div>)}
    {tab === "infrastructure" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">System</th><th className="px-4 py-3">Type</th><th className="px-4 py-3">Encryption</th><th className="px-4 py-3">Last Test</th><th className="px-4 py-3">Status</th></tr></thead>
      <tbody>{[
        { sys: "S3 Vault", type: "Cloud Object", enc: "AES-256-GCM", test: "2h ago", status: "healthy" },
        { sys: "NFS Backup", type: "On-Prem", enc: "AES-256", test: "24h ago", status: "at_risk" },
        { sys: "K8s etcd Backup", type: "Container", enc: "AES-256-CBC", test: "4h ago", status: "healthy" },
        { sys: "AI Model Vault", type: "Cloud Object", enc: "AES-256-GCM", test: "1h ago", status: "healthy" },
      ].map((s, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90">{s.sys}</td><td className="px-4 py-3 text-white/60">{s.type}</td><td className="px-4 py-3 text-white/70">{s.enc}</td><td className="px-4 py-3 text-white/50">{s.test}</td><td className="px-4 py-3"><StatusBadge status={s.status} /></td></tr>))}</tbody></table></div>)}
    {tab === "vulnerabilities" && (<div className="space-y-3">
      {[{ id: "BSP-007", vuln: "NFS backup accessible without authentication", comp: "access_control", severity: "critical" },
        { id: "BSP-006", vuln: "Backup admin credentials not rotated in 180 days", comp: "access_control", severity: "high" },
        { id: "BSP-005", vuln: "No immutability lock on S3 backup bucket", comp: "storage", severity: "high" },
      ].map((v) => (<div key={v.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{v.id}</span><span className="text-xs text-white/40 ml-2">{v.comp}</span></div><StatusBadge status={v.severity} /></div>
        <p className="text-white/90 font-medium">{v.vuln}</p></div>))}</div>)}
    {tab === "hardening" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Hardening Recommendations</h3>
      {[{ rec: "Enable MFA for all backup admin accounts", priority: "critical", effort: "Low", status: "pending" },
        { rec: "Enable S3 Object Lock on backup buckets", priority: "high", effort: "Medium", status: "in_progress" },
        { rec: "Implement network segmentation for backup VLAN", priority: "high", effort: "High", status: "pending" },
        { rec: "Schedule automated recovery tests weekly", priority: "medium", effort: "Low", status: "completed" },
      ].map((h, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{h.rec}</p><p className="text-xs text-white/50">{h.priority} | Effort: {h.effort}</p></div><StatusBadge status={h.status} /></div>))}</div>)}
  </div>);
}
