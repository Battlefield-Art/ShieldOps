import { useState } from "react";
import { Database, Shield, CheckCircle, AlertTriangle, Clock } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "backups" | "recovery" | "gaps";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "backups", label: "Backup Inventory" }, { id: "recovery", label: "Recovery Tests" }, { id: "gaps", label: "Gaps" }];
export default function BackupValidator() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Backup Validator" subtitle="Backup integrity validation and recovery testing" icon={<Database className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Backups Tracked" value="86" icon={<Database className="h-5 w-5" />} />
      <MetricCard title="Verified (7d)" value="72" icon={<CheckCircle className="h-5 w-5" />} />
      <MetricCard title="Recovery Success" value="94%" icon={<Shield className="h-5 w-5" />} />
      <MetricCard title="Gaps Found" value="3" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Backup Health</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {[{ label: "Verified", count: 72, color: "text-emerald-400" }, { label: "Unverified", count: 11, color: "text-yellow-400" }, { label: "Failed/Corrupt", count: 3, color: "text-red-400" }].map((s) => (
        <div key={s.label} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.label}</p><p className={clsx("text-3xl font-bold mt-1", s.color)}>{s.count}</p></div>))}</div></div>)}
    {tab === "backups" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Service</th><th className="px-4 py-3">Type</th><th className="px-4 py-3">Size</th><th className="px-4 py-3">Age</th><th className="px-4 py-3">Encrypted</th><th className="px-4 py-3">Verified</th></tr></thead>
      <tbody>{[
        { svc: "postgres-primary", type: "Full", size: "42 GB", age: "4h", enc: true, ver: true },
        { svc: "redis-cluster", type: "Snapshot", size: "8 GB", age: "2h", enc: true, ver: true },
        { svc: "elasticsearch", type: "Incremental", size: "120 GB", age: "1d", enc: false, ver: false },
      ].map((b, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-cyan-400 font-mono text-sm">{b.svc}</td><td className="px-4 py-3 text-white/70">{b.type}</td><td className="px-4 py-3 text-white/80">{b.size}</td><td className="px-4 py-3 text-white/60">{b.age}</td><td className="px-4 py-3">{b.enc ? <CheckCircle className="h-4 w-4 text-emerald-400" /> : <AlertTriangle className="h-4 w-4 text-red-400" />}</td><td className="px-4 py-3">{b.ver ? <CheckCircle className="h-4 w-4 text-emerald-400" /> : <Clock className="h-4 w-4 text-yellow-400" />}</td></tr>))}</tbody></table></div>)}
    {tab === "recovery" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Recent Recovery Tests</h3>
      {[{ svc: "postgres-primary", time: "8.4 min", loss: false, status: "success" },
        { svc: "redis-cluster", time: "2.1 min", loss: false, status: "success" },
        { svc: "elasticsearch", time: "45 min", loss: true, status: "partial" },
      ].map((r, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{r.svc}</p><p className="text-xs text-white/50">Recovery: {r.time} | Data loss: {r.loss ? "Yes" : "No"}</p></div><StatusBadge status={r.status} /></div>))}</div>)}
    {tab === "gaps" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Backup Gaps</h3>
      {[{ gap: "Elasticsearch backup not encrypted", sev: "high", fix: "Enable encryption at rest" },
        { gap: "No offsite backup for postgres-primary", sev: "medium", fix: "Configure cross-region replication" },
      ].map((g, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{g.gap}</p><p className="text-xs text-cyan-400">{g.fix}</p></div><StatusBadge status={g.sev} /></div>))}</div>)}
  </div>);
}
