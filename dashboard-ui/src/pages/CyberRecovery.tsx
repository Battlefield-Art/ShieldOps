import { useState } from "react";
import { RotateCcw, Shield, Clock, Database } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "recoveries" | "clean_room" | "metrics";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "recoveries", label: "Recoveries" }, { id: "clean_room", label: "Clean Room" }, { id: "metrics", label: "RTO/RPO" }];
export default function CyberRecovery() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Cyber Recovery" subtitle="Automated disaster recovery with clean room validation and ransomware-safe restore" icon={<RotateCcw className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Recovery Points" value="847" icon={<Database className="h-5 w-5" />} />
      <MetricCard title="Clean Room Validated" value="98.2%" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Actual RTO" value="12 min" icon={<Clock className="h-5 w-5 text-cyan-400" />} />
      <MetricCard title="RPO" value="15 min" icon={<Clock className="h-5 w-5 text-yellow-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Recovery Readiness</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {[{ label: "Systems Protected", count: 47, color: "text-emerald-400" }, { label: "Validated Clean", count: 44, color: "text-cyan-400" }, { label: "Needs Attention", count: 3, color: "text-yellow-400" }].map((s) => (
        <div key={s.label} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.label}</p><p className={clsx("text-3xl font-bold mt-1", s.color)}>{s.count}</p></div>))}</div></div>)}
    {tab === "recoveries" && (<div className="space-y-3">
      {[{ id: "REC-012", system: "Production Database", type: "full_restore", duration: "8 min", status: "completed", clean: true },
        { id: "REC-011", system: "K8s Cluster", type: "parallel_recovery", duration: "14 min", status: "completed", clean: true },
        { id: "REC-010", system: "File Server", type: "granular_restore", duration: "3 min", status: "completed", clean: true },
      ].map((r) => (<div key={r.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{r.id}</span>{r.clean && <span className="text-xs text-emerald-400 ml-2">CLEAN</span>}</div><StatusBadge status={r.status} /></div>
        <p className="text-white/90 font-medium">{r.system}</p><p className="text-xs text-white/50">Type: {r.type} | Duration: {r.duration}</p></div>))}</div>)}
    {tab === "clean_room" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Snapshot</th><th className="px-4 py-3">System</th><th className="px-4 py-3">Malware Scan</th><th className="px-4 py-3">Persistence</th><th className="px-4 py-3">Status</th></tr></thead>
      <tbody>{[
        { snap: "snap-2026-03-26-00", sys: "prod-db", malware: "clean", persist: "none", status: "validated" },
        { snap: "snap-2026-03-25-23", sys: "k8s-cluster", malware: "clean", persist: "none", status: "validated" },
        { snap: "snap-2026-03-25-22", sys: "file-server", malware: "suspicious", persist: "registry_key", status: "quarantined" },
      ].map((s, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 font-mono text-xs text-white/70">{s.snap}</td><td className="px-4 py-3 text-white/90">{s.sys}</td><td className="px-4 py-3"><StatusBadge status={s.malware} /></td><td className="px-4 py-3 text-white/60">{s.persist}</td><td className="px-4 py-3"><StatusBadge status={s.status} /></td></tr>))}</tbody></table></div>)}
    {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">RTO/RPO Performance</h3>
      {[{ sys: "Production Database", rto_target: "30 min", rto_actual: "8 min", rpo_target: "1h", rpo_actual: "15 min", status: "exceeds" },
        { sys: "K8s Cluster", rto_target: "1h", rto_actual: "14 min", rpo_target: "30 min", rpo_actual: "15 min", status: "exceeds" },
        { sys: "File Server", rto_target: "2h", rto_actual: "3 min", rpo_target: "4h", rpo_actual: "1h", status: "exceeds" },
      ].map((m, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{m.sys}</p><p className="text-xs text-white/50">RTO: {m.rto_actual} (target {m.rto_target}) | RPO: {m.rpo_actual} (target {m.rpo_target})</p></div><StatusBadge status={m.status} /></div>))}</div>)}
  </div>);
}
