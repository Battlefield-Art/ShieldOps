import { useState } from "react";
import { FileSearch, Shield, Database, Lock, CheckCircle, Clock } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "artifacts" | "chain" | "packages";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "artifacts", label: "Artifacts" }, { id: "chain", label: "Chain of Custody" }, { id: "packages", label: "Evidence Packages" }];
export default function EvidenceCollector() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Evidence Collector" subtitle="Auto-collect forensic evidence — memory, logs, configs, chain of custody" icon={<FileSearch className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Artifacts Collected" value="234" icon={<Database className="h-5 w-5" />} />
      <MetricCard title="Integrity Verified" value="100%" icon={<CheckCircle className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Packages Ready" value="8" icon={<Shield className="h-5 w-5 text-cyan-400" />} />
      <MetricCard title="Collection Time" value="3.2 min" icon={<Clock className="h-5 w-5 text-cyan-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Evidence by Type</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {[{ type: "Log Files", count: 89, size: "2.3 GB", color: "text-cyan-400" }, { type: "Config Snapshots", count: 67, size: "145 MB", color: "text-emerald-400" }, { type: "Network Captures", count: 23, size: "890 MB", color: "text-yellow-400" }].map((e) => (
        <div key={e.type} className="card-interactive p-4"><p className={clsx("font-bold", e.color)}>{e.type}</p><p className="text-2xl font-bold text-white/80 mt-1">{e.count}</p><p className="text-xs text-white/40">{e.size}</p></div>))}</div></div>)}
    {tab === "artifacts" && (<div className="space-y-3">
      {[{ id: "EVD-234", type: "CloudTrail logs", source: "AWS us-east-1", hash: "sha256:a4e8...", integrity: "verified" },
        { id: "EVD-233", type: "Okta system log", source: "Okta tenant", hash: "sha256:b7c1...", integrity: "verified" },
        { id: "EVD-232", type: "VPC flow logs", source: "AWS VPC", hash: "sha256:c9d2...", integrity: "verified" },
      ].map((a) => (<div key={a.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{a.id}</span><span className="text-xs text-white/40 ml-2">{a.source}</span></div><StatusBadge status={a.integrity} /></div>
        <p className="text-white/90 font-medium">{a.type}</p><p className="text-xs text-white/50 font-mono">{a.hash}</p></div>))}</div>)}
    {tab === "chain" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Chain of Custody</h3>
      {[{ action: "Collected", by: "evidence_collector agent", time: "14:37 UTC", hash: "sha256:a4e8..." },
        { action: "Verified integrity", by: "evidence_collector agent", time: "14:38 UTC", hash: "Match confirmed" },
        { action: "Packaged", by: "evidence_collector agent", time: "14:39 UTC", hash: "Package EVP-008" },
        { action: "Stored (immutable)", by: "air_gap_vault agent", time: "14:40 UTC", hash: "WORM locked" },
      ].map((c, i) => (<div key={i} className="card-interactive p-3 flex items-center gap-4"><span className="text-cyan-400 font-mono text-xs w-16">{c.time}</span><div><p className="text-white/80 text-sm">{c.action}</p><p className="text-xs text-white/40">{c.by} | {c.hash}</p></div></div>))}</div>)}
    {tab === "packages" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Package</th><th className="px-4 py-3">Incident</th><th className="px-4 py-3">Artifacts</th><th className="px-4 py-3">Size</th><th className="px-4 py-3">Status</th></tr></thead>
      <tbody>{[
        { pkg: "EVP-008", incident: "IR-089", artifacts: 45, size: "1.2 GB", status: "sealed" },
        { pkg: "EVP-007", incident: "IR-088", artifacts: 23, size: "340 MB", status: "sealed" },
        { pkg: "EVP-006", incident: "IR-087", artifacts: 67, size: "2.1 GB", status: "sealed" },
      ].map((p, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 font-mono text-cyan-400">{p.pkg}</td><td className="px-4 py-3 text-white/90">{p.incident}</td><td className="px-4 py-3 text-white/80">{p.artifacts}</td><td className="px-4 py-3 text-white/60">{p.size}</td><td className="px-4 py-3"><StatusBadge status={p.status} /></td></tr>))}</tbody></table></div>)}
  </div>);
}
