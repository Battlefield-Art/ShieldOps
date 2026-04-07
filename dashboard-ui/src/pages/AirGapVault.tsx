import { useState } from "react";
import { Lock, Shield, Database, AlertTriangle, CheckCircle } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "assets" | "integrity" | "retention";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "assets", label: "Vault Assets" }, { id: "integrity", label: "Integrity" }, { id: "retention", label: "Retention" }];
export default function AirGapVault() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Air-Gap Vault" subtitle="Air-gapped data vault with continuous integrity verification — backups, AI models, configs" icon={<Lock className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Vault Assets" value="234" icon={<Database className="h-5 w-5" />} />
      <MetricCard title="Isolation Verified" value="100%" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Integrity" value="99.8%" icon={<CheckCircle className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Tamper Alerts" value="1" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Vault Health</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {[{ label: "Full Air-Gap", count: 89, color: "text-emerald-400" }, { label: "Logical Air-Gap", count: 112, color: "text-cyan-400" }, { label: "Network Isolated", count: 33, color: "text-yellow-400" }].map((v) => (
        <div key={v.label} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{v.label}</p><p className={clsx("text-3xl font-bold mt-1", v.color)}>{v.count}</p></div>))}</div></div>)}
    {tab === "assets" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Asset</th><th className="px-4 py-3">Type</th><th className="px-4 py-3">Isolation</th><th className="px-4 py-3">Integrity</th><th className="px-4 py-3">Last Check</th></tr></thead>
      <tbody>{[
        { asset: "prod-db-backup-daily", type: "Database", isolation: "full_air_gap", integrity: "verified", check: "1h ago" },
        { asset: "claude-ft-weights-v3", type: "AI Model", isolation: "full_air_gap", integrity: "verified", check: "2h ago" },
        { asset: "rag-index-snapshot", type: "RAG Index", isolation: "logical_air_gap", integrity: "verified", check: "4h ago" },
        { asset: "terraform-state-vault", type: "Config", isolation: "network_isolated", integrity: "degraded", check: "30m ago" },
      ].map((a, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90 font-medium">{a.asset}</td><td className="px-4 py-3 text-white/60">{a.type}</td><td className="px-4 py-3"><StatusBadge status={a.isolation} /></td><td className="px-4 py-3"><StatusBadge status={a.integrity} /></td><td className="px-4 py-3 text-white/50">{a.check}</td></tr>))}</tbody></table></div>)}
    {tab === "integrity" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Integrity Verification Chain</h3>
      {[{ asset: "prod-db-backup-daily", hash: "SHA-256: a4e8f2c1...d7b3", chain: "234 blocks verified", status: "verified" },
        { asset: "claude-ft-weights-v3", hash: "SHA-256: b7c1d3a9...e4f1", chain: "12 blocks verified", status: "verified" },
        { asset: "terraform-state-vault", hash: "SHA-256: MISMATCH", chain: "Block 8 failed", status: "tampered" },
      ].map((v, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{v.asset}</p><p className="text-xs text-white/50 font-mono">{v.hash} | {v.chain}</p></div><StatusBadge status={v.status} /></div>))}</div>)}
    {tab === "retention" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Retention Policies</h3>
      {[{ asset: "prod-db-backup-daily", policy: "365 days WORM", compliance: "SOC 2, HIPAA", hold: "None", status: "active" },
        { asset: "claude-ft-weights-v3", policy: "Permanent immutable", compliance: "Internal", hold: "None", status: "active" },
        { asset: "audit-logs-2025", policy: "7 years WORM", compliance: "SEC 17a-4", hold: "Legal hold active", status: "locked" },
      ].map((r, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{r.asset}</p><p className="text-xs text-white/50">{r.policy} | {r.compliance} | {r.hold}</p></div><StatusBadge status={r.status} /></div>))}</div>)}
  </div>);
}
