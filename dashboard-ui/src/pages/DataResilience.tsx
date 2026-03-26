import { useState } from "react";
import { HardDrive, Lock, Shield, AlertTriangle, CheckCircle, Database } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "assets" | "protection" | "anomalies";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "assets", label: "Data Assets" }, { id: "protection", label: "Protection" }, { id: "anomalies", label: "Anomalies" }];
export default function DataResilience() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Data Resilience" subtitle="Immutable data protection with continuous observability — databases, cloud, AI models" icon={<HardDrive className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Data Assets" value="127" icon={<Database className="h-5 w-5" />} />
      <MetricCard title="Immutable" value="89%" icon={<Lock className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Anomalies (7d)" value="3" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Resilience Score" value="94.2%" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Protection by Asset Type</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">
      {[{ type: "Databases", count: 23, protected: "100%", color: "text-emerald-400" }, { type: "Object Storage", count: 45, protected: "91%", color: "text-cyan-400" }, { type: "AI Models", count: 18, protected: "83%", color: "text-yellow-400" }, { type: "Config/Secrets", count: 41, protected: "88%", color: "text-cyan-400" }].map((a) => (
        <div key={a.type} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{a.type}</p><p className={clsx("text-3xl font-bold mt-1", a.color)}>{a.protected}</p><p className="text-xs text-white/40">{a.count} assets</p></div>))}</div></div>)}
    {tab === "assets" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Asset</th><th className="px-4 py-3">Type</th><th className="px-4 py-3">Protection</th><th className="px-4 py-3">Last Verified</th><th className="px-4 py-3">Status</th></tr></thead>
      <tbody>{[
        { asset: "prod-customer-db", type: "Database", protection: "immutable", verified: "5 min ago", status: "protected" },
        { asset: "s3-data-lake", type: "Object Storage", protection: "versioned", verified: "15 min ago", status: "protected" },
        { asset: "claude-fine-tune-v3", type: "AI Model", protection: "immutable", verified: "1h ago", status: "protected" },
        { asset: "rag-index-prod", type: "RAG Index", protection: "unprotected", verified: "Never", status: "at_risk" },
      ].map((a, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90 font-medium">{a.asset}</td><td className="px-4 py-3 text-white/60">{a.type}</td><td className="px-4 py-3"><StatusBadge status={a.protection} /></td><td className="px-4 py-3 text-white/50">{a.verified}</td><td className="px-4 py-3"><StatusBadge status={a.status} /></td></tr>))}</tbody></table></div>)}
    {tab === "protection" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Immutability Enforcements</h3>
      {[{ asset: "prod-customer-db", enforcement: "Object Lock (WORM)", retention: "365 days", compliance: "SOC 2, HIPAA", status: "enforced" },
        { asset: "s3-data-lake", enforcement: "S3 Object Lock + Versioning", retention: "90 days", compliance: "PCI DSS", status: "enforced" },
        { asset: "claude-fine-tune-v3", enforcement: "Checksum + Signed Hash", retention: "Permanent", compliance: "Internal", status: "enforced" },
      ].map((p, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{p.asset}</p><p className="text-xs text-white/50">{p.enforcement} | Retention: {p.retention} | {p.compliance}</p></div><StatusBadge status={p.status} /></div>))}</div>)}
    {tab === "anomalies" && (<div className="space-y-3">
      {[{ id: "ANM-003", asset: "rag-index-prod", type: "Unexpected modification", detail: "RAG index modified outside deployment window", severity: "high" },
        { id: "ANM-002", asset: "config-vault", type: "Deletion attempt", detail: "Attempted deletion of secrets by unknown SA", severity: "critical" },
        { id: "ANM-001", asset: "training-data-v2", type: "Encryption event", detail: "Training dataset encrypted by non-standard process", severity: "critical" },
      ].map((a) => (<div key={a.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{a.id}</span><span className="text-xs text-white/40 ml-2">{a.asset}</span></div><StatusBadge status={a.severity} /></div>
        <p className="text-white/90 font-medium">{a.type}</p><p className="text-xs text-white/50">{a.detail}</p></div>))}</div>)}
  </div>);
}
