import { useState } from "react";
import { Lock, Key, ShieldCheck, AlertTriangle } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "assets" | "keys" | "certificates";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "assets", label: "Encryption Assets" }, { id: "keys", label: "Key Rotation" }, { id: "certificates", label: "Certificate Health" }];
export default function DataEncryptionMonitor() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Data Encryption Monitor" subtitle="Encryption at rest and in transit - key rotation, certificate health, and gap detection" icon={<Lock className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Encryption Coverage" value="71.4%" icon={<ShieldCheck className="h-5 w-5" />} />
      <MetricCard title="Keys Tracked" value="3" icon={<Key className="h-5 w-5 text-cyan-400" />} />
      <MetricCard title="Certs Expiring" value="1" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Gaps Found" value="6" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Encryption Posture Summary</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {[{ label: "At Rest", encrypted: 3, total: 5 }, { label: "In Transit", encrypted: 2, total: 2 }, { label: "Key Rotation", healthy: 2, overdue: 1 }].map((s) => (
        <div key={s.label} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.label}</p>{"encrypted" in s ? (<><p className="text-cyan-400 text-2xl font-bold mt-1">{s.encrypted}/{s.total}</p><p className="text-xs text-white/40">assets encrypted</p></>) : (<><p className="text-yellow-400 text-2xl font-bold mt-1">{s.overdue} overdue</p><p className="text-xs text-white/40">{s.healthy} healthy</p></>)}</div>))}</div></div>)}
    {tab === "assets" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Asset</th><th className="px-4 py-3">Type</th><th className="px-4 py-3">Provider</th><th className="px-4 py-3">Algorithm</th><th className="px-4 py-3">Status</th></tr></thead>
      <tbody>{[
        { name: "prod-customer-db", type: "RDS", provider: "AWS", algo: "AES-256", status: "encrypted" },
        { name: "analytics-bucket", type: "S3", provider: "AWS", algo: "-", status: "unencrypted" },
        { name: "user-uploads-bucket", type: "S3", provider: "AWS", algo: "AES-256", status: "encrypted" },
        { name: "legacy-payments-db", type: "RDS", provider: "AWS", algo: "3DES", status: "weak" },
        { name: "api-gateway", type: "Service", provider: "AWS", algo: "TLS1.3", status: "encrypted" },
        { name: "internal-service-mesh", type: "Service", provider: "GCP", algo: "TLS1.1", status: "weak" },
        { name: "ml-training-data", type: "GCS", provider: "GCP", algo: "-", status: "unencrypted" },
      ].map((a, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90">{a.name}</td><td className="px-4 py-3 text-white/60">{a.type}</td><td className="px-4 py-3 text-white/60">{a.provider}</td><td className="px-4 py-3 font-mono text-xs text-white/70">{a.algo}</td><td className="px-4 py-3"><StatusBadge status={a.status} /></td></tr>))}</tbody></table></div>)}
    {tab === "keys" && (<div className="space-y-3">
      {[{ alias: "prod-customer-key", provider: "AWS KMS", algo: "AES-256", rotated: "95d ago", interval: "90d", status: "overdue", auto: true },
        { alias: "user-uploads-key", provider: "AWS KMS", algo: "AES-256", rotated: "45d ago", interval: "90d", status: "healthy", auto: true },
        { alias: "legacy-payments-key", provider: "AWS KMS", algo: "3DES", rotated: "450d ago", interval: "365d", status: "overdue", auto: false },
      ].map((k) => (<div key={k.alias} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-sm text-cyan-400">{k.alias}</span><span className="text-xs text-white/40 ml-2">{k.provider}</span></div><StatusBadge status={k.status} /></div>
        <p className="text-white/70 text-sm">Algorithm: {k.algo} | Last rotated: {k.rotated} | Interval: {k.interval}</p><p className="text-xs text-white/50">Auto-rotation: {k.auto ? "enabled" : "disabled"}</p></div>))}</div>)}
    {tab === "certificates" && (<div className="space-y-3">
      {[{ domain: "api.shieldops.io", issuer: "Let's Encrypt", expiry: "45d", keySize: "2048-bit", status: "valid", autoRenew: true },
        { domain: "dashboard.shieldops.io", issuer: "Let's Encrypt", expiry: "12d", keySize: "2048-bit", status: "expiring_soon", autoRenew: true },
        { domain: "internal.legacy.corp", issuer: "Self-Signed", expiry: "expired 30d", keySize: "1024-bit", status: "expired", autoRenew: false },
        { domain: "payments.corp.io", issuer: "DigiCert", expiry: "180d", keySize: "4096-bit", status: "valid", autoRenew: false },
      ].map((c) => (<div key={c.domain} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-sm text-cyan-400">{c.domain}</span><span className="text-xs text-white/40 ml-2">{c.issuer}</span></div><StatusBadge status={c.status} /></div>
        <p className="text-white/70 text-sm">Key: {c.keySize} | Expiry: {c.expiry}</p><p className="text-xs text-white/50">Auto-renew: {c.autoRenew ? "enabled" : "disabled"}</p></div>))}</div>)}
  </div>);
}
