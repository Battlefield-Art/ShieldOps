import { useState } from "react";
import { Lock, AlertTriangle, CheckCircle, Clock, RefreshCw } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "certs" | "expiring" | "rotations";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "certs", label: "Certificates" }, { id: "expiring", label: "Expiring" }, { id: "rotations", label: "Rotations" }];
export default function CertificateManager() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Certificate Manager" subtitle="TLS certificate lifecycle, expiry alerts, and automated rotation" icon={<Lock className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Certificates" value="142" icon={<Lock className="h-5 w-5" />} />
      <MetricCard title="Expiring (<30d)" value="5" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Auto-Renewable" value="89%" icon={<RefreshCw className="h-5 w-5" />} />
      <MetricCard title="Chain Valid" value="98%" icon={<CheckCircle className="h-5 w-5" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Certificate Health</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {[{ label: "Valid", count: 134, color: "text-emerald-400" }, { label: "Expiring Soon", count: 5, color: "text-yellow-400" }, { label: "Expired/Revoked", count: 3, color: "text-red-400" }].map((s) => (
        <div key={s.label} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.label}</p><p className={clsx("text-3xl font-bold mt-1", s.color)}>{s.count}</p></div>))}</div></div>)}
    {tab === "certs" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Domain</th><th className="px-4 py-3">Issuer</th><th className="px-4 py-3">Expires</th><th className="px-4 py-3">Key</th><th className="px-4 py-3">Auto</th><th className="px-4 py-3">Status</th></tr></thead>
      <tbody>{[
        { domain: "*.shieldops.io", issuer: "Let's Encrypt", exp: "82d", key: "EC-256", auto: true, status: "valid" },
        { domain: "api.shieldops.io", issuer: "DigiCert", exp: "12d", key: "RSA-2048", auto: false, status: "expiring" },
        { domain: "dashboard.shieldops.io", issuer: "Let's Encrypt", exp: "45d", key: "EC-256", auto: true, status: "valid" },
      ].map((c, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 font-mono text-xs text-cyan-400">{c.domain}</td><td className="px-4 py-3 text-white/70">{c.issuer}</td><td className="px-4 py-3 text-white/80">{c.exp}</td><td className="px-4 py-3 text-white/60">{c.key}</td><td className="px-4 py-3">{c.auto ? <CheckCircle className="h-4 w-4 text-emerald-400" /> : <Clock className="h-4 w-4 text-yellow-400" />}</td><td className="px-4 py-3"><StatusBadge status={c.status} /></td></tr>))}</tbody></table></div>)}
    {tab === "expiring" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Certificates Expiring Within 30 Days</h3>
      {[{ domain: "api.shieldops.io", days: 12, action: "Manual renewal required" },
        { domain: "internal-mcp.local", days: 8, action: "Auto-renewal scheduled" },
      ].map((e, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium font-mono">{e.domain}</p><p className="text-xs text-white/50">{e.action}</p></div><span className="text-red-400 font-bold">{e.days}d</span></div>))}</div>)}
    {tab === "rotations" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Recent Rotations</h3>
      {[{ domain: "*.shieldops.io", method: "ACME auto-renewal", when: "3 days ago", status: "completed" },
        { domain: "vault-internal.local", method: "Vault PKI", when: "1 week ago", status: "completed" },
      ].map((r, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{r.domain}</p><p className="text-xs text-white/50">{r.method} | {r.when}</p></div><StatusBadge status={r.status} /></div>))}</div>)}
  </div>);
}
