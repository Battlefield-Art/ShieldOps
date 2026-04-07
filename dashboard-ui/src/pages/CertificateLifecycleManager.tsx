import { useState } from "react";
import { Shield, Lock, AlertTriangle, RefreshCw, Clock } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "certificates" | "renewals" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "certificates", label: "Certificates" },
  { id: "renewals", label: "Renewals" },
  { id: "metrics", label: "Metrics" },
];

const CERTS = [
  { cn: "*.shieldops.io", type: "Wildcard", issuer: "Let's Encrypt", expiry: "2026-06-15", status: "valid", days: 77 },
  { cn: "api.shieldops.io", type: "TLS Server", issuer: "DigiCert", expiry: "2026-04-15", status: "expiring_soon", days: 16 },
  { cn: "internal.corp.co", type: "CA Intermediate", issuer: "Internal CA", expiry: "2026-12-01", status: "valid", days: 246 },
  { cn: "legacy.app.co", type: "Self-Signed", issuer: "Self", expiry: "2026-03-25", status: "expired", days: -5 },
  { cn: "code-sign.shieldops.io", type: "Code Signing", issuer: "Sectigo", expiry: "2027-01-01", status: "valid", days: 277 },
];

export default function CertificateLifecycleManager() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Certificate Lifecycle Manager" subtitle="TLS/SSL certificate discovery, monitoring, and auto-renewal" icon={<Lock className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Certificates" value="234" icon={<Shield className="h-5 w-5" />} />
        <MetricCard title="Expiring (30d)" value="7" icon={<Clock className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Expired" value="2" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Auto-Renewed" value="89%" icon={<RefreshCw className="h-5 w-5 text-emerald-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Certificate Health</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Valid", v: "225", c: "text-emerald-400" }, { l: "Expiring", v: "7", c: "text-yellow-400" }, { l: "Expired", v: "2", c: "text-red-400" }, { l: "Misconfig", v: "3", c: "text-orange-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "certificates" && (<div className="space-y-3">{CERTS.map((c) => (<div key={c.cn} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><span className="text-white/90 font-medium font-mono text-sm">{c.cn}</span><StatusBadge status={c.status} /></div><div className="flex gap-4 text-sm text-white/50"><span>{c.type}</span><span>Issuer: {c.issuer}</span><span>Expires: {c.expiry}</span><span className={c.days < 0 ? "text-red-400" : c.days < 30 ? "text-yellow-400" : "text-emerald-400"}>{c.days < 0 ? `Expired ${-c.days}d ago` : `${c.days}d remaining`}</span></div></div>))}</div>)}
      {tab === "renewals" && (<div className="card-surface p-6"><h3 className="section-heading">Recent Renewals</h3><div className="space-y-2">{[{ cn: "cdn.shieldops.io", time: "2h ago", method: "ACME auto-renewal", status: "success" }, { cn: "mail.shieldops.io", time: "1d ago", method: "ACME auto-renewal", status: "success" }, { cn: "vpn.corp.co", time: "3d ago", method: "Manual renewal", status: "success" }].map((r, i) => (<div key={i} className="card-interactive p-3 flex items-center justify-between text-sm"><span className="text-white/90 font-mono">{r.cn}</span><div className="flex gap-3 text-white/50"><span>{r.method}</span><span>{r.time}</span><StatusBadge status={r.status} /></div></div>))}</div></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Lifecycle Trends</h3>{[{ m: "Auto-Renewal Rate", v: "89%", t: "+5%" }, { m: "Avg Cert Age", v: "142 days", t: "Healthy range" }, { m: "Compliance Score", v: "96%", t: "+2%" }, { m: "Outage Prevention", v: "100%", t: "0 cert-related outages" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
