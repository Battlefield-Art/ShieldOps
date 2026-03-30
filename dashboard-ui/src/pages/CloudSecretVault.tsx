import { useState } from "react";
import { KeyRound, Shield, AlertTriangle, RefreshCw, Eye, BarChart3 } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "secrets_inventory" | "rotation_status" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "secrets_inventory", label: "Secrets Inventory" },
  { id: "rotation_status", label: "Rotation Status" },
  { id: "metrics", label: "Metrics" },
];

const SECRETS = [
  { name: "prod/db/postgres_main", type: "Database", vault: "AWS Secrets Manager", risk: "critical", detail: "Not rotated in 187 days, accessed by 12 services" },
  { name: "api/stripe_live_key", type: "API Key", vault: "HashiCorp Vault", risk: "high", detail: "Found in application logs, rotation overdue by 45 days" },
  { name: "infra/ssh/deploy_key", type: "SSH Key", vault: "Unmanaged", risk: "high", detail: "Not stored in any vault, shared across 3 teams" },
  { name: "auth/oauth/client_secret", type: "OAuth Token", vault: "Azure Key Vault", risk: "medium", detail: "Rotation compliant, single service access" },
  { name: "tls/wildcard_cert", type: "TLS Certificate", vault: "AWS ACM", risk: "low", detail: "Auto-renewed, 45 days until expiry" },
];

export default function CloudSecretVault() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Cloud Secret Vault" subtitle="Secret lifecycle management and exposure detection" icon={<KeyRound className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Total Secrets" value="342" icon={<KeyRound className="h-5 w-5" />} />
        <MetricCard title="Rotation Overdue" value="28" icon={<RefreshCw className="h-5 w-5 text-orange-400" />} />
        <MetricCard title="Exposed Secrets" value="5" icon={<Eye className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Unmanaged" value="14" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Vault Distribution</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "AWS Secrets Manager", v: "156", c: "text-orange-400" }, { l: "HashiCorp Vault", v: "98", c: "text-cyan-400" }, { l: "Azure Key Vault", v: "74", c: "text-blue-400" }, { l: "Unmanaged", v: "14", c: "text-red-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "secrets_inventory" && (<div className="space-y-3">{SECRETS.map((s) => (<div key={s.name} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="text-white/90 font-medium font-mono text-sm">{s.name}</span><span className="ml-2 text-xs text-white/40">{s.type}</span></div><StatusBadge status={s.risk} /></div><p className="text-white/50 text-sm">{s.detail}</p><span className="text-xs text-white/40">Vault: {s.vault}</span></div>))}</div>)}
      {tab === "rotation_status" && (<div className="card-surface p-6"><h3 className="section-heading">Rotation Compliance</h3><div className="space-y-2">{[{ secret: "prod/db/postgres_main", days: "187 days overdue", policy: "90-day", status: "critical" }, { secret: "api/stripe_live_key", days: "45 days overdue", policy: "90-day", status: "high" }, { secret: "infra/ssh/deploy_key", days: "Never rotated", policy: "90-day", status: "high" }, { secret: "auth/oauth/client_secret", days: "12 days remaining", policy: "90-day", status: "low" }].map((r, i) => (<div key={i} className="card-interactive p-3 flex items-center justify-between text-sm"><span className="text-white/70 font-mono">{r.secret}</span><div className="flex gap-3"><span className="text-white/40">{r.days}</span><StatusBadge status={r.status} /></div></div>))}</div></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Vault Metrics</h3>{[{ m: "Rotation Compliance", v: "82.1%", t: "+3.2% vs last month" }, { m: "Avg Secret Age", v: "67 days", t: "-8 days" }, { m: "Vault Coverage", v: "95.9%", t: "+1.2%" }, { m: "Exposure Incidents", v: "2", t: "-3 vs last quarter" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
