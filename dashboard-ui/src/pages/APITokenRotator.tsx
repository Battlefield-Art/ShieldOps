import { useState } from "react";
import { Key, AlertTriangle, RefreshCw, Clock } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "token_inventory" | "rotation_schedule" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "token_inventory", label: "Token Inventory" },
  { id: "rotation_schedule", label: "Rotation Schedule" },
  { id: "metrics", label: "Metrics" },
];

const TOKENS = [
  { id: "TK-001", name: "stripe-prod-key", service: "Stripe", age: 210, risk: "critical", detail: "API key 210 days old, max policy 90 days, rotation overdue" },
  { id: "TK-002", name: "aws-lambda-svc", service: "AWS", age: 365, risk: "critical", detail: "Service account 365 days old, 3 overprivileged scopes" },
  { id: "TK-003", name: "jwt-signing-secret", service: "AuthService", age: 400, risk: "critical", detail: "JWT secret 400 days old, max policy 60 days" },
  { id: "TK-004", name: "pagerduty-token", service: "PagerDuty", age: 180, risk: "high", detail: "API key 180 days old, last used 5 days ago" },
];

export default function APITokenRotator() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="API Token Rotator" subtitle="Automated API token rotation and lifecycle management" icon={<Key className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Tokens Discovered" value="48" icon={<Key className="h-5 w-5" />} />
        <MetricCard title="Stale Tokens" value="12" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Rotated Today" value="8" icon={<RefreshCw className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Avg Token Age" value="142d" icon={<Clock className="h-5 w-5 text-cyan-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Token Health</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Healthy", v: "28", c: "text-emerald-400" }, { l: "Stale", v: "12", c: "text-yellow-400" }, { l: "Critical", v: "5", c: "text-red-400" }, { l: "Overprivileged", v: "9", c: "text-orange-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "token_inventory" && (<div className="space-y-3">{TOKENS.map((t) => (<div key={t.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{t.id}</span><span className="ml-2 text-white/90 font-medium">{t.name}</span></div><StatusBadge status={t.risk} /></div><p className="text-white/70 text-sm">{t.service} &middot; {t.age} days old</p><p className="text-white/50 text-xs mt-1">{t.detail}</p></div>))}</div>)}
      {tab === "rotation_schedule" && (<div className="card-surface p-6"><p className="text-white/60">Automated rotation schedule with zero-downtime token swaps across 48 credentials.</p></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Rotation Metrics</h3>{[{ m: "Rotation Success Rate", v: "99.2%", t: "+0.3%" }, { m: "Avg Rotation Time", v: "2.4s", t: "-0.8s" }, { m: "Zero-Downtime Rate", v: "100%", t: "stable" }, { m: "Policy Compliance", v: "85%", t: "+12%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
