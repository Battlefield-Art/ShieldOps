import { useState } from "react";
import { Key, AlertTriangle, Shield, Lock, Eye, Users } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "auth_events" | "bypass_attempts" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "auth_events", label: "Auth Events" },
  { id: "bypass_attempts", label: "Bypass Attempts" },
  { id: "metrics", label: "Metrics" },
];

const AUTH_EVENTS = [
  { id: "AE-001", user: "admin@corp.io", method: "TOTP", provider: "Okta", result: "success", risk: "low", time: "1m ago" },
  { id: "AE-002", user: "svc-deploy", method: "None", provider: "Azure AD", result: "bypassed", risk: "critical", time: "4m ago" },
  { id: "AE-003", user: "dev-user-12", method: "Push", provider: "Duo", result: "success", risk: "low", time: "7m ago" },
  { id: "AE-004", user: "ops-lead", method: "SMS", provider: "Okta", result: "success", risk: "medium", time: "12m ago" },
];

const BYPASS_ATTEMPTS = [
  { id: "BP-001", user: "svc-deploy", technique: "Legacy protocol fallback", provider: "Azure AD", severity: "critical", blocked: true },
  { id: "BP-002", user: "contractor-ext", technique: "Session token replay", provider: "Okta", severity: "high", blocked: true },
  { id: "BP-003", user: "api-service-3", technique: "MFA fatigue (push spam)", provider: "Duo", severity: "high", blocked: false },
];

export default function MfaBypassDetector() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="MFA Bypass Detector" subtitle="Detect and prevent multi-factor authentication bypass attempts" icon={<Key className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Auth Events (24h)" value="18,420" icon={<Users className="h-5 w-5" />} />
        <MetricCard title="Bypass Attempts" value="14" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Block Rate" value="92.8%" icon={<Shield className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="MFA Coverage" value="96%" icon={<Lock className="h-5 w-5 text-emerald-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">MFA Method Distribution</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "TOTP/HOTP", v: "8,412", c: "text-emerald-400" }, { l: "Push Notify", v: "6,231", c: "text-cyan-400" }, { l: "FIDO2/WebAuthn", v: "2,914", c: "text-yellow-400" }, { l: "SMS (legacy)", v: "863", c: "text-red-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "auth_events" && (<div className="space-y-3">{AUTH_EVENTS.map((e) => (<div key={e.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{e.id}</span><span className="ml-2 text-xs text-white/40">{e.provider}</span></div><StatusBadge status={e.risk} /></div><p className="text-white/90 text-sm">{e.user} via <span className="text-cyan-400">{e.method}</span></p><div className="flex gap-4 mt-2 text-xs text-white/50"><span className={e.result === "bypassed" ? "text-red-400" : "text-emerald-400"}>{e.result}</span><span>{e.time}</span></div></div>))}</div>)}
      {tab === "bypass_attempts" && (<div className="space-y-3">{BYPASS_ATTEMPTS.map((b) => (<div key={b.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{b.id}</span><span className="ml-2 text-xs text-white/40">{b.provider}</span></div><StatusBadge status={b.severity} /></div><p className="text-white/90 text-sm"><Eye className="inline h-3 w-3 mr-1" />{b.user}: <span className="text-yellow-400">{b.technique}</span></p><span className={clsx("text-xs", b.blocked ? "text-emerald-400" : "text-red-400")}>{b.blocked ? "Blocked" : "Not blocked"}</span></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">MFA Security Metrics</h3>{[{ m: "Bypass Block Rate", v: "92.8%", t: "+3.2%" }, { m: "MFA Enrollment", v: "96%", t: "+1.5%" }, { m: "SMS Deprecation", v: "4.7%", t: "-2.1%" }, { m: "Avg Auth Latency", v: "1.2s", t: "-0.3s" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
