import { useState } from "react";
import { UserCheck, Shield, AlertTriangle, Users, Key, Lock } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "threats" | "responses" | "sources";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "threats", label: "Threats" }, { id: "responses", label: "Responses" }, { id: "sources", label: "Identity Sources" }];
export default function IdentityProtection() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Identity Protection" subtitle="Real-time identity threat detection across Okta, Entra ID, AWS IAM, GCP IAM, K8s RBAC" icon={<UserCheck className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Identities Protected" value="2.4K" icon={<Users className="h-5 w-5" />} />
      <MetricCard title="Threats Blocked (24h)" value="23" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Attack Chains" value="3" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
      <MetricCard title="IdP Coverage" value="6/6" icon={<Key className="h-5 w-5 text-cyan-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Threat Types (24h)</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">
      {[{ type: "Credential Theft", count: 8, color: "text-red-400" }, { type: "Impossible Travel", count: 6, color: "text-yellow-400" }, { type: "MFA Bypass", count: 5, color: "text-red-400" }, { type: "Privilege Escalation", count: 4, color: "text-yellow-400" }].map((t) => (
        <div key={t.type} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{t.type}</p><p className={clsx("text-3xl font-bold mt-1", t.color)}>{t.count}</p></div>))}</div></div>)}
    {tab === "threats" && (<div className="space-y-3">
      {[{ id: "IDT-023", type: "Impossible Travel", identity: "admin@corp.com", source: "Okta", detail: "Login from US then India in 5 min", severity: "critical" },
        { id: "IDT-022", type: "MFA Fatigue", identity: "developer@corp.com", source: "Entra ID", detail: "47 MFA push notifications in 2 min", severity: "high" },
        { id: "IDT-021", type: "Token Theft", identity: "data-agent-v2", source: "AI Agent Registry", detail: "OAuth token used from unregistered IP", severity: "critical" },
        { id: "IDT-020", type: "Privilege Escalation", identity: "ci-sa@gcp", source: "GCP IAM", detail: "Service account assumed admin role", severity: "high" },
      ].map((t) => (<div key={t.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{t.id}</span><span className="text-xs text-white/40 ml-2">{t.source}</span></div><StatusBadge status={t.severity} /></div>
        <p className="text-white/90 font-medium">{t.type}: {t.identity}</p><p className="text-xs text-white/50">{t.detail}</p></div>))}</div>)}
    {tab === "responses" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Automated Responses</h3>
      {[{ action: "Account Locked", identity: "admin@corp.com", source: "Okta", trigger: "Impossible travel", time: "0.3s" },
        { action: "Session Revoked", identity: "data-agent-v2", source: "AI Registry", trigger: "Token theft", time: "0.1s" },
        { action: "Forced MFA Reset", identity: "developer@corp.com", source: "Entra ID", trigger: "MFA fatigue", time: "0.5s" },
        { action: "Role Reverted", identity: "ci-sa@gcp", source: "GCP IAM", trigger: "Privilege escalation", time: "0.8s" },
      ].map((r, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{r.action}</p><p className="text-xs text-white/50">{r.identity} | {r.source} | {r.trigger} | {r.time}</p></div><StatusBadge status="completed" /></div>))}</div>)}
    {tab === "sources" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">IdP</th><th className="px-4 py-3">Identities</th><th className="px-4 py-3">Threats (24h)</th><th className="px-4 py-3">Coverage</th></tr></thead>
      <tbody>{[
        { idp: "Okta", count: 800, threats: 8, coverage: "100%" },
        { idp: "Entra ID", count: 650, threats: 6, coverage: "100%" },
        { idp: "AWS IAM", count: 420, threats: 4, coverage: "100%" },
        { idp: "GCP IAM", count: 280, threats: 3, coverage: "100%" },
        { idp: "K8s RBAC", count: 190, threats: 1, coverage: "100%" },
        { idp: "AI Agent Registry", count: 60, threats: 1, coverage: "100%" },
      ].map((s, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90 font-medium">{s.idp}</td><td className="px-4 py-3 text-white/80">{s.count}</td><td className="px-4 py-3 text-red-400">{s.threats}</td><td className="px-4 py-3 text-emerald-400">{s.coverage}</td></tr>))}</tbody></table></div>)}
  </div>);
}
