import { useState } from "react";
import { UserMinus, Shield, Users, AlertTriangle, Key, CheckCircle } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "excess" | "changes" | "verified";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "excess", label: "Excess Access" }, { id: "changes", label: "Changes" }, { id: "verified", label: "Verified" }];
export default function AccessRemediation() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Access Remediation" subtitle="Revoke stale access, right-size permissions, disable dormant accounts" icon={<UserMinus className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Accounts Audited" value="2.4K" icon={<Users className="h-5 w-5" />} />
      <MetricCard title="Excess Found" value="234" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Remediated" value="189" icon={<CheckCircle className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Permissions Removed" value="1.2K" icon={<Key className="h-5 w-5 text-cyan-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Access Issues by Type</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">
      {[{ type: "Stale Access", count: 89, color: "text-yellow-400" }, { type: "Over-Privileged", count: 67, color: "text-red-400" }, { type: "Dormant Accounts", count: 45, color: "text-white/60" }, { type: "Shared Credentials", count: 33, color: "text-yellow-400" }].map((i) => (
        <div key={i.type} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{i.type}</p><p className={clsx("text-3xl font-bold mt-1", i.color)}>{i.count}</p></div>))}</div></div>)}
    {tab === "excess" && (<div className="space-y-3">
      {[{ account: "dev-contractor-expired", issue: "Dormant 120 days, still has prod access", severity: "critical", action: "Disable account" },
        { account: "ci-deploy-sa", issue: "Has admin permissions, only needs deploy", severity: "high", action: "Right-size to deploy-only" },
        { account: "former-employee-42", issue: "Account active 30 days after termination", severity: "critical", action: "Immediate disable" },
      ].map((e, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><p className="text-white/90 font-medium font-mono">{e.account}</p><StatusBadge status={e.severity} /></div>
        <p className="text-white/70 text-sm">{e.issue}</p><p className="text-xs text-white/50">Action: {e.action}</p></div>))}</div>)}
    {tab === "changes" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Executed Changes</h3>
      {[{ action: "Disabled dormant account", target: "dev-contractor-expired", status: "completed", notified: true },
        { action: "Removed 23 unused permissions", target: "ci-deploy-sa", status: "completed", notified: true },
        { action: "Revoked all sessions", target: "former-employee-42", status: "completed", notified: true },
      ].map((c, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{c.action}</p><p className="text-xs text-white/50">{c.target} | Owner notified: {c.notified ? "Yes" : "No"}</p></div><StatusBadge status={c.status} /></div>))}</div>)}
    {tab === "verified" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Access Verification</h3>
      {[{ target: "dev-contractor-expired", check: "Login attempt", result: "Access denied (disabled)", status: "verified" },
        { target: "ci-deploy-sa", check: "Permission enumeration", result: "Only deploy actions remain", status: "verified" },
        { target: "former-employee-42", check: "Session check", result: "Zero active sessions", status: "verified" },
      ].map((v, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{v.target}</p><p className="text-xs text-white/50">{v.check}: {v.result}</p></div><StatusBadge status={v.status} /></div>))}</div>)}
  </div>);
}
