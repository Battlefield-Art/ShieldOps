import { useState } from "react";
import { Key, Shield, AlertTriangle, Users, Lock } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "leaked" | "mfa" | "policies";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "leaked", label: "Leaked Credentials" }, { id: "mfa", label: "MFA Coverage" }, { id: "policies", label: "Policies" }];
export default function CredentialTester() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Credential Tester" subtitle="Credential hygiene validation — leaked credentials, MFA coverage, rotation compliance" icon={<Key className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Accounts Tested" value="2.4K" icon={<Users className="h-5 w-5" />} />
      <MetricCard title="Leaked Found" value="23" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
      <MetricCard title="MFA Gaps" value="47" icon={<Lock className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Hygiene Score" value="78%" icon={<Shield className="h-5 w-5 text-yellow-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Credential Risk Breakdown</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">
      {[{ risk: "Compromised", count: 23, color: "text-red-400" }, { risk: "Weak", count: 89, color: "text-yellow-400" }, { risk: "No MFA", count: 47, color: "text-yellow-400" }, { risk: "Stale (90d+)", count: 156, color: "text-white/60" }].map((r) => (
        <div key={r.risk} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{r.risk}</p><p className={clsx("text-3xl font-bold mt-1", r.color)}>{r.count}</p></div>))}</div></div>)}
    {tab === "leaked" && (<div className="space-y-3"><p className="text-xs text-white/40 mb-2">Checked via k-anonymity hash prefix — no actual passwords transmitted</p>
      {[{ account: "admin@company.com", source: "2024 breach database", severity: "critical", action: "Force reset" },
        { account: "dev-sa@gcp-project", source: "GitHub commit history", severity: "critical", action: "Rotate immediately" },
        { account: "ci-bot@company.com", source: "Paste site", severity: "high", action: "Rotate + audit" },
      ].map((l, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{l.account}</p><p className="text-xs text-white/50">Source: {l.source} | Action: {l.action}</p></div><StatusBadge status={l.severity} /></div>))}</div>)}
    {tab === "mfa" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Category</th><th className="px-4 py-3">Total</th><th className="px-4 py-3">MFA Enabled</th><th className="px-4 py-3">Coverage</th></tr></thead>
      <tbody>{[
        { cat: "Human Users", total: 645, mfa: 612, pct: "94.8%" },
        { cat: "Admin Accounts", total: 23, mfa: 23, pct: "100%" },
        { cat: "Service Accounts", total: 120, mfa: 34, pct: "28.3%" },
        { cat: "API Keys", total: 89, mfa: 0, pct: "N/A" },
      ].map((m, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90">{m.cat}</td><td className="px-4 py-3 text-white/80">{m.total}</td><td className="px-4 py-3 text-white/70">{m.mfa}</td><td className="px-4 py-3"><span className={clsx("font-mono", m.pct === "100%" ? "text-emerald-400" : parseFloat(m.pct) > 90 ? "text-cyan-400" : "text-yellow-400")}>{m.pct}</span></td></tr>))}</tbody></table></div>)}
    {tab === "policies" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Password Policy Compliance</h3>
      {[{ policy: "Minimum 12 characters", compliance: "94%", status: "compliant" },
        { policy: "Require uppercase + number + special", compliance: "89%", status: "at_risk" },
        { policy: "No password reuse (last 12)", compliance: "97%", status: "compliant" },
        { policy: "Rotation every 90 days", compliance: "67%", status: "non_compliant" },
      ].map((p, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{p.policy}</p><p className="text-xs text-white/50">Compliance: {p.compliance}</p></div><StatusBadge status={p.status} /></div>))}</div>)}
  </div>);
}
