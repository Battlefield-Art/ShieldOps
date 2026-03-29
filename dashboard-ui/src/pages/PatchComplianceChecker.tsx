import { useState } from "react";
import { PackageCheck, AlertTriangle, Clock, Shield, Server } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "patches" | "sla" | "rollout";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "patches", label: "Missing Patches" }, { id: "sla", label: "SLA Tracking" }, { id: "rollout", label: "Rollout Schedule" }];
export default function PatchComplianceChecker() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Patch Compliance Checker" subtitle="Fleet patch compliance, SLA tracking, rollout scheduling, and risk assessment" icon={<PackageCheck className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Fleet Systems" value="1,842" icon={<Server className="h-5 w-5" />} />
      <MetricCard title="Compliance Rate" value="91.4%" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Critical Missing" value="23" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
      <MetricCard title="SLA Breaches" value="5" icon={<Clock className="h-5 w-5 text-yellow-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Patch Status Distribution</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">
      {[{ label: "Fully Patched", count: 1684, color: "text-emerald-400" }, { label: "Pending", count: 89, color: "text-yellow-400" }, { label: "Critical", count: 23, color: "text-red-400" }, { label: "Excluded", count: 46, color: "text-white/40" }].map((s) => (
        <div key={s.label} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.label}</p><p className={clsx("text-3xl font-bold mt-1", s.color)}>{s.count}</p></div>))}</div></div>)}
    {tab === "patches" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Patch</th><th className="px-4 py-3">System</th><th className="px-4 py-3">CVE</th><th className="px-4 py-3">Days Overdue</th><th className="px-4 py-3">Severity</th></tr></thead>
      <tbody>{[
        { patch: "OpenSSL RCE", system: "web-prod-01", cve: "CVE-2026-1234", overdue: 12, severity: "critical" },
        { patch: "Kernel privesc", system: "db-prod-01", cve: "CVE-2026-5678", overdue: 5, severity: "high" },
        { patch: "Windows update", system: "dev-ws-01", cve: "CVE-2026-9012", overdue: 0, severity: "medium" },
        { patch: "glibc overflow", system: "api-staging-01", cve: "CVE-2026-3456", overdue: 2, severity: "high" },
      ].map((p, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90 font-medium">{p.patch}</td><td className="px-4 py-3 text-white/60 font-mono text-xs">{p.system}</td><td className="px-4 py-3 text-cyan-400 font-mono text-xs">{p.cve}</td><td className="px-4 py-3 text-white/80">{p.overdue}d</td><td className="px-4 py-3"><StatusBadge status={p.severity} /></td></tr>))}</tbody></table></div>)}
    {tab === "sla" && (<div className="space-y-3">
      {[{ patch: "CVE-2026-1234", system: "web-prod-01", sla: "7 days", overdue: "12 days", breach: "5 days", severity: "critical" },
        { patch: "CVE-2026-5678", system: "db-prod-01", sla: "14 days", overdue: "5 days", breach: "N/A", severity: "compliant" },
        { patch: "CVE-2026-9012", system: "dev-ws-01", sla: "30 days", overdue: "0 days", breach: "N/A", severity: "compliant" },
      ].map((s, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><span className="font-mono text-xs text-cyan-400">{s.patch}</span><StatusBadge status={s.severity} /></div>
        <p className="text-white/90">{s.system}</p><p className="text-xs text-white/50">SLA: {s.sla} | Overdue: {s.overdue} | Breach: {s.breach}</p></div>))}</div>)}
    {tab === "rollout" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Scheduled Rollouts</h3>
      {[{ id: "ROL-001", patch: "OpenSSL RCE (CVE-2026-1234)", target: "web-prod-01", window: "MW-1 (Tonight)", priority: 1, status: "scheduled" },
        { id: "ROL-002", patch: "Kernel privesc (CVE-2026-5678)", target: "db-prod-01", window: "MW-1 (Tonight)", priority: 2, status: "scheduled" },
        { id: "ROL-003", patch: "Windows update (CVE-2026-9012)", target: "dev-ws-01", window: "MW-2 (Next week)", priority: 3, status: "pending" },
      ].map((r) => (<div key={r.id} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">P{r.priority}: {r.patch}</p><p className="text-xs text-white/50">{r.target} | {r.window}</p></div><StatusBadge status={r.status} /></div>))}</div>)}
  </div>);
}
