import { useState } from "react";
import { Lock, Shield, AlertTriangle, Key, Users } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "violations" | "cross_account" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "violations", label: "Violations" },
  { id: "cross_account", label: "Cross-Account" },
  { id: "metrics", label: "Metrics" },
];

const VIOLATIONS = [
  { id: "CPA-001", identity: "prod-deploy-role", provider: "AWS", type: "WILDCARD_ACCESS", severity: "critical", detail: "s3:* on all resources in production account" },
  { id: "CPA-002", identity: "gcp-ci-sa", provider: "GCP", type: "OVERPRIVILEGED", severity: "high", detail: "Owner role granted, only needs Storage Admin + Cloud Build" },
  { id: "CPA-003", identity: "azure-monitor-sp", provider: "Azure", type: "DORMANT_CREDENTIAL", severity: "high", detail: "Last used 120 days ago, has Contributor on 3 subscriptions" },
  { id: "CPA-004", identity: "k8s-default-sa", provider: "K8s", type: "ESCALATION_PATH", severity: "medium", detail: "Can create pods with host PID — privilege escalation risk" },
];

export default function CloudPermissionAuditor() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Cloud Permission Auditor" subtitle="Cross-cloud least-privilege analysis and remediation" icon={<Lock className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Identities Audited" value="2,340" icon={<Users className="h-5 w-5" />} />
        <MetricCard title="Violations" value="87" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Least Privilege Score" value="68%" icon={<Shield className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Auto-Remediated" value="34" icon={<Key className="h-5 w-5 text-emerald-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Permission Health</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Compliant", v: "2,253", c: "text-emerald-400" }, { l: "Over-Privileged", v: "54", c: "text-orange-400" }, { l: "Dormant", v: "21", c: "text-yellow-400" }, { l: "Escalation Paths", v: "12", c: "text-red-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "violations" && (<div className="space-y-3">{VIOLATIONS.map((v) => (<div key={v.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{v.id}</span><span className="ml-2 text-white/90 font-medium">{v.identity}</span><span className="ml-2 text-xs text-white/40">{v.provider}</span></div><StatusBadge status={v.severity} /></div><p className="text-white/70 text-sm">{v.type}: {v.detail}</p></div>))}</div>)}
      {tab === "cross_account" && (<div className="card-surface p-6"><h3 className="section-heading">Cross-Account Access</h3><div className="space-y-2">{[{ from: "prod-account", to: "dev-account", roles: 3, risk: "high" }, { from: "shared-services", to: "prod-account", roles: 7, risk: "medium" }, { from: "vendor-access", to: "staging", roles: 2, risk: "low" }].map((c, i) => (<div key={i} className="card-interactive p-3 flex items-center justify-between text-sm"><span className="text-white/70">{c.from} → {c.to}</span><div className="flex gap-4"><span className="text-white/50">{c.roles} roles</span><StatusBadge status={c.risk} /></div></div>))}</div></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Audit Trends</h3>{[{ m: "Least Privilege Score", v: "68%", t: "+8%" }, { m: "Violations Remediated", v: "234", t: "+45 this month" }, { m: "Dormant Credentials", v: "21", t: "-12" }, { m: "Avg Time to Fix", v: "2.1 days", t: "-0.6 days" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
