import { useState } from "react";
import { UserCheck, Shield, AlertTriangle, Key, Lock } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "policies" | "alerts" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "policies", label: "Policies" },
  { id: "alerts", label: "Alerts" },
  { id: "metrics", label: "Metrics" },
];

const ALERTS = [
  { id: "IAM-001", role: "prod-admin-role", provider: "AWS", risk: "critical", issue: "AdministratorAccess policy attached — 4,200 unused permissions" },
  { id: "IAM-002", role: "ci-deploy-sa", provider: "GCP", risk: "high", issue: "Owner role on 3 projects, only needs Storage Admin" },
  { id: "IAM-003", role: "k8s-cluster-admin", provider: "K8s", risk: "high", issue: "cluster-admin binding for service account — needs RBAC scoping" },
  { id: "IAM-004", role: "legacy-api-user", provider: "AWS", risk: "medium", issue: "90-day unused credentials, last activity 2025-12-01" },
];

export default function IAMPolicyAnalyzer() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="IAM Policy Analyzer" subtitle="Cross-cloud identity and access management analysis" icon={<UserCheck className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Policies Analyzed" value="1,247" icon={<Lock className="h-5 w-5" />} />
        <MetricCard title="Over-Privileged" value="34" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Unused Perms" value="8,400" icon={<Key className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Least Privilege Score" value="72%" icon={<Shield className="h-5 w-5 text-cyan-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">IAM Health</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Compliant", v: "1,213", c: "text-emerald-400" }, { l: "Over-Privileged", v: "34", c: "text-red-400" }, { l: "Unused", v: "12", c: "text-yellow-400" }, { l: "Score", v: "72%", c: "text-cyan-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "policies" && (<div className="card-surface p-6"><p className="text-white/60">Policy inventory across AWS, GCP, Azure, and Kubernetes.</p></div>)}
      {tab === "alerts" && (<div className="space-y-3">{ALERTS.map((a) => (<div key={a.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{a.id}</span><span className="ml-2 text-white/90 font-medium">{a.role}</span><span className="ml-2 text-xs text-white/40">{a.provider}</span></div><StatusBadge status={a.risk} /></div><p className="text-white/70 text-sm">{a.issue}</p></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">IAM Trends</h3>{[{ m: "Least Privilege Score", v: "72%", t: "+5%" }, { m: "Policies Remediated", v: "89", t: "+12 this week" }, { m: "Unused Permissions", v: "8,400", t: "-1,200" }, { m: "Avg Time to Fix", v: "2.3 days", t: "-0.5 days" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
