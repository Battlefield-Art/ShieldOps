import { useState } from "react";
import { UserCheck, Shield, AlertTriangle, Key, UserX } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "service_accounts" | "orphan_detection" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "service_accounts", label: "Service Accounts" },
  { id: "orphan_detection", label: "Orphan Detection" },
  { id: "metrics", label: "Metrics" },
];

const ACCOUNTS = [
  { id: "SA-001", name: "deploy-bot-prod", type: "Service Principal", provider: "AWS", risk: "high", permissions: 34, lastUsed: "2h ago" },
  { id: "SA-002", name: "ci-pipeline-runner", type: "IAM Role", provider: "AWS", risk: "medium", permissions: 18, lastUsed: "5m ago" },
  { id: "SA-003", name: "monitoring-svc@gcp", type: "Service Principal", provider: "GCP", risk: "low", permissions: 8, lastUsed: "1h ago" },
  { id: "SA-004", name: "legacy-etl-job", type: "API Key", provider: "Azure", risk: "critical", permissions: 47, lastUsed: "180d ago" },
];

const ORPHANS = [
  { id: "ORP-001", account: "old-jenkins-bot", reason: "Owner departed", daysInactive: 245, permissions: 22, risk: "critical" },
  { id: "ORP-002", account: "test-deploy-key", reason: "Attached to decommissioned resource", daysInactive: 180, permissions: 15, risk: "high" },
  { id: "ORP-003", account: "staging-api-svc", reason: "No recent activity", daysInactive: 120, permissions: 9, risk: "medium" },
  { id: "ORP-004", account: "demo-analytics-bot", reason: "Owner departed", daysInactive: 310, permissions: 31, risk: "critical" },
];

export default function ServiceAccountGuardian() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Service Account Guardian" subtitle="Service account security, lifecycle management, and orphan detection" icon={<UserCheck className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Total Accounts" value="247" icon={<Key className="h-5 w-5" />} />
        <MetricCard title="Orphaned" value="12" icon={<UserX className="h-5 w-5 text-red-400" />} />
        <MetricCard title="High Risk" value="8" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Remediated (30d)" value="19" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Account Distribution</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "IAM Roles", v: "89", c: "text-cyan-400" }, { l: "Service Principals", v: "72", c: "text-emerald-400" }, { l: "API Keys", v: "54", c: "text-yellow-400" }, { l: "OAuth Clients", v: "32", c: "text-white/70" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "service_accounts" && (<div className="space-y-3">{ACCOUNTS.map((a) => (<div key={a.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{a.id}</span><span className="ml-2 text-xs text-white/40">{a.provider}</span></div><StatusBadge status={a.risk} /></div><p className="text-white/90 text-sm font-medium font-mono">{a.name}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>{a.type}</span><span>{a.permissions} permissions</span><span>Last used: {a.lastUsed}</span></div></div>))}</div>)}
      {tab === "orphan_detection" && (<div className="space-y-3">{ORPHANS.map((o) => (<div key={o.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{o.id}</span><span className="ml-2 text-xs text-white/40">{o.daysInactive}d inactive</span></div><StatusBadge status={o.risk} /></div><p className="text-white/90 text-sm font-medium font-mono">{o.account}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span className="text-red-400">{o.reason}</span><span>{o.permissions} permissions</span></div></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Guardian Performance</h3>{[{ m: "Orphan Detection Rate", v: "96%", t: "+3%" }, { m: "Avg Remediation Time", v: "4.2 hrs", t: "-1.8 hrs" }, { m: "Permission Right-Sizing", v: "73%", t: "+11%" }, { m: "Key Rotation Compliance", v: "84%", t: "+6%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
