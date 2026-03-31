import { useState } from "react";
import { Key, Users, ShieldAlert, AlertTriangle, Shield, BarChart3 } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "identities" | "excess_permissions" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "identities", label: "Identities" },
  { id: "excess_permissions", label: "Excess Permissions" },
  { id: "metrics", label: "Metrics" },
];

const IDENTITIES = [
  { id: "IDN-001", name: "ci-deploy-svc", type: "Service Account", provider: "AWS", excess: 47, risk: "critical" },
  { id: "IDN-002", name: "data-pipeline-role", type: "Role", provider: "GCP", excess: 23, risk: "high" },
  { id: "IDN-003", name: "dev-team-group", type: "Group", provider: "Azure", excess: 12, risk: "medium" },
  { id: "IDN-004", name: "monitoring-svc", type: "Service Account", provider: "AWS", excess: 5, risk: "low" },
];

const EXCESS = [
  { id: "EXC-001", identity: "ci-deploy-svc", permission: "s3:*", lastUsed: "Never", severity: "critical" },
  { id: "EXC-002", identity: "ci-deploy-svc", permission: "iam:CreateRole", lastUsed: "92 days ago", severity: "high" },
  { id: "EXC-003", identity: "data-pipeline-role", permission: "bigquery.admin", lastUsed: "180 days ago", severity: "high" },
  { id: "EXC-004", identity: "dev-team-group", permission: "Microsoft.KeyVault/vaults/delete", lastUsed: "Never", severity: "medium" },
];

export default function CloudEntitlementManager() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Cloud Entitlement Manager" subtitle="CIEM — least-privilege governance across cloud IAM" icon={<Key className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Cloud Identities" value="1,247" icon={<Users className="h-5 w-5" />} />
        <MetricCard title="Excess Permissions" value="342" icon={<ShieldAlert className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="High Risk" value="28" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Compliance Score" value="74%" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Entitlement Coverage</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "AWS", v: "512", c: "text-cyan-400" }, { l: "GCP", v: "389", c: "text-emerald-400" }, { l: "Azure", v: "278", c: "text-yellow-400" }, { l: "K8s RBAC", v: "68", c: "text-white/70" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "identities" && (<div className="space-y-3">{IDENTITIES.map((i) => (<div key={i.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{i.id}</span><span className="ml-2 text-xs text-white/40">{i.type}</span></div><StatusBadge status={i.risk} /></div><p className="text-white/90 text-sm font-medium">{i.name}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>Provider: {i.provider}</span><span className={i.excess > 20 ? "text-red-400" : "text-white/40"}>{i.excess} excess permissions</span></div></div>))}</div>)}
      {tab === "excess_permissions" && (<div className="space-y-3">{EXCESS.map((e) => (<div key={e.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{e.id}</span><span className="ml-2 text-xs text-white/40">{e.identity}</span></div><StatusBadge status={e.severity} /></div><p className="text-white/90 text-sm font-mono">{e.permission}</p><span className="text-xs text-white/40">Last used: {e.lastUsed}</span></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">CIEM Performance</h3>{[{ m: "Permission Reduction", v: "38%", t: "+12%" }, { m: "Avg Excess per Identity", v: "4.2", t: "-1.8" }, { m: "Wildcard Policies", v: "17", t: "-9" }, { m: "Compliance Score", v: "74%", t: "+15%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
