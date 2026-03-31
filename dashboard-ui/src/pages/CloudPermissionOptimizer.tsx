import { useState } from "react";
import { Lock, Shield, AlertTriangle, TrendingDown, Users, FileText } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "permission_analysis" | "recommendations" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "permission_analysis", label: "Permission Analysis" },
  { id: "recommendations", label: "Recommendations" },
  { id: "metrics", label: "Metrics" },
];

const PERMISSIONS = [
  { id: "PRM-001", principal: "arn:aws:iam::123:role/DataPipeline", provider: "AWS", excess: 47, risk: "critical", lastUsed: "12 days ago" },
  { id: "PRM-002", principal: "sa-gcp-analytics@proj.iam", provider: "GCP", excess: 23, risk: "high", lastUsed: "3 days ago" },
  { id: "PRM-003", principal: "spn-azure-deploy", provider: "Azure", excess: 8, risk: "medium", lastUsed: "1 day ago" },
  { id: "PRM-004", principal: "arn:aws:iam::123:user/legacy-svc", provider: "AWS", excess: 91, risk: "critical", lastUsed: "90+ days" },
];

const RECOMMENDATIONS = [
  { id: "REC-001", principal: "legacy-svc", action: "Remove 91 unused permissions", risk: "critical", auto: true },
  { id: "REC-002", principal: "DataPipeline", action: "Scope S3 access to specific buckets", risk: "high", auto: false },
  { id: "REC-003", principal: "sa-gcp-analytics", action: "Remove BigQuery admin, keep reader", risk: "high", auto: true },
  { id: "REC-004", principal: "spn-azure-deploy", action: "Restrict to resource group scope", risk: "medium", auto: false },
];

export default function CloudPermissionOptimizer() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Cloud Permission Optimizer" subtitle="Cross-cloud permission right-sizing and least-privilege enforcement" icon={<Lock className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Total Permissions" value="2,847" icon={<Users className="h-5 w-5" />} />
        <MetricCard title="Excess Permissions" value="169" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Reduction Target" value="42%" icon={<TrendingDown className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Risk Score" value="7.2" icon={<Shield className="h-5 w-5 text-red-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Permission Posture by Provider</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">{[{ l: "AWS", v: "1,420", e: "91", c: "text-yellow-400" }, { l: "GCP", v: "823", e: "45", c: "text-cyan-400" }, { l: "Azure", v: "604", e: "33", c: "text-emerald-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p><p className="text-xs text-white/40 mt-1">{s.e} excess</p></div>))}</div></div>)}
      {tab === "permission_analysis" && (<div className="space-y-3">{PERMISSIONS.map((p) => (<div key={p.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{p.id}</span><span className="ml-2 text-xs text-white/40">{p.provider}</span></div><StatusBadge status={p.risk} /></div><p className="text-white/90 text-sm font-mono">{p.principal}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span className="text-yellow-400">{p.excess} excess permissions</span><span>Last used: {p.lastUsed}</span></div></div>))}</div>)}
      {tab === "recommendations" && (<div className="space-y-3">{RECOMMENDATIONS.map((r) => (<div key={r.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{r.id}</span><span className="ml-2 text-xs text-white/40">{r.principal}</span></div><StatusBadge status={r.risk} /></div><p className="text-white/90 text-sm">{r.action}</p><span className={clsx("text-xs mt-1 inline-block", r.auto ? "text-emerald-400" : "text-white/40")}>{r.auto ? "Auto-remediable" : "Manual review required"}</span></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Optimization Metrics</h3>{[{ m: "Permission Reduction", v: "42%", t: "+8%" }, { m: "Avg Excess per Principal", v: "12.3", t: "-3.1" }, { m: "Auto-remediation Rate", v: "67%", t: "+12%" }, { m: "Compliance Score", v: "89%", t: "+5%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
