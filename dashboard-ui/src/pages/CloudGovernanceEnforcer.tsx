import { useState } from "react";
import { Cloud, Tag, AlertTriangle, Shield, CheckCircle, BarChart3 } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "resource_compliance" | "tag_violations" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "resource_compliance", label: "Resource Compliance" },
  { id: "tag_violations", label: "Tag Violations" },
  { id: "metrics", label: "Metrics" },
];

const RESOURCES = [
  { id: "RES-001", name: "prod-web-cluster", provider: "AWS", type: "EKS", tags: 8, required: 8, status: "compliant" },
  { id: "RES-002", name: "staging-db-primary", provider: "AWS", type: "RDS", tags: 5, required: 8, status: "non-compliant" },
  { id: "RES-003", name: "analytics-bucket-v2", provider: "GCP", type: "GCS", tags: 7, required: 8, status: "partial" },
  { id: "RES-004", name: "dev-vm-sandbox-12", provider: "Azure", type: "VM", tags: 3, required: 8, status: "non-compliant" },
];

const TAG_VIOLATIONS = [
  { id: "TV-001", resource: "RES-002", missing: "cost-center, team", naming: "Invalid env value", severity: "high", remediated: false },
  { id: "TV-002", resource: "RES-004", missing: "cost-center, team, project, owner, env", naming: "No naming convention", severity: "critical", remediated: false },
  { id: "TV-003", resource: "RES-003", missing: "data-classification", naming: "None", severity: "medium", remediated: true },
];

export default function CloudGovernanceEnforcer() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Cloud Governance Enforcer" subtitle="Tag compliance, naming conventions, and resource lifecycle enforcement" icon={<Cloud className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Resources Scanned" value="1,847" icon={<Cloud className="h-5 w-5" />} />
        <MetricCard title="Tag Violations" value="312" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Compliance Score" value="81%" icon={<Shield className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Auto-Remediated" value="89" icon={<CheckCircle className="h-5 w-5 text-emerald-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Compliance by Provider</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "AWS", v: "84%", c: "text-cyan-400" }, { l: "GCP", v: "79%", c: "text-emerald-400" }, { l: "Azure", v: "76%", c: "text-yellow-400" }, { l: "Overall", v: "81%", c: "text-white/90" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "resource_compliance" && (<div className="space-y-3">{RESOURCES.map((r) => (<div key={r.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{r.id}</span><span className="ml-2 text-xs text-white/40">{r.provider} / {r.type}</span></div><StatusBadge status={r.status} /></div><p className="text-white/90 text-sm font-medium">{r.name}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>Tags: {r.tags}/{r.required}</span><span className={r.tags === r.required ? "text-emerald-400" : "text-yellow-400"}>{Math.round((r.tags / r.required) * 100)}% complete</span></div></div>))}</div>)}
      {tab === "tag_violations" && (<div className="space-y-3">{TAG_VIOLATIONS.map((v) => (<div key={v.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{v.id}</span><span className="ml-2 text-xs text-white/40">{v.resource}</span></div><StatusBadge status={v.severity} /></div><p className="text-white/90 text-sm">Missing: <span className="text-yellow-400">{v.missing}</span></p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>Naming: {v.naming}</span><span className={v.remediated ? "text-emerald-400" : "text-red-400"}>{v.remediated ? "Remediated" : "Pending"}</span></div></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Governance Metrics</h3>{[{ m: "Compliance Score", v: "81%", t: "+4%" }, { m: "Auto-Remediation Rate", v: "72%", t: "+8%" }, { m: "Orphaned Resources", v: "23", t: "-7" }, { m: "Cost Attribution Gap", v: "$12,400/mo", t: "-$3,200" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
