import { useState } from "react";
import { GitBranch, Cloud, AlertTriangle, Wrench } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "drift_report" | "remediation_plan" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "drift_report", label: "Drift Report" },
  { id: "remediation_plan", label: "Remediation Plan" },
  { id: "metrics", label: "Metrics" },
];

const DRIFTS = [
  { resource: "sg-0a1b2c3d (prod-api)", type: "Security Group", drift: "Port 22 opened manually", risk: "critical" },
  { resource: "iam-role-deploy-admin", type: "IAM Policy", drift: "Inline policy added outside IaC", risk: "critical" },
  { resource: "s3://logs-backup-prod", type: "Storage", drift: "Encryption disabled", risk: "high" },
  { resource: "vpc-0x9y8z (staging)", type: "Network ACL", drift: "Egress rule modified", risk: "medium" },
  { resource: "rds-prod-primary", type: "Compute", drift: "Instance class changed", risk: "low" },
];

export default function CloudDriftRemediator() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Cloud Drift Remediator" subtitle="IaC drift detection and automated remediation" icon={<GitBranch className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Resources Scanned" value="1,892" icon={<Cloud className="h-5 w-5" />} />
        <MetricCard title="Drifts Detected" value="47" icon={<GitBranch className="h-5 w-5 text-orange-400" />} />
        <MetricCard title="Critical Drifts" value="12" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Auto-Remediated" value="31" icon={<Wrench className="h-5 w-5 text-emerald-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Drift by Type</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Security Group", v: "18", c: "text-red-400" }, { l: "IAM Policy", v: "12", c: "text-orange-400" }, { l: "Storage Config", v: "9", c: "text-yellow-400" }, { l: "Network ACL", v: "8", c: "text-cyan-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "drift_report" && (<div className="space-y-3">{DRIFTS.map((d) => (<div key={d.resource} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="text-white/90 font-medium font-mono text-sm">{d.resource}</span><span className="ml-2 text-xs text-white/40">{d.type}</span></div><StatusBadge status={d.risk} /></div><p className="text-white/50 text-sm">{d.drift}</p></div>))}</div>)}
      {tab === "remediation_plan" && (<div className="card-surface p-6"><h3 className="section-heading">Remediation Queue</h3><div className="space-y-2">{[{ resource: "sg-0a1b2c3d", action: "Revert to baseline", status: "critical", approval: "Required" }, { resource: "iam-role-deploy-admin", action: "Remove inline policy", status: "critical", approval: "Required" }, { resource: "s3://logs-backup-prod", action: "Re-enable encryption", status: "high", approval: "Auto" }, { resource: "vpc-0x9y8z", action: "Revert egress rule", status: "medium", approval: "Auto" }].map((p, i) => (<div key={i} className="card-interactive p-3 flex items-center justify-between text-sm"><div><span className="text-white/90 font-mono">{p.resource}</span><span className="ml-2 text-white/40">{p.action}</span></div><div className="flex gap-3"><span className="text-white/40">{p.approval}</span><StatusBadge status={p.status} /></div></div>))}</div></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Drift Trends</h3>{[{ m: "Drift Rate", v: "2.5%", t: "-0.8% vs last scan" }, { m: "Auto-Fix Rate", v: "66%", t: "+12%" }, { m: "Mean Time to Remediate", v: "4.2 min", t: "-1.8 min" }, { m: "Compliance Score", v: "94.2%", t: "+3.1%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
