import { useState } from "react";
import { Key, AlertTriangle, Activity, Shield, Lock } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "iam_policies" | "risk_findings" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "iam_policies", label: "IAM Policies" },
  { id: "risk_findings", label: "Risk Findings" },
  { id: "metrics", label: "Metrics" },
];

const POLICIES = [
  { id: "POL-001", provider: "AWS", name: "AdminAccess-Legacy", principals: 3, unused: 47, risk: "critical", detail: "Full admin access attached to 3 service accounts — 47 permissions unused in 90d" },
  { id: "POL-002", provider: "GCP", name: "editor-role-wide", principals: 12, unused: 23, risk: "high", detail: "Editor role with project-wide scope — cross-project access detected" },
  { id: "POL-003", provider: "Azure", name: "Contributor-SubScope", principals: 8, unused: 15, risk: "medium", detail: "Contributor role at subscription level — 15 unused capabilities" },
  { id: "POL-004", provider: "AWS", name: "ReadOnly-DataTeam", principals: 45, unused: 2, risk: "low", detail: "Read-only access — well-scoped with minimal excess" },
];

const FINDINGS = [
  { id: "RF-001", provider: "AWS", level: "critical", category: "Privilege Escalation", desc: "Service account can attach admin policies to itself via iam:PutRolePolicy" },
  { id: "RF-002", provider: "GCP", level: "high", category: "Cross-Project Access", desc: "Service account has roles in 4 projects including production" },
  { id: "RF-003", provider: "Azure", level: "high", category: "Orphaned Account", desc: "Service principal unused for 180d still has Contributor role" },
  { id: "RF-004", provider: "AWS", level: "medium", category: "Stale Credential", desc: "Access key not rotated in 270 days — last used 90d ago" },
];

export default function CloudIAMAnalyzer() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Cloud IAM Analyzer" subtitle="Cross-cloud IAM policy analysis, risk detection, and least-privilege optimization" icon={<Key className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Policies Analyzed" value="847" icon={<Shield className="h-5 w-5" />} />
        <MetricCard title="Overprivileged" value="124" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Critical Risks" value="18" icon={<Lock className="h-5 w-5 text-orange-400" />} />
        <MetricCard title="Optimizations" value="67" icon={<Activity className="h-5 w-5 text-cyan-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">IAM Posture by Provider</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">{[{ l: "AWS IAM", v: "342 policies", sub: "52 overprivileged", c: "text-orange-400" }, { l: "GCP IAM", v: "287 policies", sub: "38 overprivileged", c: "text-cyan-400" }, { l: "Azure RBAC", v: "218 policies", sub: "34 overprivileged", c: "text-blue-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className="text-lg font-bold text-white/90 mt-1">{s.v}</p><p className={clsx("text-xs mt-1", s.c)}>{s.sub}</p></div>))}</div></div>)}
      {tab === "iam_policies" && (<div className="space-y-3">{POLICIES.map((p) => (<div key={p.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{p.id}</span><span className="ml-2 inline-block px-2 py-0.5 rounded text-xs bg-white/10 text-white/70">{p.provider}</span><span className="ml-2 text-white/90 font-medium">{p.name}</span></div><StatusBadge status={p.risk} /></div><p className="text-white/70 text-sm">{p.detail}</p><div className="flex gap-4 text-xs text-white/50 mt-1"><span>{p.principals} principals</span><span>{p.unused} unused permissions</span></div></div>))}</div>)}
      {tab === "risk_findings" && (<div className="space-y-3">{FINDINGS.map((f) => (<div key={f.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{f.id}</span><span className="ml-2 inline-block px-2 py-0.5 rounded text-xs bg-white/10 text-white/70">{f.provider}</span><span className="ml-2 text-white/60 text-xs">{f.category}</span></div><StatusBadge status={f.level} /></div><p className="text-white/70 text-sm">{f.desc}</p></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">IAM Health Trends</h3>{[{ m: "Least-Privilege Score", v: "64%", t: "+8% after remediation" }, { m: "Unused Permission Ratio", v: "32%", t: "-5% improvement" }, { m: "Cross-Cloud Consistency", v: "71%", t: "+12% since alignment" }, { m: "Credential Rotation", v: "89%", t: "within 90d policy" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
