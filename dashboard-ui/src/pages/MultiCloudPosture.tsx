import { useState } from "react";
import { Cloud, Shield, AlertTriangle, Layers, Target } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "cloud_comparison" | "cross_cloud_gaps" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "cloud_comparison", label: "Cloud Comparison" },
  { id: "cross_cloud_gaps", label: "Cross-Cloud Gaps" },
  { id: "metrics", label: "Metrics" },
];

const COMPARISONS = [
  { category: "IAM", aws: 82, gcp: 78, azure: 85 },
  { category: "Network", aws: 76, gcp: 88, azure: 71 },
  { category: "Encryption", aws: 91, gcp: 87, azure: 89 },
  { category: "Logging", aws: 88, gcp: 92, azure: 80 },
  { category: "Compute", aws: 79, gcp: 74, azure: 82 },
  { category: "Storage", aws: 85, gcp: 81, azure: 77 },
];

export default function MultiCloudPosture() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Multi-Cloud Posture" subtitle="Unified security posture management across AWS, GCP, and Azure" icon={<Cloud className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Overall Score" value="81.4" icon={<Shield className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Total Findings" value="347" icon={<AlertTriangle className="h-5 w-5 text-orange-400" />} />
        <MetricCard title="Security Gaps" value="14" icon={<Target className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Recommendations" value="28" icon={<Layers className="h-5 w-5 text-emerald-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Provider Scores</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">{[{ l: "AWS", v: "83.5", c: "text-orange-400" }, { l: "GCP", v: "83.3", c: "text-cyan-400" }, { l: "Azure", v: "80.7", c: "text-blue-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p><p className="text-xs text-white/40 mt-1">/ 100</p></div>))}</div></div>)}
      {tab === "cloud_comparison" && (<div className="card-surface p-6"><h3 className="section-heading">Category Comparison</h3><div className="space-y-3">{COMPARISONS.map((c) => { const min = Math.min(c.aws, c.gcp, c.azure); const gap = Math.max(c.aws, c.gcp, c.azure) - min; return (<div key={c.category} className="card-interactive p-4"><div className="flex items-center justify-between mb-2"><span className="text-white/90 font-medium">{c.category}</span><span className={clsx("text-xs", gap > 10 ? "text-red-400" : "text-white/40")}>Gap: {gap}pts</span></div><div className="grid grid-cols-3 gap-2 text-sm"><div className="flex items-center gap-2"><span className="text-white/40 w-12">AWS</span><div className="flex-1 h-2 rounded-full bg-white/10"><div className="h-full rounded-full bg-orange-400" style={{ width: `${c.aws}%` }} /></div><span className="text-white/60 w-8 text-right">{c.aws}</span></div><div className="flex items-center gap-2"><span className="text-white/40 w-12">GCP</span><div className="flex-1 h-2 rounded-full bg-white/10"><div className="h-full rounded-full bg-cyan-400" style={{ width: `${c.gcp}%` }} /></div><span className="text-white/60 w-8 text-right">{c.gcp}</span></div><div className="flex items-center gap-2"><span className="text-white/40 w-12">Azure</span><div className="flex-1 h-2 rounded-full bg-white/10"><div className="h-full rounded-full bg-blue-400" style={{ width: `${c.azure}%` }} /></div><span className="text-white/60 w-8 text-right">{c.azure}</span></div></div></div>); })}</div></div>)}
      {tab === "cross_cloud_gaps" && (<div className="card-surface p-6"><h3 className="section-heading">Cross-Cloud Security Gaps</h3><div className="space-y-2">{[{ gap: "Network policy inconsistency across AWS/Azure", severity: "critical", providers: "AWS, Azure", impact: "Lateral movement risk" }, { gap: "IAM role sprawl in GCP vs AWS", severity: "high", providers: "GCP, AWS", impact: "Privilege escalation" }, { gap: "Logging gaps in Azure vs GCP", severity: "high", providers: "Azure", impact: "Reduced visibility" }, { gap: "Encryption key rotation mismatch", severity: "medium", providers: "AWS, GCP, Azure", impact: "Compliance gap" }].map((g, i) => (<div key={i} className="card-interactive p-3"><div className="flex items-start justify-between mb-1"><span className="text-white/70 text-sm">{g.gap}</span><StatusBadge status={g.severity} /></div><div className="flex gap-4 text-xs"><span className="text-white/40">Providers: {g.providers}</span><span className="text-white/40">Impact: {g.impact}</span></div></div>))}</div></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Posture Trends</h3>{[{ m: "Overall Score", v: "81.4/100", t: "+2.3 this month" }, { m: "Findings Remediated", v: "124", t: "+18 this week" }, { m: "Cross-Cloud Gaps", v: "14", t: "-3 vs last month" }, { m: "Policy Compliance", v: "94%", t: "+2% this quarter" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
