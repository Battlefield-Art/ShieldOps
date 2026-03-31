import { useState } from "react";
import { GitBranch, Shield, AlertTriangle, Activity, CheckCircle, Zap } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "pending_changes" | "risk_assessment" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "pending_changes", label: "Pending Changes" },
  { id: "risk_assessment", label: "Risk Assessment" },
  { id: "metrics", label: "Metrics" },
];

const CHANGES = [
  { id: "CR-001", title: "Deploy auth-service v2.4.0", service: "auth-service", risk: "medium", status: "approved", detail: "OAuth2 token refresh fix + rate limit update" },
  { id: "CR-002", title: "Update WAF rules for API gateway", service: "api-gateway", risk: "high", status: "escalated", detail: "Emergency SQLi pattern block — requires CAB review" },
  { id: "CR-003", title: "Scale Redis cluster to 6 nodes", service: "cache-layer", risk: "low", status: "auto_approved", detail: "Handle increased session load, canary deploy" },
  { id: "CR-004", title: "Upgrade PostgreSQL 15 to 16", service: "database", risk: "critical", status: "rejected", detail: "Major version upgrade — blast radius too high for current window" },
];

export default function SecurityChangeManager() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Security Change Manager" subtitle="Security-aware change management and risk assessment" icon={<GitBranch className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Changes Processed" value="47" icon={<Activity className="h-5 w-5" />} />
        <MetricCard title="Approved" value="32" icon={<CheckCircle className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="High Risk" value="8" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Avg Risk Score" value="0.42" icon={<Shield className="h-5 w-5 text-cyan-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Change Pipeline</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Pending", v: "6", c: "text-yellow-400" }, { l: "Approved", v: "32", c: "text-emerald-400" }, { l: "Rejected", v: "5", c: "text-red-400" }, { l: "Escalated", v: "4", c: "text-orange-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "pending_changes" && (<div className="space-y-3">{CHANGES.map((ch) => (<div key={ch.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{ch.id}</span><span className="ml-2 text-white/90 font-medium">{ch.title}</span></div><StatusBadge status={ch.risk} /></div><p className="text-white/70 text-sm">{ch.service} &mdash; {ch.status}</p><p className="text-white/50 text-xs mt-1">{ch.detail}</p></div>))}</div>)}
      {tab === "risk_assessment" && (<div className="card-surface p-6"><p className="text-white/60">Blast radius analysis, dependency impact scoring, and compliance flag detection across all pending changes.</p></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Rollout Health</h3>{[{ m: "Approval Rate", v: "68%", t: "+3%" }, { m: "Avg Risk Score", v: "0.42", t: "-0.05" }, { m: "Rollback Rate", v: "2.1%", t: "-0.8%" }, { m: "Avg Review Time", v: "14min", t: "-2min" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
