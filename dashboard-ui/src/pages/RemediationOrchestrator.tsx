import { useState } from "react";
import { Workflow, Zap, AlertTriangle, Target, BarChart3 } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "pipeline" | "tickets" | "metrics";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "pipeline", label: "Pipeline" }, { id: "tickets", label: "Tickets" }, { id: "metrics", label: "Metrics" }];
export default function RemediationOrchestrator() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Remediation Orchestrator" subtitle="Full pipeline: discovery → finding → ticket → fix → verify" icon={<Workflow className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Findings Processed" value="234" icon={<Target className="h-5 w-5" />} />
      <MetricCard title="Auto-Remediated" value="142" icon={<Zap className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Tickets Created" value="67" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="MTTR" value="4.2h" icon={<BarChart3 className="h-5 w-5 text-cyan-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Routing Decisions</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">
      {[{ route: "Auto-Remediate", count: 142, pct: "60.7%", color: "text-emerald-400" }, { route: "Create Ticket", count: 67, pct: "28.6%", color: "text-cyan-400" }, { route: "Escalate", count: 18, pct: "7.7%", color: "text-yellow-400" }, { route: "Accept Risk", count: 7, pct: "3.0%", color: "text-white/40" }].map((r) => (
        <div key={r.route} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{r.route}</p><p className={clsx("text-3xl font-bold mt-1", r.color)}>{r.pct}</p><p className="text-xs text-white/40">{r.count} findings</p></div>))}</div></div>)}
    {tab === "pipeline" && (<div className="card-surface p-6"><h3 className="section-heading">Autonomous Pipeline</h3><div className="space-y-2">
      {[{ stage: "Discovery", agents: "network_pentest, web_app_scanner, cloud_pentest", findings: 234 },
        { stage: "Classification", agents: "remediation_orchestrator", findings: 234 },
        { stage: "Auto-Fix", agents: "config_remediation, patch_orchestrator, access_remediation", findings: 142 },
        { stage: "Ticket", agents: "JIRA/ServiceNow integration", findings: 67 },
        { stage: "Verification", agents: "remediation_verifier", findings: 142 },
      ].map((s, i) => (<div key={i} className="card-interactive p-3 flex items-center justify-between"><div className="flex items-center gap-3"><span className="text-cyan-400 font-mono w-6">{i + 1}.</span><div><p className="text-white/90 font-medium">{s.stage}</p><p className="text-xs text-white/40">{s.agents}</p></div></div><span className="text-white/60">{s.findings}</span></div>))}</div></div>)}
    {tab === "tickets" && (<div className="space-y-3">
      {[{ id: "JIRA-1234", title: "Fix XSS in customer portal search", priority: "p1", assignee: "AppSec Team", source: "web_app_scanner", status: "in_progress" },
        { id: "JIRA-1235", title: "Remediate IAM wildcard policy", priority: "p0", assignee: "Cloud Team", source: "cloud_pentest", status: "open" },
        { id: "SN-5678", title: "Rotate leaked API key", priority: "p0", assignee: "DevOps", source: "credential_tester", status: "resolved" },
      ].map((t) => (<div key={t.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{t.id}</span><span className="text-xs text-white/40 ml-2">{t.source}</span></div><StatusBadge status={t.priority} /></div>
        <p className="text-white/90 font-medium">{t.title}</p><p className="text-xs text-white/50">Assignee: {t.assignee} | <StatusBadge status={t.status} /></p></div>))}</div>)}
    {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Remediation Metrics</h3>
      {[{ metric: "Mean Time to Remediate", value: "4.2 hours", trend: "-67% vs manual", status: "improving" },
        { metric: "Auto-Remediation Rate", value: "60.7%", trend: "+12% vs last month", status: "improving" },
        { metric: "Verification Pass Rate", value: "92.3%", trend: "Stable", status: "stable" },
        { metric: "Regression Rate", value: "1.9%", trend: "-0.5% vs last month", status: "improving" },
        { metric: "SLA Compliance", value: "94.8%", trend: "+3% vs last month", status: "improving" },
      ].map((m, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{m.metric}</p><p className="text-xs text-white/50">{m.value} | {m.trend}</p></div><StatusBadge status={m.status} /></div>))}</div>)}
  </div>);
}
