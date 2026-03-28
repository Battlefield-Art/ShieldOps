import { useState } from "react";
import { Target, AlertTriangle, Shield, BarChart3, Zap, TrendingUp } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "ranked" | "context" | "actions";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "ranked", label: "Ranked Findings" }, { id: "context", label: "Business Context" }, { id: "actions", label: "Action Plans" }];
export default function RiskPrioritizer() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Risk Prioritizer" subtitle="Fix the right things first — business context + exploitability + blast radius" icon={<Target className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Findings Ranked" value="189" icon={<BarChart3 className="h-5 w-5" />} />
      <MetricCard title="Immediate Action" value="12" icon={<Zap className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Urgent" value="34" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Risk Reduction" value="-23%" icon={<TrendingUp className="h-5 w-5 text-emerald-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Priority Distribution</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">
      {[{ level: "Immediate", count: 12, color: "text-red-400" }, { level: "Urgent", count: 34, color: "text-yellow-400" }, { level: "Scheduled", count: 98, color: "text-white/60" }, { level: "Deferred", count: 45, color: "text-white/40" }].map((l) => (
        <div key={l.level} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{l.level}</p><p className={clsx("text-3xl font-bold mt-1", l.color)}>{l.count}</p></div>))}</div></div>)}
    {tab === "ranked" && (<div className="space-y-3">
      {[{ rank: 1, finding: "SQLi in customer portal (prod)", risk: 9.8, factors: "EPSS 0.97 + customer data + actively exploited", urgency: "immediate" },
        { rank: 2, finding: "Public S3 with PII data", risk: 9.5, factors: "EPSS 0.92 + PII exposure + regulatory", urgency: "immediate" },
        { rank: 3, finding: "Admin credential in git history", risk: 9.2, factors: "Direct access + production + no rotation", urgency: "immediate" },
        { rank: 4, finding: "Unpatched Log4j in API gateway", risk: 8.9, factors: "EPSS 0.95 + internet-facing + critical path", urgency: "urgent" },
      ].map((r) => (<div key={r.rank} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div className="flex items-center gap-3"><span className="text-cyan-400 font-mono text-lg">#{r.rank}</span><div><p className="text-white/90 font-medium">{r.finding}</p><p className="text-xs text-white/50">{r.factors}</p></div></div><div className="text-right"><span className="text-red-400 font-mono text-lg">{r.risk}</span><br/><StatusBadge status={r.urgency} /></div></div></div>))}</div>)}
    {tab === "context" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Risk Factors</h3>
      {[{ factor: "Exploitability (EPSS)", weight: "30%", desc: "How likely is this to be exploited in the wild?" },
        { factor: "Blast Radius", weight: "25%", desc: "How many systems/users are affected if exploited?" },
        { factor: "Asset Criticality", weight: "20%", desc: "Is this a production, customer-facing, or revenue system?" },
        { factor: "Data Sensitivity", weight: "15%", desc: "Does this system handle PII, PHI, PCI, or trade secrets?" },
        { factor: "Regulatory Impact", weight: "10%", desc: "Would this trigger GDPR, HIPAA, PCI, or SOC 2 violations?" },
      ].map((f, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{f.factor} ({f.weight})</p><p className="text-xs text-white/50">{f.desc}</p></div></div>))}</div>)}
    {tab === "actions" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Action Plans</h3>
      {[{ finding: "SQLi in customer portal", plan: "Deploy WAF rule immediately, then fix code in sprint", owner: "AppSec + Dev", deadline: "4 hours" },
        { finding: "Public S3 with PII", plan: "Restrict ACL now, audit all buckets this week", owner: "Cloud Team", deadline: "1 hour" },
        { finding: "Admin cred in git", plan: "Rotate credential, purge git history, enable pre-commit scanning", owner: "DevOps", deadline: "2 hours" },
      ].map((a, i) => (<div key={i} className="card-interactive p-4"><p className="text-white/90 font-medium">{a.finding}</p><p className="text-xs text-white/70 mt-1">{a.plan}</p><p className="text-xs text-white/50">Owner: {a.owner} | Deadline: {a.deadline}</p></div>))}</div>)}
  </div>);
}
