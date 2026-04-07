import { useState } from "react";
import { FileText, Search, TrendingUp, CheckCircle } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "root_cause" | "lessons" | "recommendations";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "root_cause", label: "Root Cause" }, { id: "lessons", label: "Lessons" }, { id: "recommendations", label: "Recommendations" }];
export default function PostIncidentAnalyzer() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Post-Incident Analyzer" subtitle="Automated post-mortem — root cause, lessons learned, recommendations" icon={<FileText className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Post-Mortems" value="24" icon={<FileText className="h-5 w-5" />} />
      <MetricCard title="Root Causes Found" value="22" icon={<Search className="h-5 w-5 text-cyan-400" />} />
      <MetricCard title="Lessons Applied" value="89%" icon={<CheckCircle className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Recurring Reduced" value="-67%" icon={<TrendingUp className="h-5 w-5 text-emerald-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Root Cause Categories</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">
      {[{ cat: "Human Error", count: 8, pct: "33%", color: "text-yellow-400" }, { cat: "Process Gap", count: 7, pct: "29%", color: "text-yellow-400" }, { cat: "Technical Failure", count: 5, pct: "21%", color: "text-red-400" }, { cat: "Third Party", count: 4, pct: "17%", color: "text-white/60" }].map((c) => (
        <div key={c.cat} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{c.cat}</p><p className={clsx("text-3xl font-bold mt-1", c.color)}>{c.pct}</p></div>))}</div></div>)}
    {tab === "root_cause" && (<div className="space-y-3">
      {[{ incident: "IR-089", cause: "Phishing email bypassed email gateway — no DMARC enforcement", category: "process_gap", impact: "Admin credential compromise + data exposure" },
        { incident: "IR-085", cause: "Unpatched Log4j on internal API — missed by vulnerability scanner", category: "technical_failure", impact: "Remote code execution" },
      ].map((r, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><span className="font-mono text-xs text-cyan-400">{r.incident}</span><StatusBadge status={r.category} /></div>
        <p className="text-white/90 font-medium">{r.cause}</p><p className="text-xs text-white/50">Impact: {r.impact}</p></div>))}</div>)}
    {tab === "lessons" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Lessons Learned</h3>
      {[{ lesson: "Enforce DMARC on all domains", source: "IR-089", status: "implemented", recurrence: "0 since" },
        { lesson: "Add Log4j to continuous scanner schedule", source: "IR-085", status: "implemented", recurrence: "0 since" },
        { lesson: "Enable MFA number matching (prevent fatigue)", source: "IR-082", status: "in_progress", recurrence: "1 since" },
      ].map((l, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{l.lesson}</p><p className="text-xs text-white/50">{l.source} | Recurrence: {l.recurrence}</p></div><StatusBadge status={l.status} /></div>))}</div>)}
    {tab === "recommendations" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">AI-Generated Recommendations</h3>
      {[{ rec: "Deploy phishing_simulator monthly for all departments with >15% click rate", priority: "high", source: "Pattern: 3 phishing incidents in 2 months" },
        { rec: "Enable continuous_scanner for all internal APIs (not just external)", priority: "high", source: "Pattern: 2 unpatched internal services exploited" },
        { rec: "Add credential rotation automation for service accounts >90 days old", priority: "medium", source: "Pattern: stale SA credentials used in 4 incidents" },
      ].map((r, i) => (<div key={i} className="card-interactive p-4"><p className="text-white/90 font-medium">{r.rec}</p><p className="text-xs text-white/50">{r.source}</p><StatusBadge status={r.priority} /></div>))}</div>)}
  </div>);
}
