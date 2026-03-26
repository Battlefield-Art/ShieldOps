import { useState } from "react";
import { RefreshCw, Target, AlertTriangle, TrendingUp, CheckCircle, Eye } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "evaluations" | "improvements" | "mistakes";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "evaluations", label: "Evaluations" }, { id: "improvements", label: "Improvements" }, { id: "mistakes", label: "Mistakes" }];
export default function ReflectionEngine() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Reflection Engine" subtitle="Self-evaluation — did my actions work? What would I do differently?" icon={<RefreshCw className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Actions Reviewed" value="847" icon={<Eye className="h-5 w-5" />} />
      <MetricCard title="Effectiveness" value="91.3%" icon={<Target className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Mistakes Found" value="23" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Improvements Applied" value="18" icon={<TrendingUp className="h-5 w-5 text-cyan-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Outcome Assessment</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">
      {[{ outcome: "Effective", count: 772, pct: "91%", color: "text-emerald-400" }, { outcome: "Partial", count: 52, pct: "6%", color: "text-yellow-400" }, { outcome: "Ineffective", count: 20, pct: "2%", color: "text-red-400" }, { outcome: "Counterproductive", count: 3, pct: "0.4%", color: "text-red-400" }].map((o) => (
        <div key={o.outcome} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{o.outcome}</p><p className={clsx("text-3xl font-bold mt-1", o.color)}>{o.pct}</p><p className="text-xs text-white/40">{o.count} actions</p></div>))}</div></div>)}
    {tab === "evaluations" && (<div className="space-y-3">
      {[{ agent: "agentic_mdr", action: "Auto-contained credential theft", outcome: "effective", detail: "Threat neutralized, no lateral movement", time: "2h ago" },
        { agent: "breakout_defender", action: "Isolated compromised host", outcome: "effective", detail: "Breakout prevented, 2.1 min MTTR", time: "6h ago" },
        { agent: "ai_triage_accelerator", action: "Auto-closed benign alert", outcome: "counterproductive", detail: "Was actually a true positive — missed C2 beacon", time: "12h ago" },
      ].map((e, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><span className="text-white/40 text-xs">{e.agent}</span><StatusBadge status={e.outcome} /></div>
        <p className="text-white/90 font-medium">{e.action}</p><p className="text-xs text-white/50">{e.detail} | {e.time}</p></div>))}</div>)}
    {tab === "improvements" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Applied Improvements</h3>
      {[{ improvement: "Lowered FP threshold for DNS-based C2 detection", type: "threshold_adjust", agent: "ai_triage_accelerator", impact: "Caught 3 previously missed C2 beacons" },
        { improvement: "Added lateral movement check before auto-close", type: "playbook_update", agent: "agentic_mdr", impact: "Prevents premature closure of multi-stage attacks" },
        { improvement: "Increased breakout risk weight for cross-cloud pivots", type: "threshold_adjust", agent: "breakout_defender", impact: "Faster containment for cloud-to-cloud attacks" },
      ].map((imp, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{imp.improvement}</p><p className="text-xs text-white/50">{imp.agent} | {imp.type} | {imp.impact}</p></div><CheckCircle className="h-4 w-4 text-emerald-400" /></div>))}</div>)}
    {tab === "mistakes" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Recurring Mistakes</h3>
      {[{ mistake: "Auto-closing DNS tunneling alerts as benign", occurrences: 3, agent: "ai_triage_accelerator", fix: "Added DNS entropy check before auto-close", status: "fixed" },
        { mistake: "Not checking for persistence before declaring contained", occurrences: 2, agent: "breakout_defender", fix: "Added persistence scan step", status: "fixed" },
        { mistake: "Over-escalating low-confidence identity alerts", occurrences: 5, agent: "identity_protection", fix: "Raised escalation threshold from 0.5 to 0.65", status: "monitoring" },
      ].map((m, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><p className="text-white/90 font-medium">{m.mistake}</p><StatusBadge status={m.status} /></div>
        <p className="text-xs text-white/50">{m.occurrences}x | {m.agent} | Fix: {m.fix}</p></div>))}</div>)}
  </div>);
}
