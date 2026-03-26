import { useState } from "react";
import { Gauge, Zap, Target, BarChart3, CheckCircle, XCircle } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "triage" | "accuracy" | "routing";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "triage", label: "Triage Queue" }, { id: "accuracy", label: "Accuracy" }, { id: "routing", label: "Routing" }];
export default function AITriageAccelerator() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="AI Triage Accelerator" subtitle="10x faster investigation with 3x higher accuracy — Claude-powered" icon={<Gauge className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Speedup Factor" value="10.2x" icon={<Zap className="h-5 w-5 text-cyan-400" />} />
      <MetricCard title="Accuracy" value="97.8%" icon={<Target className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="FP Rate" value="2.1%" icon={<XCircle className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Alerts Triaged (24h)" value="1,847" icon={<BarChart3 className="h-5 w-5" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Triage Performance vs Manual</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {[{ label: "AI Avg Triage", value: "0.8 min", compare: "vs 8.5 min manual", color: "text-cyan-400" },
        { label: "AI Accuracy", value: "97.8%", compare: "vs 84% manual", color: "text-emerald-400" },
        { label: "Auto-Closed (FP)", value: "67%", compare: "saves 12h analyst/day", color: "text-white/70" }].map((s) => (
        <div key={s.label} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.label}</p><p className={clsx("text-3xl font-bold mt-1", s.color)}>{s.value}</p><p className="text-xs text-white/40 mt-1">{s.compare}</p></div>))}</div></div>)}
    {tab === "triage" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Alert</th><th className="px-4 py-3">Classification</th><th className="px-4 py-3">Confidence</th><th className="px-4 py-3">Time</th><th className="px-4 py-3">Route</th></tr></thead>
      <tbody>{[
        { alert: "Failed SSH brute force", cls: "false_positive", conf: "0.97", time: "0.3s", route: "auto_close" },
        { alert: "Suspicious PowerShell", cls: "malicious", conf: "0.91", time: "1.2s", route: "auto_remediate" },
        { alert: "Unusual data transfer", cls: "suspicious", conf: "0.68", time: "0.8s", route: "analyst_review" },
        { alert: "Credential stuffing", cls: "true_positive", conf: "0.88", time: "0.5s", route: "auto_remediate" },
      ].map((t, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90">{t.alert}</td><td className="px-4 py-3"><StatusBadge status={t.cls} /></td><td className="px-4 py-3 font-mono text-white/70">{t.conf}</td><td className="px-4 py-3 text-white/60">{t.time}</td><td className="px-4 py-3"><StatusBadge status={t.route} /></td></tr>))}</tbody></table></div>)}
    {tab === "accuracy" && (<div className="card-surface p-6"><h3 className="section-heading">Classification Accuracy (30d)</h3><div className="space-y-3">
      {[{ cls: "True Positive", correct: 892, total: 912, pct: "97.8%" },
        { cls: "False Positive", correct: 1247, total: 1273, pct: "97.9%" },
        { cls: "Benign", correct: 8934, total: 9102, pct: "98.2%" },
        { cls: "Suspicious", correct: 234, total: 267, pct: "87.6%" },
      ].map((a, i) => (<div key={i} className="card-interactive p-3 flex items-center justify-between"><div><p className="text-white/90 font-medium">{a.cls}</p><p className="text-xs text-white/50">{a.correct}/{a.total} correct</p></div><span className="text-emerald-400 font-mono">{a.pct}</span></div>))}</div></div>)}
    {tab === "routing" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Routing Distribution (24h)</h3>
      {[{ route: "Auto-Close (Benign)", count: 1238, pct: "67%", icon: <CheckCircle className="h-4 w-4 text-white/40" /> },
        { route: "Auto-Remediate", count: 371, pct: "20%", icon: <Zap className="h-4 w-4 text-emerald-400" /> },
        { route: "Analyst Review", count: 201, pct: "11%", icon: <Target className="h-4 w-4 text-yellow-400" /> },
        { route: "Urgent Escalation", count: 37, pct: "2%", icon: <XCircle className="h-4 w-4 text-red-400" /> },
      ].map((r, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div className="flex items-center gap-3">{r.icon}<div><p className="text-white/90 font-medium">{r.route}</p><p className="text-xs text-white/50">{r.count} alerts</p></div></div><span className="text-white/70 font-mono">{r.pct}</span></div>))}</div>)}
  </div>);
}
