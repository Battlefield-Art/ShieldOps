import { useState } from "react";
import { Filter, BarChart3, AlertTriangle, Zap, Layers, TrendingUp } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "rule_performance" | "tuning_suggestions" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "rule_performance", label: "Rule Performance" },
  { id: "tuning_suggestions", label: "Tuning Suggestions" },
  { id: "metrics", label: "Metrics" },
];

const RULES = [
  { id: "DET-001", name: "Brute Force Login", category: "Threshold", precision: "42%", fp_rate: "58%", volume: 340, status: "poor" },
  { id: "DET-002", name: "Lateral Movement RDP", category: "Behavioral", precision: "91%", fp_rate: "9%", volume: 12, status: "excellent" },
  { id: "DET-003", name: "DNS Tunneling", category: "Anomaly", precision: "67%", fp_rate: "33%", volume: 85, status: "fair" },
  { id: "DET-004", name: "Privilege Escalation", category: "Correlation", precision: "78%", fp_rate: "22%", volume: 28, status: "good" },
];

const TUNINGS = [
  { id: "TUN-001", rule: "Brute Force Login", action: "Raise threshold from 5 to 15 attempts", impact: "FP reduction: 65%", risk: "low" },
  { id: "TUN-002", rule: "DNS Tunneling", action: "Add allowlist for CDN domains", impact: "FP reduction: 40%", risk: "medium" },
  { id: "TUN-003", rule: "Noisy Firewall Drops", action: "Consolidate with DET-009", impact: "Alert reduction: 120/day", risk: "low" },
];

export default function SIEMRuleOptimizer() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="SIEM Rule Optimizer" subtitle="Detection rule optimization and false positive reduction" icon={<Filter className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Total Rules" value="312" icon={<Layers className="h-5 w-5" />} />
        <MetricCard title="Noisy Rules" value="47" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="FP Reduction" value="34%" icon={<TrendingUp className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Overlapping" value="18" icon={<Zap className="h-5 w-5 text-cyan-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Rule Health Distribution</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Excellent", v: "142", c: "text-emerald-400" }, { l: "Good", v: "89", c: "text-cyan-400" }, { l: "Fair", v: "34", c: "text-yellow-400" }, { l: "Poor", v: "47", c: "text-red-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "rule_performance" && (<div className="space-y-3">{RULES.map((r) => (<div key={r.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{r.id}</span><span className="ml-2 text-xs text-white/40">{r.category}</span></div><StatusBadge status={r.status} /></div><p className="text-white/90 text-sm">{r.name}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>Precision: {r.precision}</span><span className={parseInt(r.fp_rate) > 30 ? "text-red-400" : "text-white/40"}>FP Rate: {r.fp_rate}</span><span>{r.volume} alerts/day</span></div></div>))}</div>)}
      {tab === "tuning_suggestions" && (<div className="space-y-3">{TUNINGS.map((t) => (<div key={t.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{t.id}</span><span className="ml-2 text-xs text-white/40">{t.rule}</span></div><StatusBadge status={t.risk} /></div><p className="text-white/90 text-sm">{t.action}</p><span className="text-xs text-emerald-400">{t.impact}</span></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Optimization Metrics</h3>{[{ m: "Avg Precision", v: "76%", t: "+8%" }, { m: "Alert Volume Reduction", v: "42%", t: "+12%" }, { m: "Rules Tuned (30d)", v: "23", t: "+7" }, { m: "Overlap Groups", v: "18", t: "-3" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
