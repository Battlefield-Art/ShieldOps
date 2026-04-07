import { useState } from "react";
import { Filter, Bell, AlertTriangle, Users, TrendingDown } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "noise_analysis" | "tuning_suggestions" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "noise_analysis", label: "Noise Analysis" },
  { id: "tuning_suggestions", label: "Tuning Suggestions" },
  { id: "metrics", label: "Metrics" },
];

const RULES = [
  { id: "RULE-001", name: "Failed SSH Login", noise: 0.82, category: "false_positive", count24h: 1240, status: "critical" },
  { id: "RULE-002", name: "Port Scan Detected", noise: 0.90, category: "low_fidelity", count24h: 3400, status: "critical" },
  { id: "RULE-003", name: "Cert Expiry Warning", noise: 0.71, category: "stale_rule", count24h: 890, status: "warning" },
  { id: "RULE-004", name: "Excessive API Rate", noise: 0.68, category: "threshold_drift", count24h: 560, status: "warning" },
  { id: "RULE-005", name: "DNS Bad Domain", noise: 0.18, category: "valid", count24h: 45, status: "healthy" },
  { id: "RULE-006", name: "Malware Signature", noise: 0.06, category: "valid", count24h: 8, status: "healthy" },
];

const TUNINGS = [
  { rule: "Failed SSH Login", action: "Raise threshold to 10/min", reduction: "72%", risk: "low" },
  { rule: "Port Scan Detected", action: "Deduplicate by source IP", reduction: "85%", risk: "low" },
  { rule: "Cert Expiry Warning", action: "Aggregate to daily digest", reduction: "95%", risk: "medium" },
  { rule: "Excessive API Rate", action: "Adjust from 100/s to 500/s", reduction: "60%", risk: "medium" },
];

export default function AlertFatigueReducer() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Alert Fatigue Reducer" subtitle="Alert noise detection, analyst fatigue scoring, and rule tuning" icon={<Filter className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Alerts (24h)" value="6,160" icon={<Bell className="h-5 w-5" />} />
        <MetricCard title="Noise Rate" value="68%" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Analysts at Risk" value="2" icon={<Users className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Est. Reduction" value="74%" icon={<TrendingDown className="h-5 w-5 text-emerald-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Fatigue Indicators</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "High Noise Rules", v: "4", c: "text-red-400" }, { l: "False Positives", v: "68%", c: "text-yellow-400" }, { l: "Avg Triage Time", v: "8.3m", c: "text-cyan-400" }, { l: "Dismiss Rate", v: "42%", c: "text-orange-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "noise_analysis" && (<div className="space-y-3">{RULES.map((r) => (<div key={r.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{r.id}</span><span className="ml-2 text-white/90 font-medium">{r.name}</span></div><StatusBadge status={r.status} /></div><div className="flex items-center gap-4 text-sm text-white/60"><span>Noise: {(r.noise * 100).toFixed(0)}%</span><span>Category: {r.category}</span><span>24h: {r.count24h.toLocaleString()}</span></div></div>))}</div>)}
      {tab === "tuning_suggestions" && (<div className="space-y-3">{TUNINGS.map((t, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="text-white/90 font-medium">{t.rule}</span></div><StatusBadge status={t.risk} /></div><p className="text-white/70 text-sm">{t.action}</p><p className="text-xs text-emerald-400 mt-1">Expected reduction: {t.reduction}</p></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Reduction Trends</h3>{[{ m: "Noise Rate (30d)", v: "68%", t: "-12%" }, { m: "False Positive Rate", v: "62%", t: "-8%" }, { m: "Avg Triage Time", v: "8.3m", t: "-2.1m" }, { m: "Analyst Satisfaction", v: "7.2/10", t: "+1.4" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
