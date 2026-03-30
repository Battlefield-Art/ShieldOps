import { useState } from "react";
import { BarChart3, Clock, Shield, TrendingUp, Users, Zap } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "bottlenecks" | "benchmarks" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "bottlenecks", label: "Bottlenecks" },
  { id: "benchmarks", label: "Benchmarks" },
  { id: "metrics", label: "Recommendations" },
];

const BOTTLENECKS = [
  { id: "BN-001", area: "Tier 1 Triage", severity: "high", detail: "Average triage time 12.4 min (target: 5 min) — insufficient staffing in APAC shift", recommendation: "Add 2 analysts to APAC rotation or enable AI auto-triage" },
  { id: "BN-002", area: "Alert Fatigue", severity: "high", detail: "67% of alerts are false positives — analysts ignoring low-confidence alerts", recommendation: "Tune detection rules, implement SOAR enrichment pre-triage" },
  { id: "BN-003", area: "Escalation Delay", severity: "medium", detail: "Avg escalation to Tier 2 takes 45 min (target: 15 min)", recommendation: "Implement automated escalation based on MITRE ATT&CK mapping" },
  { id: "BN-004", area: "Tool Switching", severity: "medium", detail: "Analysts switching between 7 tools per investigation", recommendation: "Consolidate into unified investigation workspace" },
];

export default function SOCMetricsAnalyzer() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="SOC Metrics Analyzer" subtitle="SOC performance analytics with industry benchmarking" icon={<BarChart3 className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="MTTD" value="3.2 min" icon={<Clock className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="MTTR" value="18 min" icon={<Zap className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Alerts/Day" value="1,247" icon={<Shield className="h-5 w-5" />} />
        <MetricCard title="Analyst Util" value="78%" icon={<Users className="h-5 w-5 text-cyan-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">SOC Performance</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Detection", v: "A", c: "text-emerald-400" }, { l: "Response", v: "B+", c: "text-cyan-400" }, { l: "Coverage", v: "A-", c: "text-emerald-400" }, { l: "Efficiency", v: "B", c: "text-yellow-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "bottlenecks" && (<div className="space-y-3">{BOTTLENECKS.map((b) => (<div key={b.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{b.id}</span><span className="ml-2 text-white/90 font-medium">{b.area}</span></div><StatusBadge status={b.severity} /></div><p className="text-white/70 text-sm">{b.detail}</p><p className="text-emerald-400/70 text-xs mt-2">{b.recommendation}</p></div>))}</div>)}
      {tab === "benchmarks" && (<div className="card-surface p-6"><h3 className="section-heading">Industry Benchmarks</h3><div className="space-y-2">{[{ metric: "MTTD", yours: "3.2 min", industry: "8.5 min", status: "better" }, { metric: "MTTR", yours: "18 min", industry: "12 min", status: "worse" }, { metric: "FP Rate", yours: "67%", industry: "45%", status: "worse" }, { metric: "Coverage", yours: "94%", industry: "82%", status: "better" }].map((b, i) => (<div key={i} className="card-interactive p-3 flex items-center justify-between text-sm"><span className="text-white/90 w-24">{b.metric}</span><span className="text-cyan-400 font-mono">{b.yours}</span><span className="text-white/40">vs {b.industry}</span><span className={b.status === "better" ? "text-emerald-400" : "text-red-400"}>{b.status === "better" ? "Above" : "Below"}</span></div>))}</div></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Improvement Recommendations</h3>{[{ m: "Deploy AI Auto-Triage", v: "High Impact", t: "Reduce MTTR by 40%" }, { m: "Tune Detection Rules", v: "High Impact", t: "Reduce FP rate to 35%" }, { m: "Add APAC Analysts", v: "Medium Impact", t: "Cover 24/7 gap" }, { m: "Unified Workspace", v: "Medium Impact", t: "Save 8 min/investigation" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono text-sm">{x.v}</span></div>))}</div>)}
    </div>
  );
}
