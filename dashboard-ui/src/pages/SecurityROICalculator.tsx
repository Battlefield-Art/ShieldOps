import { useState } from "react";
import { DollarSign, TrendingUp, BarChart3, Target } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "roi_dashboard" | "investment_analysis" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "roi_dashboard", label: "ROI Dashboard" },
  { id: "investment_analysis", label: "Investment Analysis" },
  { id: "metrics", label: "Metrics" },
];

const INVESTMENTS = [
  { id: "INV-001", name: "EDR Platform", cost: "$250K", value: "$2.5M", roi: "900%", status: "high" },
  { id: "INV-002", name: "SIEM Platform", cost: "$180K", value: "$820K", roi: "356%", status: "high" },
  { id: "INV-003", name: "SOC Team", cost: "$450K", value: "$1.8M", roi: "300%", status: "medium" },
  { id: "INV-004", name: "Security Awareness", cost: "$45K", value: "$320K", roi: "611%", status: "high" },
  { id: "INV-005", name: "Annual Pentest", cost: "$85K", value: "$150K", roi: "76%", status: "low" },
];

export default function SecurityROICalculator() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Security ROI Calculator" subtitle="Investment ROI analysis, benchmarking, and value forecasting" icon={<DollarSign className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Total Investment" value="$1.13M" icon={<DollarSign className="h-5 w-5" />} />
        <MetricCard title="Total Value" value="$5.59M" icon={<TrendingUp className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Overall ROI" value="395%" icon={<BarChart3 className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Payback Period" value="3.6 mo" icon={<Target className="h-5 w-5 text-yellow-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Investment Allocation</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Tooling", v: "38%", c: "text-cyan-400" }, { l: "Personnel", v: "40%", c: "text-blue-400" }, { l: "Training", v: "4%", c: "text-emerald-400" }, { l: "Other", v: "18%", c: "text-yellow-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "roi_dashboard" && (<div className="space-y-3">{INVESTMENTS.map((inv) => (<div key={inv.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{inv.id}</span><span className="ml-2 text-white/90 font-medium">{inv.name}</span></div><StatusBadge status={inv.status} /></div><div className="grid grid-cols-3 gap-2 text-sm"><div><span className="text-white/50">Cost:</span> <span className="text-white/80">{inv.cost}</span></div><div><span className="text-white/50">Value:</span> <span className="text-white/80">{inv.value}</span></div><div><span className="text-white/50">ROI:</span> <span className="text-emerald-400 font-mono">{inv.roi}</span></div></div></div>))}</div>)}
      {tab === "investment_analysis" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Benchmark Comparison</h3>{[{ c: "Tooling", org: "38%", ind: "32%", r: "Above average" }, { c: "Personnel", org: "40%", ind: "42%", r: "On track" }, { c: "Training", org: "4%", ind: "8%", r: "Below average" }, { c: "Consulting", org: "8%", ind: "10%", r: "On track" }].map((b, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{b.c}</p><p className="text-xs text-white/50">Org: {b.org} | Industry: {b.ind}</p></div><span className="text-sm text-white/60">{b.r}</span></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">ROI Trends</h3>{[{ m: "Breach Cost Avoided", v: "$2.5M", t: "+$400K" }, { m: "Risk Reduction", v: "40%", t: "+8%" }, { m: "MTTR Improvement", v: "82%", t: "+12%" }, { m: "Compliance Savings", v: "$150K", t: "+$25K" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
