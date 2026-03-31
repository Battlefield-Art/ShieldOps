import { useState } from "react";
import { DollarSign, BarChart3, Layers, TrendingUp, Shield, Target } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "tool_effectiveness" | "budget_allocation" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "tool_effectiveness", label: "Tool Effectiveness" },
  { id: "budget_allocation", label: "Budget Allocation" },
  { id: "metrics", label: "Metrics" },
];

const TOOLS = [
  { name: "CrowdStrike Falcon", category: "EDR", cost: "$420K", roi: "3.2x", effectiveness: "high" },
  { name: "Splunk Enterprise", category: "SIEM", cost: "$680K", roi: "1.8x", effectiveness: "medium" },
  { name: "Palo Alto Prisma", category: "Cloud Security", cost: "$310K", roi: "2.5x", effectiveness: "high" },
  { name: "Tenable.io", category: "Vuln Mgmt", cost: "$95K", roi: "4.1x", effectiveness: "high" },
  { name: "Legacy Scanner", category: "Vuln Mgmt", cost: "$140K", roi: "0.3x", effectiveness: "low" },
];

export default function SecurityBudgetOptimizer() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Security Budget Optimizer" subtitle="Security investment ROI analysis and budget optimization" icon={<DollarSign className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Total Spend" value="$2.4M" icon={<DollarSign className="h-5 w-5" />} />
        <MetricCard title="Avg ROI" value="2.1x" icon={<TrendingUp className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Overlap Found" value="8 pairs" icon={<Layers className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Savings Potential" value="$340K" icon={<Target className="h-5 w-5 text-cyan-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Spend by Category</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "EDR", v: "$420K", c: "text-red-400" }, { l: "SIEM", v: "$680K", c: "text-orange-400" }, { l: "Cloud Security", v: "$310K", c: "text-cyan-400" }, { l: "Vuln Mgmt", v: "$235K", c: "text-emerald-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "tool_effectiveness" && (<div className="space-y-3">{TOOLS.map((t) => (<div key={t.name} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="text-white/90 font-medium">{t.name}</span><span className="ml-2 text-xs text-white/40">{t.category}</span></div><StatusBadge status={t.effectiveness} /></div><div className="flex items-center gap-4 text-sm"><span className="text-white/50">{t.cost}/yr</span><span className="text-cyan-400">ROI: {t.roi}</span></div></div>))}</div>)}
      {tab === "budget_allocation" && (<div className="card-surface p-6"><h3 className="section-heading">Recommended Actions</h3><div className="space-y-2">{[{ tool: "Legacy Scanner", action: "Divest", savings: "$140K", risk: "low" }, { tool: "Splunk Enterprise", action: "Optimize License", savings: "$95K", risk: "medium" }, { tool: "Tenable.io", action: "Invest More", savings: "-$30K", risk: "low" }, { tool: "CrowdStrike Falcon", action: "Maintain", savings: "$0", risk: "low" }].map((a, i) => (<div key={i} className="card-interactive p-3 flex items-center justify-between text-sm"><div><span className="text-white/90">{a.tool}</span><span className="ml-2 text-white/40">{a.action}</span></div><div className="flex gap-3"><span className={clsx("font-mono", a.savings.startsWith("-") ? "text-orange-400" : "text-emerald-400")}>{a.savings}</span><StatusBadge status={a.risk} /></div></div>))}</div></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Budget Trends</h3>{[{ m: "Annual Spend", v: "$2.4M", t: "-$180K vs last year" }, { m: "Avg Tool ROI", v: "2.1x", t: "+0.3x" }, { m: "Redundancy Rate", v: "18%", t: "-5%" }, { m: "Budget Efficiency", v: "84%", t: "+7%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
