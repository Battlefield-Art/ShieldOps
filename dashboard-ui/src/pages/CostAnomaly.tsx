import { useState } from "react";
import { DollarSign, AlertTriangle, Trash2, Zap } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "anomalies" | "waste" | "llm_costs";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" }, { id: "anomalies", label: "Cost Anomalies" },
  { id: "waste", label: "Resource Waste" }, { id: "llm_costs", label: "LLM Costs" },
];

export default function CostAnomaly() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Cost Anomaly Detector" subtitle="Cloud cost spike detection, billing anomalies, and resource waste identification" icon={<DollarSign className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Monthly Spend" value="$47.2K" icon={<DollarSign className="h-5 w-5" />} />
        <MetricCard title="Anomalies (7d)" value="4" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Monthly Waste" value="$4.8K" icon={<Trash2 className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="LLM Cost (MTD)" value="$8.1K" icon={<Zap className="h-5 w-5" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (
        <div className="card-surface p-6 space-y-4">
          <h3 className="section-heading">Cost Breakdown by Service</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {[{ svc: "Compute (EC2/GCE)", cost: "$18.4K", pct: 39, trend: "+12%" }, { svc: "LLM APIs", cost: "$8.1K", pct: 17, trend: "+28%" }, { svc: "Storage + DB", cost: "$12.3K", pct: 26, trend: "-3%" }].map((s) => (
              <div key={s.svc} className="card-interactive p-4"><p className="text-sm text-white/60">{s.svc}</p><p className="text-2xl font-bold text-white mt-1">{s.cost}</p><p className="text-xs text-white/40">{s.pct}% of total | Trend: <span className={s.trend.startsWith("+") ? "text-red-400" : "text-emerald-400"}>{s.trend}</span></p></div>
            ))}
          </div>
        </div>
      )}
      {tab === "anomalies" && (
        <div className="card-surface overflow-hidden">
          <table className="w-full text-sm">
            <thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Resource</th><th className="px-4 py-3">Type</th><th className="px-4 py-3">Expected</th><th className="px-4 py-3">Actual</th><th className="px-4 py-3">Deviation</th><th className="px-4 py-3">Severity</th></tr></thead>
            <tbody>
              {[
                { resource: "i-0abc123 (EC2)", type: "Cost Spike", expected: "$120/day", actual: "$528/day", deviation: "+340%", sev: "critical" },
                { resource: "claude-3-opus", type: "LLM Overrun", expected: "$150/day", actual: "$420/day", deviation: "+180%", sev: "high" },
                { resource: "rds-analytics", type: "Billing Error", expected: "$85/day", actual: "$340/day", deviation: "+300%", sev: "high" },
                { resource: "s3-logs-archive", type: "Gradual Drift", expected: "$30/day", actual: "$52/day", deviation: "+73%", sev: "medium" },
              ].map((a, i) => (
                <tr key={i} className="border-b border-white/5 hover:bg-white/5">
                  <td className="px-4 py-3 font-mono text-xs text-cyan-400">{a.resource}</td>
                  <td className="px-4 py-3 text-white/70">{a.type}</td>
                  <td className="px-4 py-3 text-white/60">{a.expected}</td>
                  <td className="px-4 py-3 text-white/80">{a.actual}</td>
                  <td className="px-4 py-3 text-red-400 font-bold">{a.deviation}</td>
                  <td className="px-4 py-3"><StatusBadge status={a.sev} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {tab === "waste" && (
        <div className="card-surface p-6 space-y-3">
          <h3 className="section-heading">Resource Waste ($4,800/mo identified)</h3>
          {[
            { resource: "i-0def456 (m5.xlarge)", type: "Idle Compute", util: "2%", waste: "$1,200/mo", action: "Terminate" },
            { resource: "vol-0ghi789 (500GB)", type: "Unattached Volume", util: "0%", waste: "$50/mo", action: "Delete" },
            { resource: "i-0jkl012 (r5.2xlarge)", type: "Oversized Instance", util: "8%", waste: "$2,400/mo", action: "Downsize to r5.large" },
            { resource: "nat-gateway-staging", type: "Orphaned Resource", util: "0%", waste: "$1,150/mo", action: "Delete" },
          ].map((w, i) => (
            <div key={i} className="card-interactive p-4 flex items-center justify-between">
              <div><p className="text-white/90 font-medium">{w.resource}</p><p className="text-xs text-white/50">{w.type} | Utilization: {w.util} | Waste: <span className="text-red-400">{w.waste}</span></p></div>
              <span className="text-xs text-cyan-400">{w.action}</span>
            </div>
          ))}
        </div>
      )}
      {tab === "llm_costs" && (
        <div className="card-surface p-6 space-y-4">
          <h3 className="section-heading">LLM API Cost Breakdown (MTD: $8,100)</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {[{ model: "Claude Opus", cost: "$4,200", tokens: "12.4M", agents: 8 }, { model: "Claude Sonnet", cost: "$2,800", tokens: "28.6M", agents: 42 }, { model: "Claude Haiku", cost: "$1,100", tokens: "45.2M", agents: 21 }].map((l) => (
              <div key={l.model} className="card-interactive p-4"><p className="text-sm text-white/60">{l.model}</p><p className="text-2xl font-bold text-white mt-1">{l.cost}</p><p className="text-xs text-white/40">{l.tokens} tokens | {l.agents} agents</p></div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
