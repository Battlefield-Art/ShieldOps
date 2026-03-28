import { useState } from "react";
import { LayoutDashboard, Activity, Shield, BarChart3, Zap, Clock } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "kpis" | "agents" | "anomalies";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "kpis", label: "KPIs" }, { id: "agents", label: "Agent Fleet" }, { id: "anomalies", label: "Anomalies" }];
export default function SecurityDashboardAggregator() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Security Dashboard" subtitle="Unified CISO view — metrics from all 174 agents in one place" icon={<LayoutDashboard className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Security Score" value="B+ (82)" icon={<Shield className="h-5 w-5 text-cyan-400" />} />
      <MetricCard title="Agents Active" value="24/174" icon={<Activity className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="MTTR" value="4.2h" icon={<Clock className="h-5 w-5 text-cyan-400" />} />
      <MetricCard title="Findings Open" value="67" icon={<Zap className="h-5 w-5 text-yellow-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Security Domains</h3><div className="grid grid-cols-2 md:grid-cols-4 gap-3">
      {[{ domain: "Detection", score: 82, agents: 15, color: "text-cyan-400" }, { domain: "Prevention", score: 78, agents: 12, color: "text-cyan-400" }, { domain: "Response", score: 71, agents: 18, color: "text-yellow-400" }, { domain: "Compliance", score: 91, agents: 8, color: "text-emerald-400" }, { domain: "Coverage", score: 78, agents: 6, color: "text-cyan-400" }, { domain: "Operations", score: 85, agents: 14, color: "text-emerald-400" }].map((d) => (
        <div key={d.domain} className="card-interactive p-3 text-center"><p className="text-xs text-white/60">{d.domain}</p><p className={clsx("text-2xl font-bold mt-1", d.color)}>{d.score}</p><p className="text-xs text-white/30">{d.agents} agents</p></div>))}</div></div>)}
    {tab === "kpis" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">KPI</th><th className="px-4 py-3">Current</th><th className="px-4 py-3">Target</th><th className="px-4 py-3">Status</th></tr></thead>
      <tbody>{[
        { kpi: "Mean Time to Detect (MTTD)", current: "1.8 min", target: "<5 min", status: "on_target" },
        { kpi: "Mean Time to Respond (MTTR)", current: "4.2 hours", target: "<8 hours", status: "on_target" },
        { kpi: "Patch Compliance", current: "95.9%", target: ">95%", status: "on_target" },
        { kpi: "MITRE Coverage", current: "78.4%", target: ">85%", status: "at_risk" },
        { kpi: "Detection Rate", current: "82.0%", target: ">90%", status: "at_risk" },
        { kpi: "Auto-Remediation Rate", current: "61%", target: ">70%", status: "off_target" },
        { kpi: "Phishing Click Rate", current: "12.3%", target: "<10%", status: "at_risk" },
        { kpi: "SLA Compliance", current: "94.8%", target: ">95%", status: "at_risk" },
      ].map((k, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90">{k.kpi}</td><td className="px-4 py-3 font-mono text-white/80">{k.current}</td><td className="px-4 py-3 text-white/50">{k.target}</td><td className="px-4 py-3"><StatusBadge status={k.status} /></td></tr>))}</tbody></table></div>)}
    {tab === "agents" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Agent Fleet Status</h3>
      {[{ category: "Offensive (Phase A)", total: 6, active: 3, idle: 3, status: "healthy" },
        { category: "Remediation (Phase B)", total: 6, active: 2, idle: 4, status: "healthy" },
        { category: "Coverage (Phase C)", total: 6, active: 1, idle: 5, status: "healthy" },
        { category: "Orchestration (Phase D)", total: 6, active: 4, idle: 2, status: "healthy" },
        { category: "Core Security", total: 150, active: 14, idle: 136, status: "healthy" },
      ].map((f, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{f.category}</p><p className="text-xs text-white/50">{f.active} active | {f.idle} idle | {f.total} total</p></div><StatusBadge status={f.status} /></div>))}</div>)}
    {tab === "anomalies" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Metric Anomalies</h3>
      {[{ metric: "Finding volume spike", detail: "3x normal findings from cloud_pentest — new assets discovered?", severity: "info" },
        { metric: "MTTR increase", detail: "Response time up 40% this week — remediation pipeline bottleneck", severity: "warning" },
        { metric: "Agent health", detail: "phishing_simulator agent hasn't reported in 2 hours", severity: "warning" },
      ].map((a, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{a.metric}</p><p className="text-xs text-white/50">{a.detail}</p></div><StatusBadge status={a.severity} /></div>))}</div>)}
  </div>);
}
