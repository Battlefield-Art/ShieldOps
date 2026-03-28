import { useState } from "react";
import { Cpu, Activity, AlertTriangle, CheckCircle, TrendingUp, Zap } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "health" | "schedule" | "actions";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "health", label: "Health" }, { id: "schedule", label: "Schedule" }, { id: "actions", label: "Actions" }];
export default function AgentFleetOptimizer() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Agent Fleet Optimizer" subtitle="Monitor health, optimize scheduling, auto-scale the agent army" icon={<Cpu className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Total Agents" value="180" icon={<Cpu className="h-5 w-5" />} />
      <MetricCard title="Healthy" value="176" icon={<CheckCircle className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Issues" value="4" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Utilization" value="14.3%" icon={<Activity className="h-5 w-5 text-cyan-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Fleet Status</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">
      {[{ status: "Healthy", count: 176, color: "text-emerald-400" }, { status: "Degraded", count: 2, color: "text-yellow-400" }, { status: "Idle", count: 152, color: "text-white/40" }, { status: "Active", count: 24, color: "text-cyan-400" }].map((s) => (
        <div key={s.status} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.status}</p><p className={clsx("text-3xl font-bold mt-1", s.color)}>{s.count}</p></div>))}</div></div>)}
    {tab === "health" && (<div className="space-y-3">
      {[{ agent: "phishing_simulator", status: "degraded", issue: "No heartbeat for 2 hours", action: "Restart recommended" },
        { agent: "web_app_scanner", status: "degraded", issue: "High memory usage (92%)", action: "Scale up recommended" },
        { agent: "network_pentest", status: "healthy", issue: "None", action: "No action needed" },
        { agent: "security_pipeline", status: "healthy", issue: "None", action: "No action needed" },
      ].map((a, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{a.agent}</p><p className="text-xs text-white/50">{a.issue} | {a.action}</p></div><StatusBadge status={a.status} /></div>))}</div>)}
    {tab === "schedule" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Schedule Optimization</h3>
      {[{ opt: "Stagger network + cloud scans", reason: "Both run at 2am causing resource contention", impact: "-40% peak CPU" },
        { opt: "Reduce credential_tester frequency", reason: "Daily is overkill for static accounts", impact: "-30% API calls" },
        { opt: "Scale up web_app_scanner during deploys", reason: "Deploy-triggered scans timeout at current capacity", impact: "+50% scan speed" },
      ].map((o, i) => (<div key={i} className="card-interactive p-4"><p className="text-white/90 font-medium">{o.opt}</p><p className="text-xs text-white/50">{o.reason}</p><p className="text-xs text-cyan-400">Impact: {o.impact}</p></div>))}</div>)}
    {tab === "actions" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Recommended Actions</h3>
      {[{ action: "Restart phishing_simulator", reason: "No heartbeat 2h", urgency: "high", status: "pending" },
        { action: "Scale up web_app_scanner to 2 replicas", reason: "Memory pressure during scans", urgency: "medium", status: "pending" },
        { action: "Disable deprecated otel_pipeline v1", reason: "Replaced by otel_logs_pipeline", urgency: "low", status: "pending" },
      ].map((a, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{a.action}</p><p className="text-xs text-white/50">{a.reason}</p></div><StatusBadge status={a.urgency} /></div>))}</div>)}
  </div>);
}
