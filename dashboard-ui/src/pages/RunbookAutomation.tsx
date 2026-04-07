import { useState } from "react";
import { BookOpen, Play, CheckCircle, RotateCcw } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "library" | "executions" | "reliability";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" }, { id: "library", label: "Runbook Library" },
  { id: "executions", label: "Recent Executions" }, { id: "reliability", label: "Step Reliability" },
];
export default function RunbookAutomation() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Runbook Automation" subtitle="Automated runbook execution with approval workflows and rollback" icon={<BookOpen className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Runbooks Available" value="24" icon={<BookOpen className="h-5 w-5" />} />
        <MetricCard title="Executions (7d)" value="47" icon={<Play className="h-5 w-5" />} />
        <MetricCard title="Success Rate" value="94%" icon={<CheckCircle className="h-5 w-5" />} />
        <MetricCard title="Rollbacks" value="3" icon={<RotateCcw className="h-5 w-5 text-yellow-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (
        <div className="card-surface p-6 space-y-4"><h3 className="section-heading">Automation Impact</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {[{ label: "MTTR Reduction", value: "68%", sub: "From 42 min to 13 min avg" }, { label: "Manual Steps Saved", value: "312", sub: "This month" }, { label: "Toil Hours Saved", value: "86h", sub: "This month" }].map((m) => (
              <div key={m.label} className="card-interactive p-4"><p className="text-sm text-white/60">{m.label}</p><p className="text-2xl font-bold text-cyan-400 mt-1">{m.value}</p><p className="text-xs text-white/40">{m.sub}</p></div>
            ))}
          </div>
        </div>
      )}
      {tab === "library" && (
        <div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Runbook</th><th className="px-4 py-3">Trigger</th><th className="px-4 py-3">Steps</th><th className="px-4 py-3">Approval</th><th className="px-4 py-3">Risk</th><th className="px-4 py-3">Last Run</th></tr></thead>
          <tbody>{[
            { name: "restart_service", trigger: "Incident", steps: 4, approval: false, risk: "low", last: "2 hr ago" },
            { name: "rollback_deployment", trigger: "Canary failure", steps: 6, approval: true, risk: "medium", last: "1 day ago" },
            { name: "rotate_credentials", trigger: "Secret exposure", steps: 5, approval: true, risk: "medium", last: "3 days ago" },
            { name: "scale_deployment", trigger: "Load spike", steps: 3, approval: false, risk: "low", last: "4 hr ago" },
            { name: "database_failover", trigger: "DB health check", steps: 8, approval: true, risk: "high", last: "2 weeks ago" },
          ].map((r, i) => (
            <tr key={i} className="border-b border-white/5 hover:bg-white/5">
              <td className="px-4 py-3 font-mono text-sm text-cyan-400">{r.name}</td><td className="px-4 py-3 text-white/70">{r.trigger}</td>
              <td className="px-4 py-3 text-white/80">{r.steps}</td><td className="px-4 py-3">{r.approval ? "Required" : "Auto"}</td>
              <td className="px-4 py-3"><StatusBadge status={r.risk} /></td><td className="px-4 py-3 text-white/50">{r.last}</td>
            </tr>
          ))}</tbody></table>
        </div>
      )}
      {tab === "executions" && (
        <div className="card-surface p-6 space-y-3"><h3 className="section-heading">Recent Executions</h3>
          {[{ runbook: "restart_service", target: "api-gateway", status: "completed", steps: "4/4", duration: "2.3 min", trigger: "INC-4821" },
            { runbook: "scale_deployment", target: "worker-pool", status: "completed", steps: "3/3", duration: "1.1 min", trigger: "Auto-scale" },
            { runbook: "rollback_deployment", target: "billing-svc", status: "rolled_back", steps: "4/6", duration: "5.8 min", trigger: "Canary fail" },
          ].map((e, i) => (
            <div key={i} className="card-interactive p-4 flex items-center justify-between">
              <div><p className="text-white/90 font-medium"><span className="font-mono text-cyan-400">{e.runbook}</span> → {e.target}</p><p className="text-xs text-white/50">Steps: {e.steps} | Duration: {e.duration} | Trigger: {e.trigger}</p></div>
              <StatusBadge status={e.status} />
            </div>
          ))}
        </div>
      )}
      {tab === "reliability" && (
        <div className="card-surface p-6 space-y-3"><h3 className="section-heading">Step Reliability (30d)</h3>
          {[{ step: "kubectl drain", success: 98, runs: 142 }, { step: "kubectl rollout restart", success: 99, runs: 89 }, { step: "vault rotate-secret", success: 95, runs: 34 }, { step: "health check verification", success: 92, runs: 186 }].map((s) => (
            <div key={s.step} className="card-interactive p-4"><div className="flex items-center justify-between mb-2"><p className="text-white/90 font-medium font-mono text-sm">{s.step}</p><span className={clsx("font-bold", s.success >= 95 ? "text-emerald-400" : "text-yellow-400")}>{s.success}%</span></div>
              <div className="h-2 bg-white/10 rounded-full"><div className="h-2 bg-cyan-500 rounded-full" style={{ width: `${s.success}%` }} /></div>
              <p className="text-xs text-white/40 mt-1">{s.runs} executions</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
