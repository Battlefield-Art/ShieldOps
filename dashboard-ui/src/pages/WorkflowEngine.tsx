import { useState } from "react";
import { Workflow, Play, CheckCircle, Clock, Zap } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "workflows" | "executions" | "gates";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "workflows", label: "Workflows" }, { id: "executions", label: "Executions" }, { id: "gates", label: "Approval Gates" }];
export default function WorkflowEngine() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Workflow Engine" subtitle="Custom security workflow orchestration with approval gates" icon={<Workflow className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Active Workflows" value="3" icon={<Play className="h-5 w-5" />} />
      <MetricCard title="Completed (7d)" value="28" icon={<CheckCircle className="h-5 w-5" />} />
      <MetricCard title="Pending Approvals" value="2" icon={<Clock className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Avg Duration" value="4.2 min" icon={<Zap className="h-5 w-5" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Workflow Library</h3>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {[{ name: "Incident Response", runs: 12, success: 92 }, { name: "Access Revocation", runs: 8, success: 100 }, { name: "Compliance Scan", runs: 8, success: 88 }].map((w) => (
          <div key={w.name} className="card-interactive p-4"><p className="text-sm text-white/60">{w.name}</p><p className="text-2xl font-bold text-white mt-1">{w.runs} runs</p><p className="text-xs text-white/40">{w.success}% success rate</p></div>))}
      </div></div>)}
    {tab === "workflows" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Workflow</th><th className="px-4 py-3">Trigger</th><th className="px-4 py-3">Steps</th><th className="px-4 py-3">Gates</th><th className="px-4 py-3">Timeout</th></tr></thead>
      <tbody>{[
        { name: "incident_response", trigger: "SEV1/SEV2 alert", steps: 6, gates: 1, timeout: "30 min" },
        { name: "access_revocation", trigger: "Termination event", steps: 4, gates: 1, timeout: "15 min" },
        { name: "compliance_scan", trigger: "Scheduled (daily)", steps: 5, gates: 0, timeout: "60 min" },
      ].map((w, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 font-mono text-sm text-cyan-400">{w.name}</td><td className="px-4 py-3 text-white/70">{w.trigger}</td><td className="px-4 py-3 text-white/80">{w.steps}</td><td className="px-4 py-3 text-white/80">{w.gates}</td><td className="px-4 py-3 text-white/60">{w.timeout}</td></tr>))}</tbody></table></div>)}
    {tab === "executions" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Recent Executions</h3>
      {[{ wf: "incident_response", trigger: "INC-5012", status: "completed", steps: "6/6", dur: "3.8 min" },
        { wf: "access_revocation", trigger: "TERM-John.Doe", status: "running", steps: "2/4", dur: "1.2 min" },
        { wf: "compliance_scan", trigger: "Scheduled", status: "paused", steps: "3/5", dur: "—" },
      ].map((e, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium"><span className="font-mono text-cyan-400">{e.wf}</span> → {e.trigger}</p><p className="text-xs text-white/50">Steps: {e.steps} | Duration: {e.dur}</p></div><StatusBadge status={e.status} /></div>))}</div>)}
    {tab === "gates" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Pending Approvals</h3>
      {[{ wf: "access_revocation", gate: "Manager approval for admin revocation", approver: "jane.smith@co.com", waiting: "12 min" },
        { wf: "compliance_scan", gate: "Security review before remediation", approver: "security-team", waiting: "45 min" },
      ].map((g, i) => (<div key={i} className="card-interactive p-4"><p className="text-white/90 font-medium">{g.gate}</p><p className="text-xs text-white/50">{g.wf} | Approver: {g.approver} | Waiting: {g.waiting}</p></div>))}</div>)}
  </div>);
}
