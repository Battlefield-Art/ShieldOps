import { useState } from "react";
import { Workflow, Play, Activity, CheckCircle } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "workflows" | "execution_log" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "workflows", label: "Workflows" },
  { id: "execution_log", label: "Execution Log" },
  { id: "metrics", label: "Metrics" },
];

const WORKFLOWS = [
  { id: "WF-001", name: "Critical Alert Response", trigger: "SIEM Alert (critical)", steps: 4, status: "deployed", detail: "Enrich > Block IP > Notify SOC > Escalate IR" },
  { id: "WF-002", name: "Malware Containment", trigger: "EDR Detection", steps: 3, status: "deployed", detail: "Isolate Host > Collect Forensics > Notify SOC" },
  { id: "WF-003", name: "Brute Force Response", trigger: "IAM Alert (>10 failures)", steps: 4, status: "testing", detail: "Lock Account > Enrich Identity > Notify > Remediate" },
  { id: "WF-004", name: "Compliance Scan", trigger: "Schedule (daily 2AM)", steps: 2, status: "deployed", detail: "Run Scan > Generate Report" },
];

const EXECUTIONS = [
  { id: "EX-001", workflow: "Critical Alert Response", status: "success", duration: "1.2s", time: "2 min ago" },
  { id: "EX-002", workflow: "Malware Containment", status: "success", duration: "3.4s", time: "15 min ago" },
  { id: "EX-003", workflow: "Brute Force Response", status: "failed", duration: "0.8s", time: "1 hr ago" },
  { id: "EX-004", workflow: "Compliance Scan", status: "success", duration: "45.2s", time: "6 hr ago" },
];

export default function SecurityWorkflowBuilder() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Security Workflow Builder" subtitle="Visual security workflow and playbook builder" icon={<Workflow className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Active Workflows" value="18" icon={<Workflow className="h-5 w-5" />} />
        <MetricCard title="Executions Today" value="142" icon={<Play className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Success Rate" value="97.8%" icon={<CheckCircle className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Avg Duration" value="2.1s" icon={<Activity className="h-5 w-5 text-yellow-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Workflow Health</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Deployed", v: "14", c: "text-emerald-400" }, { l: "Testing", v: "3", c: "text-yellow-400" }, { l: "Disabled", v: "1", c: "text-red-400" }, { l: "Triggers Active", v: "12", c: "text-cyan-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "workflows" && (<div className="space-y-3">{WORKFLOWS.map((w) => (<div key={w.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{w.id}</span><span className="ml-2 text-white/90 font-medium">{w.name}</span></div><StatusBadge status={w.status === "deployed" ? "active" : w.status} /></div><p className="text-white/70 text-sm">Trigger: {w.trigger} | Steps: {w.steps}</p><p className="text-white/50 text-xs mt-1">{w.detail}</p></div>))}</div>)}
      {tab === "execution_log" && (<div className="space-y-3">{EXECUTIONS.map((e) => (<div key={e.id} className="card-interactive p-4 flex items-center justify-between"><div><span className="font-mono text-xs text-cyan-400">{e.id}</span><span className="ml-2 text-white/90 font-medium">{e.workflow}</span><p className="text-white/50 text-xs mt-1">{e.time} | {e.duration}</p></div><StatusBadge status={e.status === "success" ? "active" : "critical"} /></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Builder Metrics</h3>{[{ m: "Workflows Created (30d)", v: "8", t: "+3" }, { m: "Total Executions (30d)", v: "4,280", t: "+12%" }, { m: "Mean Time to Respond", v: "1.8s", t: "-0.4s" }, { m: "Validation Pass Rate", v: "94%", t: "+2%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
