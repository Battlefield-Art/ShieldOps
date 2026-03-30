import { useState } from "react";
import { Workflow, Zap, Shield, CheckCircle, AlertTriangle, BarChart3 } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "workflows" | "playbook_status" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "workflows", label: "Workflows" },
  { id: "playbook_status", label: "Playbook Status" },
  { id: "metrics", label: "Metrics" },
];

const WORKFLOWS = [
  { id: "WF-001", event: "CrowdStrike critical alert", severity: "critical", playbook: "Threat Containment", status: "running", actions: 4 },
  { id: "WF-002", event: "IAM policy violation", severity: "high", playbook: "Access Revocation", status: "completed", actions: 3 },
  { id: "WF-003", event: "Malware detection on endpoint", severity: "high", playbook: "Incident Response", status: "running", actions: 6 },
  { id: "WF-004", event: "Compliance drift detected", severity: "medium", playbook: "Compliance Enforcement", status: "pending", actions: 2 },
];

const PLAYBOOKS = [
  { name: "Threat Containment", runs: 47, success_rate: "94%", avg_time: "2.3m" },
  { name: "Incident Response", runs: 31, success_rate: "89%", avg_time: "5.1m" },
  { name: "Access Revocation", runs: 22, success_rate: "97%", avg_time: "1.1m" },
  { name: "Compliance Enforcement", runs: 18, success_rate: "91%", avg_time: "3.7m" },
  { name: "Forensic Collection", runs: 12, success_rate: "85%", avg_time: "8.2m" },
];

export default function SecurityOrchestrationHub() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Security Orchestration Hub" subtitle="Central security orchestration and workflow engine" icon={<Workflow className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Active Workflows" value="12" icon={<Zap className="h-5 w-5" />} />
        <MetricCard title="Playbooks Executed (30d)" value="130" icon={<Shield className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Success Rate" value="92%" icon={<CheckCircle className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Avg Response Time" value="3.1m" icon={<BarChart3 className="h-5 w-5 text-yellow-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Orchestration Summary</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Events Ingested", v: "1,247", c: "text-cyan-400" }, { l: "Auto-Resolved", v: "892", c: "text-emerald-400" }, { l: "Escalated", v: "43", c: "text-yellow-400" }, { l: "Failed", v: "8", c: "text-red-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "workflows" && (<div className="space-y-3">{WORKFLOWS.map((w) => (<div key={w.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{w.id}</span><span className="ml-2 text-xs text-white/40">{w.playbook}</span></div><StatusBadge status={w.status} /></div><p className="text-white/90 text-sm">{w.event}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><StatusBadge status={w.severity} /><span>{w.actions} actions</span></div></div>))}</div>)}
      {tab === "playbook_status" && (<div className="card-surface p-6"><h3 className="section-heading">Playbook Performance</h3><div className="space-y-3">{PLAYBOOKS.map((p) => (<div key={p.name} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{p.name}</p><p className="text-xs text-white/50">{p.runs} runs | Avg: {p.avg_time}</p></div><span className="text-cyan-400 font-mono">{p.success_rate}</span></div>))}</div></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Orchestration Metrics</h3>{[{ m: "Mean Time to Respond", v: "3.1 min", t: "-0.8 min" }, { m: "Auto-Resolution Rate", v: "71%", t: "+5%" }, { m: "Playbook Coverage", v: "89%", t: "+3%" }, { m: "Action Success Rate", v: "92%", t: "+2%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
