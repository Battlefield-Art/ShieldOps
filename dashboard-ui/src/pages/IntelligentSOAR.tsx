import { useState } from "react";
import { Workflow, Play, GitBranch, RefreshCw, CheckCircle, Zap } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "playbooks" | "executions" | "adaptations";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "playbooks", label: "Playbooks" }, { id: "executions", label: "Executions" }, { id: "adaptations", label: "Adaptations" }];
export default function IntelligentSOAR() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Intelligent SOAR" subtitle="LangGraph-native playbooks with dynamic mid-execution adaptation" icon={<Workflow className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Playbooks Executed (7d)" value="89" icon={<Play className="h-5 w-5" />} />
      <MetricCard title="Steps Completed" value="412" icon={<CheckCircle className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Adaptations Made" value="23" icon={<GitBranch className="h-5 w-5 text-cyan-400" />} />
      <MetricCard title="Success Rate" value="96.6%" icon={<Zap className="h-5 w-5 text-emerald-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">SOAR vs Legacy XSOAR</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {[{ label: "Avg Execution Time", ours: "2.3 min", legacy: "18 min", improvement: "8x faster" },
        { label: "Adaptation Rate", ours: "26%", legacy: "0%", improvement: "AI-native" },
        { label: "Cross-Vendor Actions", ours: "17 vendors", legacy: "Palo Alto only", improvement: "Open" }].map((c) => (
        <div key={c.label} className="card-interactive p-4"><p className="text-sm text-white/60">{c.label}</p><div className="flex justify-between mt-2"><div><p className="text-white/40 text-xs">ShieldOps</p><p className="text-emerald-400 font-bold">{c.ours}</p></div><div className="text-right"><p className="text-white/40 text-xs">XSOAR</p><p className="text-white/30 font-bold">{c.legacy}</p></div></div><p className="text-xs text-cyan-400 mt-1">{c.improvement}</p></div>))}</div></div>)}
    {tab === "playbooks" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Playbook</th><th className="px-4 py-3">Type</th><th className="px-4 py-3">Steps</th><th className="px-4 py-3">Mode</th><th className="px-4 py-3">Success</th></tr></thead>
      <tbody>{[
        { name: "Credential Compromise Response", type: "containment", steps: 8, mode: "automatic", success: "98%" },
        { name: "Malware Containment + Clean", type: "eradication", steps: 12, mode: "semi_automatic", success: "95%" },
        { name: "Cloud Exposure Remediation", type: "recovery", steps: 6, mode: "automatic", success: "97%" },
        { name: "Compliance Evidence Collection", type: "compliance", steps: 5, mode: "automatic", success: "100%" },
      ].map((p, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90 font-medium">{p.name}</td><td className="px-4 py-3"><StatusBadge status={p.type} /></td><td className="px-4 py-3 text-white/80">{p.steps}</td><td className="px-4 py-3"><StatusBadge status={p.mode} /></td><td className="px-4 py-3 text-emerald-400 font-mono">{p.success}</td></tr>))}</tbody></table></div>)}
    {tab === "executions" && (<div className="space-y-3">
      {[{ id: "EXE-089", playbook: "Credential Compromise Response", trigger: "Okta alert", steps: "8/8", duration: "1.8 min", status: "completed", adapted: false },
        { id: "EXE-088", playbook: "Malware Containment + Clean", trigger: "Defender alert", steps: "14/12", duration: "4.2 min", status: "completed", adapted: true },
        { id: "EXE-087", playbook: "Cloud Exposure Remediation", trigger: "Wiz finding", steps: "6/6", duration: "2.1 min", status: "completed", adapted: false },
      ].map((e) => (<div key={e.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{e.id}</span>{e.adapted && <span className="text-xs text-yellow-400 ml-2">ADAPTED</span>}</div><StatusBadge status={e.status} /></div>
        <p className="text-white/90 font-medium">{e.playbook}</p><p className="text-xs text-white/50">Trigger: {e.trigger} | Steps: {e.steps} | {e.duration}</p></div>))}</div>)}
    {tab === "adaptations" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Dynamic Adaptations</h3>
      {[{ playbook: "Malware Containment", trigger: "New IOC discovered mid-execution", adaptation: "Added 2 containment steps for lateral C2", scope: "branch", outcome: "improved" },
        { playbook: "Credential Response", trigger: "Confidence dropped below threshold", adaptation: "Escalated to analyst before credential reset", scope: "step", outcome: "improved" },
        { playbook: "Cloud Remediation", trigger: "Blast radius exceeded limit", adaptation: "Switched to staged rollback instead of immediate", scope: "full_rewrite", outcome: "improved" },
      ].map((a, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><p className="text-white/90 font-medium">{a.playbook}</p><StatusBadge status={a.outcome} /></div>
        <p className="text-xs text-white/70">Trigger: {a.trigger}</p><p className="text-xs text-white/50">Adaptation: {a.adaptation} | Scope: <StatusBadge status={a.scope} /></p></div>))}</div>)}
  </div>);
}
