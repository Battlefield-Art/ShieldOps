import { useState } from "react";
import { Blocks, Code, CheckCircle, Rocket, Zap } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "apps" | "builder" | "deployments";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "apps", label: "Built Apps" }, { id: "builder", label: "Builder" }, { id: "deployments", label: "Deployments" }];
export default function SecurityAppBuilder() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Security App Builder" subtitle="LangGraph-native security app builder — real code, not no-code" icon={<Blocks className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Apps Built" value="12" icon={<Blocks className="h-5 w-5" />} />
      <MetricCard title="Deployed" value="9" icon={<Rocket className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Code Quality" value="94%" icon={<CheckCircle className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Avg Build Time" value="2.3 min" icon={<Zap className="h-5 w-5 text-cyan-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Builder vs Falcon Foundry</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {[{ label: "Output", ours: "Real LangGraph code", theirs: "Proprietary no-code", color: "text-cyan-400" },
        { label: "Portability", ours: "Version-controlled, testable", theirs: "Locked to Falcon", color: "text-emerald-400" },
        { label: "Capability", ours: "AI reasoning + cross-vendor", theirs: "Simple automation", color: "text-cyan-400" }].map((c) => (
        <div key={c.label} className="card-interactive p-4"><p className="text-sm text-white/60">{c.label}</p><div className="flex justify-between mt-2"><div><p className="text-white/40 text-xs">ShieldOps</p><p className={clsx("font-bold", c.color)}>{c.ours}</p></div><div className="text-right"><p className="text-white/40 text-xs">Foundry</p><p className="text-white/30">{c.theirs}</p></div></div></div>))}</div></div>)}
    {tab === "apps" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">App</th><th className="px-4 py-3">Type</th><th className="px-4 py-3">Nodes</th><th className="px-4 py-3">Quality</th><th className="px-4 py-3">Status</th></tr></thead>
      <tbody>{[
        { name: "Phishing Auto-Response", type: "response_playbook", nodes: 8, quality: "96%", status: "deployed" },
        { name: "Cloud Drift Detector", type: "detection_rule", nodes: 5, quality: "94%", status: "deployed" },
        { name: "SOC 2 Evidence Collector", type: "compliance_check", nodes: 6, quality: "98%", status: "deployed" },
        { name: "Custom Threat Hunter", type: "investigation_workflow", nodes: 10, quality: "91%", status: "testing" },
      ].map((a, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90 font-medium">{a.name}</td><td className="px-4 py-3"><StatusBadge status={a.type} /></td><td className="px-4 py-3 text-white/80">{a.nodes}</td><td className="px-4 py-3 text-emerald-400">{a.quality}</td><td className="px-4 py-3"><StatusBadge status={a.status} /></td></tr>))}</tbody></table></div>)}
    {tab === "builder" && (<div className="card-surface p-6 space-y-4"><h3 className="section-heading">Build a Security App</h3>
      <div className="bg-white/5 rounded-lg p-4"><p className="text-xs text-white/40 mb-2">Describe your security workflow:</p>
      <textarea className="w-full bg-white/5 border border-white/10 rounded p-3 text-sm text-white/90 placeholder-white/30 h-24" placeholder="e.g., When a phishing email is reported, extract IOCs, check against threat intel, block sender domain, purge from all mailboxes, and notify the user..." />
      <button className="btn-primary mt-3 px-4 py-2 flex items-center gap-2"><Code className="h-4 w-4" /> Generate LangGraph App</button></div>
      <p className="text-xs text-white/50">Apps are generated as real Python code with LangGraph StateGraph, nodes, tools, and tests. Fully version-controlled and testable.</p></div>)}
    {tab === "deployments" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Recent Deployments</h3>
      {[{ app: "Phishing Auto-Response", target: "production", version: "v1.3", status: "healthy", uptime: "99.9%" },
        { app: "Cloud Drift Detector", target: "production", version: "v2.1", status: "healthy", uptime: "100%" },
        { app: "Custom Threat Hunter", target: "staging", version: "v0.9", status: "testing", uptime: "—" },
      ].map((d, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{d.app} <span className="font-mono text-xs text-white/40">{d.version}</span></p><p className="text-xs text-white/50">Target: {d.target} | Uptime: {d.uptime}</p></div><StatusBadge status={d.status} /></div>))}</div>)}
  </div>);
}
