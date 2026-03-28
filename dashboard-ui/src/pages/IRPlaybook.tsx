import { useState } from "react";
import { BookOpen, Shield, Zap, Clock, CheckCircle, AlertTriangle } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "playbooks" | "active" | "metrics";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "playbooks", label: "Playbooks" }, { id: "active", label: "Active" }, { id: "metrics", label: "Metrics" }];
export default function IRPlaybook() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="IR Playbook Engine" subtitle="Automated incident response — select, execute, adapt, validate" icon={<BookOpen className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Playbooks Available" value="24" icon={<BookOpen className="h-5 w-5" />} />
      <MetricCard title="Incidents Handled" value="89" icon={<CheckCircle className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Avg Response Time" value="4.2 min" icon={<Clock className="h-5 w-5 text-cyan-400" />} />
      <MetricCard title="Containment Rate" value="96.6%" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Playbooks by Incident Type</h3><div className="grid grid-cols-2 md:grid-cols-4 gap-3">
      {[{ type: "Ransomware", count: 4, used: 12, color: "text-red-400" }, { type: "Data Breach", count: 3, used: 8, color: "text-red-400" }, { type: "Phishing", count: 3, used: 23, color: "text-yellow-400" }, { type: "Account Compromise", count: 4, used: 31, color: "text-yellow-400" }, { type: "Malware", count: 3, used: 15, color: "text-yellow-400" }, { type: "DDoS", count: 2, used: 5, color: "text-white/60" }, { type: "Insider Threat", count: 3, used: 7, color: "text-white/60" }, { type: "Supply Chain", count: 2, used: 3, color: "text-white/60" }].map((p) => (
        <div key={p.type} className="card-interactive p-3 text-center"><p className="text-xs text-white/60">{p.type}</p><p className={clsx("text-xl font-bold mt-1", p.color)}>{p.count}</p><p className="text-xs text-white/30">{p.used}x used</p></div>))}</div></div>)}
    {tab === "playbooks" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Playbook</th><th className="px-4 py-3">Type</th><th className="px-4 py-3">Steps</th><th className="px-4 py-3">Auto</th><th className="px-4 py-3">Success Rate</th></tr></thead>
      <tbody>{[
        { name: "Ransomware Containment", type: "ransomware", steps: 8, auto: "Yes", rate: "97%" },
        { name: "Credential Compromise", type: "account", steps: 6, auto: "Yes", rate: "98%" },
        { name: "Phishing Response", type: "phishing", steps: 5, auto: "Yes", rate: "99%" },
        { name: "Data Breach (PII)", type: "breach", steps: 10, auto: "Partial", rate: "94%" },
      ].map((p, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90 font-medium">{p.name}</td><td className="px-4 py-3"><StatusBadge status={p.type} /></td><td className="px-4 py-3 text-white/80">{p.steps}</td><td className="px-4 py-3 text-white/70">{p.auto}</td><td className="px-4 py-3 text-emerald-400">{p.rate}</td></tr>))}</tbody></table></div>)}
    {tab === "active" && (<div className="space-y-3">
      {[{ id: "IR-089", type: "Account Compromise", playbook: "Credential Response", step: "4/6 — Resetting credentials", status: "executing", time: "3.1 min" },
        { id: "IR-088", type: "Phishing", playbook: "Phishing Response", step: "5/5 — Verification", status: "completing", time: "2.8 min" },
      ].map((a) => (<div key={a.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{a.id}</span><span className="text-xs text-white/40 ml-2">{a.type}</span></div><StatusBadge status={a.status} /></div>
        <p className="text-white/90 font-medium">{a.playbook}</p><p className="text-xs text-white/50">Step: {a.step} | Elapsed: {a.time}</p></div>))}</div>)}
    {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">IR Metrics</h3>
      {[{ metric: "Mean Time to Contain", value: "4.2 min", trend: "-67% vs manual" },
        { metric: "Playbook Success Rate", value: "96.6%", trend: "+2% vs last quarter" },
        { metric: "Adaptation Rate", value: "12%", trend: "Playbooks adapted mid-incident" },
        { metric: "Auto-Resolution Rate", value: "78%", trend: "No human intervention needed" },
      ].map((m, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{m.metric}</p><p className="text-xs text-white/50">{m.trend}</p></div><span className="text-cyan-400 font-mono">{m.value}</span></div>))}</div>)}
  </div>);
}
