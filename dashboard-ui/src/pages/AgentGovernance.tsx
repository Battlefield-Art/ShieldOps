import { useState } from "react";
import { ShieldCheck, Users, AlertTriangle, Scale, CheckCircle, XCircle } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "agents" | "violations" | "escalations";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "agents", label: "Managed Agents" }, { id: "violations", label: "Violations" }, { id: "escalations", label: "Escalations" }];
export default function AgentGovernance() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Agent Governance" subtitle="AI agent capability boundaries, escalation chains, and policy enforcement" icon={<ShieldCheck className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Managed Agents" value="47" icon={<Users className="h-5 w-5" />} />
      <MetricCard title="Boundary Violations (7d)" value="12" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Compliance Score" value="91.3%" icon={<Scale className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Active Escalations" value="3" icon={<XCircle className="h-5 w-5 text-yellow-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Governance Summary (7d)</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {[{ label: "Capabilities Approved", count: 124, color: "text-emerald-400" }, { label: "Capabilities Restricted", count: 18, color: "text-yellow-400" }, { label: "Capabilities Blocked", count: 5, color: "text-red-400" }].map((s) => (
        <div key={s.label} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.label}</p><p className={clsx("text-3xl font-bold mt-1", s.color)}>{s.count}</p></div>))}</div></div>)}
    {tab === "agents" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Agent</th><th className="px-4 py-3">Framework</th><th className="px-4 py-3">Capabilities</th><th className="px-4 py-3">Risk</th><th className="px-4 py-3">Status</th></tr></thead>
      <tbody>{[
        { name: "data-processor", framework: "LangChain", caps: 3, risk: "medium", status: "compliant" },
        { name: "infra-manager", framework: "CrewAI", caps: 5, risk: "high", status: "restricted" },
        { name: "report-gen", framework: "LlamaIndex", caps: 2, risk: "low", status: "compliant" },
        { name: "unregistered-bot", framework: "Custom", caps: 7, risk: "critical", status: "blocked" },
      ].map((a, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90 font-medium">{a.name}</td><td className="px-4 py-3 text-white/60">{a.framework}</td><td className="px-4 py-3 text-white/80">{a.caps}</td><td className="px-4 py-3"><StatusBadge status={a.risk} /></td><td className="px-4 py-3"><StatusBadge status={a.status} /></td></tr>))}</tbody></table></div>)}
    {tab === "violations" && (<div className="space-y-3">
      {[{ id: "VIO-A1E3", agent: "unregistered-bot", type: "Unauthorized credential_access", severity: "critical", action: "blocked", time: "2 min ago" },
        { id: "VIO-B4F2", agent: "infra-manager", type: "Exceeded infrastructure_modify scope", severity: "high", action: "restricted", time: "1h ago" },
        { id: "VIO-C7D1", agent: "data-processor", type: "Unapproved external_api call", severity: "medium", action: "logged", time: "3h ago" },
      ].map((v) => (<div key={v.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{v.id}</span><span className="text-xs text-white/40 ml-2">{v.agent}</span></div><StatusBadge status={v.severity} /></div>
        <p className="text-white/90 font-medium">{v.type}</p><p className="text-xs text-white/50">Action: {v.action} | {v.time}</p></div>))}</div>)}
    {tab === "escalations" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Active Escalations</h3>
      {[{ id: "ESC-001", agent: "unregistered-bot", reason: "Critical: unapproved credential access", to: "CISO", status: "pending", time: "2 min ago" },
        { id: "ESC-002", agent: "infra-manager", reason: "High: production scope exceeded", to: "SOC Lead", status: "in_progress", time: "1h ago" },
        { id: "ESC-003", agent: "data-processor", reason: "Medium: rate limit exceeded", to: "Team Lead", status: "resolved", time: "6h ago" },
      ].map((e) => (<div key={e.id} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{e.reason}</p><p className="text-xs text-white/50">{e.agent} | Escalated to: {e.to} | {e.time}</p></div><StatusBadge status={e.status} /></div>))}</div>)}
  </div>);
}
