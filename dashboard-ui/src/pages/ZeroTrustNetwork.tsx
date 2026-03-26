import { useState } from "react";
import { Fingerprint, Shield, Users, Bot, Monitor, Lock } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "identities" | "sessions" | "policies";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "identities", label: "Identities" }, { id: "sessions", label: "Sessions" }, { id: "policies", label: "Policies" }];
export default function ZeroTrustNetwork() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Zero Trust Network" subtitle="Identity-first ZTNA for humans, AI agents, and non-human identities" icon={<Fingerprint className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Identities Managed" value="847" icon={<Users className="h-5 w-5" />} />
      <MetricCard title="AI Agent Identities" value="52" icon={<Bot className="h-5 w-5 text-cyan-400" />} />
      <MetricCard title="Zero Trust Score" value="91.4%" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Access Denied (24h)" value="34" icon={<Lock className="h-5 w-5 text-red-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Trust by Identity Type</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">
      {[{ type: "Humans", count: 645, trust: "92%", color: "text-emerald-400" }, { type: "Service Accounts", count: 120, trust: "87%", color: "text-cyan-400" }, { type: "AI Agents", count: 52, trust: "94%", color: "text-cyan-400" }, { type: "API Keys", count: 30, trust: "78%", color: "text-yellow-400" }].map((t) => (
        <div key={t.type} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{t.type}</p><p className={clsx("text-3xl font-bold mt-1", t.color)}>{t.trust}</p><p className="text-xs text-white/40">{t.count} identities</p></div>))}</div></div>)}
    {tab === "identities" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Identity</th><th className="px-4 py-3">Type</th><th className="px-4 py-3">Trust Score</th><th className="px-4 py-3">Decision</th></tr></thead>
      <tbody>{[
        { id: "analyst@corp.com", type: "human", trust: 0.95, decision: "allow" },
        { id: "data-agent-v3", type: "ai_agent", trust: 0.91, decision: "allow" },
        { id: "ci-deploy-sa", type: "service_account", trust: 0.72, decision: "challenge" },
        { id: "unknown-mcp-client", type: "mcp_client", trust: 0.23, decision: "deny" },
        { id: "stale-api-key-42", type: "api_key", trust: 0.45, decision: "restrict" },
      ].map((id, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90 font-mono text-sm">{id.id}</td><td className="px-4 py-3"><StatusBadge status={id.type} /></td><td className="px-4 py-3"><span className={clsx("font-mono", id.trust > 0.8 ? "text-emerald-400" : id.trust > 0.5 ? "text-yellow-400" : "text-red-400")}>{id.trust}</span></td><td className="px-4 py-3"><StatusBadge status={id.decision} /></td></tr>))}</tbody></table></div>)}
    {tab === "sessions" && (<div className="space-y-3">
      {[{ id: "SES-847", identity: "analyst@corp.com", risk: "normal", duration: "2h 14m", last_check: "30s ago" },
        { id: "SES-846", identity: "data-agent-v3", risk: "elevated", duration: "45m", last_check: "10s ago" },
        { id: "SES-845", identity: "ci-deploy-sa", risk: "suspicious", duration: "12m", last_check: "5s ago" },
      ].map((s) => (<div key={s.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{s.id}</span><span className="text-xs text-white/40 ml-2">{s.identity}</span></div><StatusBadge status={s.risk} /></div>
        <p className="text-xs text-white/50">Duration: {s.duration} | Last verified: {s.last_check}</p></div>))}</div>)}
    {tab === "policies" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Zero Trust Policies</h3>
      {[{ name: "AI Agent MCP Access", scope: "AI Agents → MCP Tools", rule: "Trust > 0.90 + approved tool list", status: "active" },
        { name: "Human Remote Access", scope: "Humans → Internal Apps", rule: "MFA + Device Posture + Trust > 0.80", status: "active" },
        { name: "Service Account API", scope: "SAs → APIs", rule: "mTLS + IP allowlist + Trust > 0.70", status: "active" },
        { name: "Continuous Verification", scope: "All Sessions", rule: "Re-verify every 5min, terminate if risk > 0.8", status: "active" },
      ].map((p, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{p.name}</p><p className="text-xs text-white/50">{p.scope} | {p.rule}</p></div><StatusBadge status={p.status} /></div>))}</div>)}
  </div>);
}
