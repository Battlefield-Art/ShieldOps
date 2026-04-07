import { useState } from "react";
import { GitBranch, Shield, AlertTriangle, Network, Key } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "trust_map" | "abuses" | "federations";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "trust_map", label: "Trust Map" }, { id: "abuses", label: "Abuses" }, { id: "federations", label: "Federations" }];
export default function TrustRelationshipMapper() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Trust Relationship Mapper" subtitle="Federation, delegation, cross-account roles, and AI agent trust chains" icon={<GitBranch className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Trust Boundaries" value="47" icon={<Network className="h-5 w-5" />} />
      <MetricCard title="Federations" value="12" icon={<Key className="h-5 w-5 text-cyan-400" />} />
      <MetricCard title="Abuses Detected" value="5" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Trust Graph Score" value="84%" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Trust by Type</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {[{ type: "Federation (SAML/OIDC)", count: 12, abuses: 2, color: "text-cyan-400" }, { type: "Cross-Account Roles", count: 18, abuses: 2, color: "text-yellow-400" }, { type: "AI Agent Delegation", count: 8, abuses: 1, color: "text-red-400" }].map((t) => (
        <div key={t.type} className="card-interactive p-4"><p className={clsx("font-bold", t.color)}>{t.type}</p><p className="text-2xl font-bold text-white/80 mt-1">{t.count}</p><p className="text-xs text-white/40">{t.abuses} abuses detected</p></div>))}</div></div>)}
    {tab === "trust_map" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Source</th><th className="px-4 py-3">Target</th><th className="px-4 py-3">Type</th><th className="px-4 py-3">Status</th></tr></thead>
      <tbody>{[
        { src: "Corp Okta", tgt: "AWS SSO", type: "federation", status: "healthy" },
        { src: "AWS Prod", tgt: "AWS Dev", type: "cross_account_role", status: "over_privileged" },
        { src: "orchestrator-agent", tgt: "remediation-agent", type: "ai_agent_delegation", status: "healthy" },
        { src: "Corp Entra", tgt: "GCP Workspace", type: "federation", status: "stale" },
        { src: "mcp-client-ext", tgt: "tool-server", type: "mcp_trust_chain", status: "unverified" },
      ].map((t, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90">{t.src}</td><td className="px-4 py-3 text-white/70">{t.tgt}</td><td className="px-4 py-3"><StatusBadge status={t.type} /></td><td className="px-4 py-3"><StatusBadge status={t.status} /></td></tr>))}</tbody></table></div>)}
    {tab === "abuses" && (<div className="space-y-3">
      {[{ id: "TA-005", type: "Cross-account pivot", detail: "Dev account role used to access Prod S3 buckets", path: "AWS Dev → AWS Prod → S3", severity: "critical" },
        { id: "TA-004", type: "Stale federation", detail: "Entra → GCP federation unused 90d but still active", path: "Corp Entra → GCP", severity: "high" },
        { id: "TA-003", type: "AI agent over-delegation", detail: "Orchestrator delegates admin scope to data-agent", path: "orchestrator → data-agent", severity: "high" },
      ].map((a) => (<div key={a.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{a.id}</span><span className="text-xs text-white/40 ml-2">{a.type}</span></div><StatusBadge status={a.severity} /></div>
        <p className="text-white/90 font-medium">{a.detail}</p><p className="text-xs text-white/50">Path: {a.path}</p></div>))}</div>)}
    {tab === "federations" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Federation Health</h3>
      {[{ fed: "Corp Okta → AWS SSO", protocol: "SAML 2.0", users: 450, last_used: "5m ago", status: "healthy" },
        { fed: "Corp Okta → Azure AD", protocol: "OIDC", users: 320, last_used: "2m ago", status: "healthy" },
        { fed: "Corp Entra → GCP Workspace", protocol: "SAML 2.0", users: 0, last_used: "90d ago", status: "stale" },
      ].map((f, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{f.fed}</p><p className="text-xs text-white/50">{f.protocol} | {f.users} users | Last: {f.last_used}</p></div><StatusBadge status={f.status} /></div>))}</div>)}
  </div>);
}
