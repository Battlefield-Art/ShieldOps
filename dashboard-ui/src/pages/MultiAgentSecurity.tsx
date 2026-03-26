import { useState } from "react";
import { Network, Link2, AlertTriangle, Shield, Eye, Lock } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "interactions" | "trust" | "anomalies";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "interactions", label: "Interactions" }, { id: "trust", label: "Trust Chains" }, { id: "anomalies", label: "Anomalies" }];
export default function MultiAgentSecurity() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Multi-Agent Security" subtitle="Secure agent-to-agent communication and trust chain verification" icon={<Network className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Agent Interactions (24h)" value="2.8K" icon={<Link2 className="h-5 w-5" />} />
      <MetricCard title="Trust Chains Verified" value="156" icon={<Lock className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Anomalies Detected" value="7" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Blocked Interactions" value="3" icon={<Shield className="h-5 w-5 text-red-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Communication Security (24h)</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">
      {[{ label: "Safe", count: "2.7K", color: "text-emerald-400" }, { label: "Suspicious", count: 7, color: "text-yellow-400" }, { label: "Blocked", count: 3, color: "text-red-400" }, { label: "Quarantined", count: 1, color: "text-orange-400" }].map((s) => (
        <div key={s.label} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.label}</p><p className={clsx("text-3xl font-bold mt-1", s.color)}>{s.count}</p></div>))}</div></div>)}
    {tab === "interactions" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Source</th><th className="px-4 py-3">Target</th><th className="px-4 py-3">Channel</th><th className="px-4 py-3">Data Sensitivity</th><th className="px-4 py-3">Verdict</th></tr></thead>
      <tbody>{[
        { source: "orchestrator-1", target: "data-agent-3", channel: "Direct", sensitivity: "internal", verdict: "safe" },
        { source: "research-bot", target: "infra-agent", channel: "Delegated", sensitivity: "confidential", verdict: "suspicious" },
        { source: "unknown-agent", target: "credential-mgr", channel: "Proxied", sensitivity: "restricted", verdict: "blocked" },
        { source: "analyst-agent", target: "report-gen", channel: "Direct", sensitivity: "public", verdict: "safe" },
      ].map((i, idx) => (<tr key={idx} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90 font-medium">{i.source}</td><td className="px-4 py-3 text-white/70">{i.target}</td><td className="px-4 py-3 text-white/60">{i.channel}</td><td className="px-4 py-3"><StatusBadge status={i.sensitivity} /></td><td className="px-4 py-3"><StatusBadge status={i.verdict} /></td></tr>))}</tbody></table></div>)}
    {tab === "trust" && (<div className="space-y-3">
      {[{ chain: "orchestrator → data-agent → report-gen", trust: "verified", method: "Cryptographic", score: 0.95 },
        { chain: "supervisor → remediation → cloud-posture", trust: "provisional", method: "Behavioral", score: 0.72 },
        { chain: "unknown-agent → credential-mgr", trust: "revoked", method: "Attestation Failed", score: 0.15 },
      ].map((t, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><p className="text-white/90 font-medium font-mono text-sm">{t.chain}</p><StatusBadge status={t.trust} /></div>
        <p className="text-xs text-white/50">Method: {t.method} | Trust Score: <span className={clsx("font-mono", t.score > 0.8 ? "text-emerald-400" : t.score > 0.5 ? "text-yellow-400" : "text-red-400")}>{t.score}</span></p></div>))}</div>)}
    {tab === "anomalies" && (<div className="space-y-3">
      {[{ id: "ANM-001", type: "Agent Impersonation", agents: "unknown → credential-mgr", severity: "critical", detail: "Agent ID spoofed to bypass trust check" },
        { id: "ANM-002", type: "Privilege Escalation via Delegation", agents: "research-bot → infra-agent", severity: "high", detail: "Delegated request exceeded source agent permissions" },
        { id: "ANM-003", type: "Data Exfil via Inter-Agent Channel", agents: "data-agent → external-proxy", severity: "high", detail: "Confidential data detected in agent message payload" },
      ].map((a) => (<div key={a.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{a.id}</span><span className="text-xs text-white/40 ml-2">{a.agents}</span></div><StatusBadge status={a.severity} /></div>
        <p className="text-white/90 font-medium">{a.type}</p><p className="text-xs text-white/50">{a.detail}</p></div>))}</div>)}
  </div>);
}
