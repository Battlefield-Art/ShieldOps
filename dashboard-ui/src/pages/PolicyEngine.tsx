import { useState } from "react";
import { FileCode, AlertTriangle, Shield, CheckCircle, RefreshCw } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "policies" | "coverage" | "drift";

const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "policies", label: "Generated Policies" },
  { id: "coverage", label: "Coverage Gaps" },
  { id: "drift", label: "Policy Drift" },
];

export default function PolicyEngine() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Policy Engine" subtitle="OPA Rego policy generation, validation, and drift detection" icon={<FileCode className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Active Policies" value="42" icon={<Shield className="h-5 w-5" />} />
        <MetricCard title="Coverage" value="91%" icon={<CheckCircle className="h-5 w-5" />} />
        <MetricCard title="Drifts Detected" value="5" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Auto-Reconciled" value="3" icon={<RefreshCw className="h-5 w-5" />} />
      </div>
      <div className="tab-bar">
        {TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}
      </div>
      {tab === "overview" && (
        <div className="card-surface p-6 space-y-4">
          <h3 className="section-heading">Policy Domain Coverage</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {[{ domain: "Access Control", policies: 14, coverage: 95 }, { domain: "Agent Behavior", policies: 8, coverage: 88 }, { domain: "Data Protection", policies: 10, coverage: 92 }, { domain: "Network", policies: 6, coverage: 85 }, { domain: "Compliance", policies: 4, coverage: 90 }].map((d) => (
              <div key={d.domain} className="card-interactive p-4">
                <p className="text-sm text-white/60">{d.domain}</p>
                <div className="flex items-baseline gap-2 mt-1"><span className="text-2xl font-bold text-white">{d.policies}</span><span className="text-sm text-white/40">policies</span></div>
                <div className="h-2 bg-white/10 rounded-full mt-2"><div className="h-2 bg-cyan-500 rounded-full" style={{ width: `${d.coverage}%` }} /></div>
                <p className="text-xs text-white/40 mt-1">{d.coverage}% requirement coverage</p>
              </div>
            ))}
          </div>
        </div>
      )}
      {tab === "policies" && (
        <div className="card-surface overflow-hidden">
          <table className="w-full text-sm">
            <thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Policy Name</th><th className="px-4 py-3">Domain</th><th className="px-4 py-3">Method</th><th className="px-4 py-3">Requirements</th><th className="px-4 py-3">Status</th><th className="px-4 py-3">Rego Lines</th></tr></thead>
            <tbody>
              {[
                { name: "agent_blast_radius", domain: "Agent Behavior", method: "LLM-generated", reqs: 3, status: "active", lines: 42 },
                { name: "pii_data_access", domain: "Data Protection", method: "Template", reqs: 2, status: "active", lines: 38 },
                { name: "cross_cloud_role", domain: "Access Control", method: "LLM-generated", reqs: 4, status: "active", lines: 56 },
                { name: "api_rate_limit", domain: "Network", method: "Template", reqs: 1, status: "active", lines: 24 },
                { name: "soc2_encryption", domain: "Compliance", method: "Derived", reqs: 2, status: "drifted", lines: 31 },
              ].map((p, i) => (
                <tr key={i} className="border-b border-white/5 hover:bg-white/5">
                  <td className="px-4 py-3 font-mono text-sm text-cyan-400">{p.name}</td>
                  <td className="px-4 py-3 text-white/70">{p.domain}</td>
                  <td className="px-4 py-3 text-white/60">{p.method}</td>
                  <td className="px-4 py-3 text-white/80">{p.reqs}</td>
                  <td className="px-4 py-3"><StatusBadge status={p.status} /></td>
                  <td className="px-4 py-3 text-white/60">{p.lines}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {tab === "coverage" && (
        <div className="card-surface p-6 space-y-3">
          <h3 className="section-heading">Uncovered Requirements</h3>
          {[
            { req: "MCP server connection authentication", framework: "ShieldOps", severity: "high", suggestion: "Generate MCP auth policy with OAuth2 enforcement" },
            { req: "AI agent output size limits", framework: "ShieldOps", severity: "medium", suggestion: "Template policy for response size caps" },
            { req: "FedRAMP SC-12 key management", framework: "FedRAMP", severity: "medium", suggestion: "Derive from NIST 800-53 SC-12 control" },
          ].map((g, i) => (
            <div key={i} className="card-interactive p-4">
              <div className="flex items-start justify-between">
                <div><p className="text-white/90 font-medium">{g.req}</p><p className="text-xs text-white/50">{g.framework}</p><p className="text-xs text-cyan-400 mt-1">{g.suggestion}</p></div>
                <StatusBadge status={g.severity} />
              </div>
            </div>
          ))}
        </div>
      )}
      {tab === "drift" && (
        <div className="card-surface p-6 space-y-3">
          <h3 className="section-heading">Detected Policy Drifts</h3>
          {[
            { policy: "soc2_encryption", drift: "Scope Expansion", expected: "AES-256 required", actual: "AES-128 allowed", severity: "high", auto: true, status: "auto_fixed" },
            { policy: "agent_blast_radius", drift: "Config Change", expected: "max_targets=5", actual: "max_targets=10", severity: "critical", auto: true, status: "pending" },
            { policy: "api_rate_limit", drift: "Override", expected: "1000 req/min", actual: "5000 req/min (override)", severity: "medium", auto: false, status: "manual_required" },
          ].map((d, i) => (
            <div key={i} className="card-interactive p-4">
              <div className="flex items-start justify-between mb-2">
                <div><p className="text-white/90 font-medium font-mono">{d.policy}</p><p className="text-xs text-white/50">{d.drift}</p></div>
                <StatusBadge status={d.severity} />
              </div>
              <div className="grid grid-cols-2 gap-4 text-xs mt-2">
                <div><p className="text-white/40">Expected</p><p className="text-emerald-400">{d.expected}</p></div>
                <div><p className="text-white/40">Actual</p><p className="text-red-400">{d.actual}</p></div>
              </div>
              <div className="mt-2 flex items-center gap-2">
                <StatusBadge status={d.status} />
                {d.auto && <span className="text-xs text-white/40">Auto-reconcilable</span>}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
