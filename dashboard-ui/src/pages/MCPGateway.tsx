import { useState } from "react";
import { Plug, Shield, AlertTriangle, Lock, Eye, Key } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "servers" | "god_keys" | "traffic";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" }, { id: "servers", label: "MCP Servers" },
  { id: "god_keys", label: "God Key Detection" }, { id: "traffic", label: "Traffic Audit" },
];
export default function MCPGateway() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="MCP Security Gateway" subtitle="Secure proxy enforcing auth, RBAC, rate limits on MCP server connections" icon={<Plug className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="MCP Servers" value="14" icon={<Plug className="h-5 w-5" />} />
        <MetricCard title="God Keys Detected" value="3" icon={<Key className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Policies Enforced" value="42" icon={<Lock className="h-5 w-5" />} />
        <MetricCard title="Tool Calls (24h)" value="48.2K" icon={<Eye className="h-5 w-5" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (
        <div className="card-surface p-6 space-y-4"><h3 className="section-heading">Gateway Security Posture</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {[{ label: "OAuth2 Coverage", value: "79%", sub: "11/14 servers" }, { label: "TLS Enforcement", value: "86%", sub: "12/14 servers" }, { label: "Rate Limiting", value: "71%", sub: "10/14 servers" }].map((m) => (
              <div key={m.label} className="card-interactive p-4"><p className="text-sm text-white/60">{m.label}</p><p className="text-2xl font-bold text-white mt-1">{m.value}</p><p className="text-xs text-white/40">{m.sub}</p></div>
            ))}
          </div>
        </div>
      )}
      {tab === "servers" && (
        <div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Server</th><th className="px-4 py-3">Auth</th><th className="px-4 py-3">Tools</th><th className="px-4 py-3">TLS</th><th className="px-4 py-3">God Key</th><th className="px-4 py-3">Risk</th></tr></thead>
          <tbody>{[
            { name: "file-server", auth: "none", tools: 5, tls: false, godKey: true, risk: "critical" },
            { name: "db-query-server", auth: "oauth2", tools: 3, tls: true, godKey: true, risk: "high" },
            { name: "slack-server", auth: "api_key", tools: 4, tls: true, godKey: false, risk: "medium" },
            { name: "github-server", auth: "oauth2", tools: 8, tls: true, godKey: false, risk: "low" },
          ].map((s, i) => (
            <tr key={i} className="border-b border-white/5 hover:bg-white/5">
              <td className="px-4 py-3 text-cyan-400 font-mono text-sm">{s.name}</td><td className="px-4 py-3 text-white/70">{s.auth}</td>
              <td className="px-4 py-3 text-white/80">{s.tools}</td><td className="px-4 py-3">{s.tls ? <Shield className="h-4 w-4 text-emerald-400" /> : <AlertTriangle className="h-4 w-4 text-red-400" />}</td>
              <td className="px-4 py-3">{s.godKey ? <span className="text-red-400 font-bold">DETECTED</span> : <span className="text-white/40">None</span>}</td>
              <td className="px-4 py-3"><StatusBadge status={s.risk} /></td>
            </tr>
          ))}</tbody></table>
        </div>
      )}
      {tab === "god_keys" && (
        <div className="card-surface p-6 space-y-3"><h3 className="section-heading">God Key Detections</h3>
          {[
            { server: "file-server", desc: "Single API key grants read/write/delete to entire filesystem", downstream: 4, remediation: "Implement per-tool OAuth scopes" },
            { server: "db-query-server", desc: "Service account has SELECT/INSERT/UPDATE/DELETE on all tables", downstream: 6, remediation: "Create read-only and write-specific service accounts" },
          ].map((g, i) => (
            <div key={i} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><p className="text-white/90 font-medium font-mono">{g.server}</p><p className="text-xs text-white/50">{g.desc}</p></div><StatusBadge status="critical" /></div>
              <p className="text-xs text-white/40">Downstream systems: {g.downstream}</p><p className="text-xs text-cyan-400 mt-1">{g.remediation}</p>
            </div>
          ))}
        </div>
      )}
      {tab === "traffic" && (
        <div className="card-surface p-6 space-y-3"><h3 className="section-heading">MCP Traffic Audit (24h)</h3>
          {[{ server: "github-server", calls: 18200, blocked: 42, topTool: "search_code" },
            { server: "db-query-server", calls: 12400, blocked: 180, topTool: "execute_query" },
            { server: "file-server", calls: 8600, blocked: 520, topTool: "read_file" },
          ].map((t) => (
            <div key={t.server} className="card-interactive p-4 flex items-center justify-between">
              <div><p className="text-white/90 font-medium font-mono">{t.server}</p><p className="text-xs text-white/50">{t.calls.toLocaleString()} calls | {t.blocked} blocked | Top: {t.topTool}</p></div>
              <StatusBadge status={t.blocked > 100 ? "warning" : "active"} />
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
