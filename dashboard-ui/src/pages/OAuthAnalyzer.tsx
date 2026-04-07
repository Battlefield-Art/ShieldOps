import { useState } from "react";
import { KeyRound, AlertTriangle, Shield, Clock } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "grants" | "anomalies" | "recommendations";

interface GrantEntry {
  id: string; app: string; provider: string; grantedTo: string;
  scopes: number; status: "active" | "stale" | "suspicious";
  riskScore: number; lastUsed: string;
}

const GRANTS: GrantEntry[] = [
  { id: "g-001", app: "Slack Analytics Bot", provider: "Slack", grantedTo: "eng-team", scopes: 12, status: "suspicious", riskScore: 89, lastUsed: "2 hr ago" },
  { id: "g-002", app: "Legacy CRM Sync", provider: "Salesforce", grantedTo: "sales-ops", scopes: 24, status: "stale", riskScore: 78, lastUsed: "186 days ago" },
  { id: "g-003", app: "GitHub Actions CI", provider: "GitHub", grantedTo: "ci-pipeline", scopes: 8, status: "active", riskScore: 45, lastUsed: "5 min ago" },
  { id: "g-004", app: "Google Drive Export", provider: "Google", grantedTo: "data-team", scopes: 6, status: "active", riskScore: 32, lastUsed: "1 hr ago" },
  { id: "g-005", app: "Deprecated Tool v1", provider: "Microsoft", grantedTo: "former-employee", scopes: 15, status: "stale", riskScore: 92, lastUsed: "342 days ago" },
];

const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "grants", label: "OAuth Grants" },
  { id: "anomalies", label: "Anomalies" },
  { id: "recommendations", label: "Recommendations" },
];

export default function OAuthAnalyzer() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="OAuth Grant Analyzer" subtitle="Discover and risk-score OAuth grants across SaaS applications" icon={<KeyRound className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Total Grants" value="847" icon={<KeyRound className="h-5 w-5" />} />
        <MetricCard title="High Risk" value="23" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Stale (>90d)" value="64" icon={<Clock className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Revoked (30d)" value="12" icon={<Shield className="h-5 w-5" />} />
      </div>
      <div className="tab-bar">
        {TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}
      </div>
      {tab === "overview" && (
        <div className="card-surface p-6 space-y-4">
          <h3 className="section-heading">Grant Risk Distribution</h3>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {[{ label: "Google Workspace", count: 234, risk: 42 }, { label: "Microsoft 365", count: 189, risk: 58 }, { label: "GitHub", count: 156, risk: 35 }, { label: "Slack", count: 268, risk: 47 }].map((p) => (
              <div key={p.label} className="card-interactive p-4">
                <p className="text-sm text-white/60">{p.label}</p>
                <p className="text-2xl font-bold text-white mt-1">{p.count}</p>
                <p className="text-xs text-white/40">Avg risk: {p.risk}%</p>
              </div>
            ))}
          </div>
        </div>
      )}
      {tab === "grants" && (
        <div className="card-surface overflow-hidden">
          <table className="w-full text-sm">
            <thead><tr className="border-b border-white/10 text-left text-white/50">
              <th className="px-4 py-3">Application</th><th className="px-4 py-3">Provider</th><th className="px-4 py-3">Granted To</th><th className="px-4 py-3">Scopes</th><th className="px-4 py-3">Status</th><th className="px-4 py-3">Risk</th><th className="px-4 py-3">Last Used</th>
            </tr></thead>
            <tbody>{GRANTS.map((g) => (
              <tr key={g.id} className="border-b border-white/5 hover:bg-white/5">
                <td className="px-4 py-3 text-white/90 font-medium">{g.app}</td>
                <td className="px-4 py-3 text-white/70">{g.provider}</td>
                <td className="px-4 py-3 text-white/70">{g.grantedTo}</td>
                <td className="px-4 py-3 text-white/80">{g.scopes}</td>
                <td className="px-4 py-3"><StatusBadge status={g.status} /></td>
                <td className="px-4 py-3"><span className={clsx("font-bold", g.riskScore > 75 ? "text-red-400" : g.riskScore > 50 ? "text-yellow-400" : "text-emerald-400")}>{g.riskScore}%</span></td>
                <td className="px-4 py-3 text-white/50">{g.lastUsed}</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      )}
      {tab === "anomalies" && (
        <div className="card-surface p-6 space-y-3">
          <h3 className="section-heading">Detected Anomalies</h3>
          {[
            { title: "OAuth grant to former employee still active", severity: "critical", app: "Deprecated Tool v1", when: "Detected 2 hr ago" },
            { title: "Excessive scope expansion on Slack bot", severity: "high", app: "Slack Analytics Bot", when: "Detected 6 hr ago" },
            { title: "Dormant grant suddenly active from new geo", severity: "medium", app: "Legacy CRM Sync", when: "Detected 1 day ago" },
          ].map((a, i) => (
            <div key={i} className="card-interactive p-4 flex items-center justify-between">
              <div><p className="text-white/90 font-medium">{a.title}</p><p className="text-xs text-white/50">{a.app} | {a.when}</p></div>
              <StatusBadge status={a.severity} />
            </div>
          ))}
        </div>
      )}
      {tab === "recommendations" && (
        <div className="card-surface p-6 space-y-3">
          <h3 className="section-heading">Recommended Actions</h3>
          {[
            { action: "Revoke", target: "Deprecated Tool v1", reason: "Grant to former employee — 342 days unused", priority: "critical" },
            { action: "Scope Reduce", target: "Slack Analytics Bot", reason: "12 scopes granted, only 4 used in 90 days", priority: "high" },
            { action: "Review", target: "Legacy CRM Sync", reason: "186 days unused — confirm if still needed", priority: "medium" },
          ].map((r, i) => (
            <div key={i} className="card-interactive p-4">
              <div className="flex items-center justify-between">
                <div><p className="text-white/90 font-medium">{r.action}: {r.target}</p><p className="text-xs text-white/50">{r.reason}</p></div>
                <StatusBadge status={r.priority} />
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
