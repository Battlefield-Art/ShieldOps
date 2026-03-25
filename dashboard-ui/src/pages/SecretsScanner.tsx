import { useState } from "react";
import { Lock, AlertTriangle, RefreshCw, Eye, FileSearch, Shield } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "findings" | "remediation" | "coverage";

const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "findings", label: "Secret Findings" },
  { id: "remediation", label: "Remediation" },
  { id: "coverage", label: "Scan Coverage" },
];

export default function SecretsScanner() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Secrets Scanner" subtitle="Detect leaked credentials across repos, configs, container images, and logs" icon={<Lock className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Active Secrets Found" value="8" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Auto-Rotated" value="14" icon={<RefreshCw className="h-5 w-5" />} />
        <MetricCard title="Repos Scanned" value="47" icon={<FileSearch className="h-5 w-5" />} />
        <MetricCard title="Coverage" value="94%" icon={<Shield className="h-5 w-5" />} />
      </div>
      <div className="tab-bar">
        {TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}
      </div>
      {tab === "overview" && (
        <div className="card-surface p-6 space-y-4">
          <h3 className="section-heading">Secret Type Distribution</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {[{ type: "AWS Access Keys", found: 3, active: 1 }, { type: "API Keys / Tokens", found: 12, active: 4 }, { type: "Database URLs", found: 5, active: 3 }].map((s) => (
              <div key={s.type} className="card-interactive p-4">
                <p className="text-sm text-white/60">{s.type}</p>
                <div className="flex items-baseline gap-2 mt-1"><span className="text-2xl font-bold text-white">{s.found}</span><span className="text-sm text-white/40">found</span><span className={clsx("text-lg font-bold", s.active > 0 ? "text-red-400" : "text-emerald-400")}>{s.active}</span><span className="text-sm text-white/40">active</span></div>
              </div>
            ))}
          </div>
        </div>
      )}
      {tab === "findings" && (
        <div className="card-surface overflow-hidden">
          <table className="w-full text-sm">
            <thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Type</th><th className="px-4 py-3">Source</th><th className="px-4 py-3">Path</th><th className="px-4 py-3">Exposure</th><th className="px-4 py-3">Active</th><th className="px-4 py-3">Severity</th></tr></thead>
            <tbody>
              {[
                { type: "AWS Access Key", source: "Git Repo", path: "src/config/aws.py:42", exposure: "public", active: true, severity: "critical" },
                { type: "Database URL", source: "Config File", path: ".env.production:8", exposure: "internal", active: true, severity: "high" },
                { type: "JWT Secret", source: "CI/CD", path: "github-actions/deploy.yml:23", exposure: "internal", active: true, severity: "high" },
                { type: "Stripe API Key", source: "Log File", path: "logs/app-2025-03.log:1842", exposure: "restricted", active: false, severity: "medium" },
                { type: "SSH Private Key", source: "Container", path: "Dockerfile:15", exposure: "internal", active: false, severity: "medium" },
              ].map((f, i) => (
                <tr key={i} className="border-b border-white/5 hover:bg-white/5">
                  <td className="px-4 py-3 text-white/90 font-medium">{f.type}</td>
                  <td className="px-4 py-3 text-white/70">{f.source}</td>
                  <td className="px-4 py-3 font-mono text-xs text-cyan-400">{f.path}</td>
                  <td className="px-4 py-3"><StatusBadge status={f.exposure} /></td>
                  <td className="px-4 py-3">{f.active ? <span className="text-red-400 font-bold">Active</span> : <span className="text-white/40">Rotated</span>}</td>
                  <td className="px-4 py-3"><StatusBadge status={f.severity} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {tab === "remediation" && (
        <div className="card-surface p-6 space-y-3">
          <h3 className="section-heading">Remediation Status</h3>
          {[
            { secret: "AWS Access Key (AKIA****)", action: "Auto-rotated via Vault", status: "completed", time: "2 min" },
            { secret: "Database URL (.env.production)", action: "Manual rotation required", status: "pending", time: "—" },
            { secret: "JWT Secret (CI/CD)", action: "Secret moved to GitHub Secrets", status: "completed", time: "12 min" },
          ].map((r, i) => (
            <div key={i} className="card-interactive p-4 flex items-center justify-between">
              <div><p className="text-white/90 font-medium">{r.secret}</p><p className="text-xs text-white/50">{r.action} | MTTR: {r.time}</p></div>
              <StatusBadge status={r.status} />
            </div>
          ))}
        </div>
      )}
      {tab === "coverage" && (
        <div className="card-surface p-6 space-y-3">
          <h3 className="section-heading">Scan Coverage</h3>
          {[
            { source: "Git Repositories", scanned: 47, total: 52 },
            { source: "Config Files", scanned: 124, total: 130 },
            { source: "Container Images", scanned: 38, total: 42 },
            { source: "CI/CD Pipelines", scanned: 14, total: 14 },
            { source: "Log Files", scanned: 89, total: 96 },
          ].map((c) => (
            <div key={c.source} className="card-interactive p-4">
              <div className="flex items-center justify-between mb-2"><p className="text-white/90 font-medium">{c.source}</p><span className="text-sm text-white/60">{c.scanned}/{c.total}</span></div>
              <div className="h-2 bg-white/10 rounded-full"><div className="h-2 bg-cyan-500 rounded-full" style={{ width: `${(c.scanned / c.total) * 100}%` }} /></div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
