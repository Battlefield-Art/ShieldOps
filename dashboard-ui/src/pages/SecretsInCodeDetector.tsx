import { useState } from "react";
import { Key, AlertTriangle, Bug, Eye, RotateCcw } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "secrets" | "exposure" | "remediation";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "secrets", label: "Secrets" }, { id: "exposure", label: "Exposure" }, { id: "remediation", label: "Remediation" }];
export default function SecretsInCodeDetector() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Secrets in Code Detector" subtitle="Detect hardcoded secrets — API keys, passwords, tokens, certificates, and private keys" icon={<Key className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Repos Scanned" value="48" icon={<Eye className="h-5 w-5" />} />
      <MetricCard title="Secrets Found" value="67" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Active Secrets" value="23" icon={<Bug className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Rotated (30d)" value="89%" icon={<RotateCcw className="h-5 w-5 text-emerald-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Secrets by Type</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">
      {[{ type: "API Keys", count: 18, color: "text-yellow-400" }, { type: "Passwords", count: 12, color: "text-red-400" }, { type: "Tokens", count: 22, color: "text-yellow-400" }, { type: "Private Keys", count: 5, color: "text-red-400" }].map((s) => (
        <div key={s.type} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.type}</p><p className={clsx("text-3xl font-bold mt-1", s.color)}>{s.count}</p></div>))}</div></div>)}
    {tab === "secrets" && (<div className="space-y-3">
      {[{ type: "AWS Access Key", file: "config/aws.py:14", risk: "critical", active: true, masked: "AKIA...X7QM" },
        { type: "Private Key", file: "certs/server.key:1", risk: "critical", active: true, masked: "-----BEGIN RSA..." },
        { type: "DB Connection", file: "settings.py:42", risk: "critical", active: true, masked: "postgres://...@db" },
        { type: "API Key", file: "utils/openai.py:8", risk: "high", active: false, masked: "sk-...proj-...abc" },
      ].map((s, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><p className="text-white/90 font-medium">{s.type} {s.active && <span className="text-xs text-red-400 ml-2">ACTIVE</span>}</p><p className="text-xs text-white/50"><span className="font-mono text-cyan-400">{s.file}</span> | <code className="bg-white/5 px-1 rounded">{s.masked}</code></p></div><StatusBadge status={s.risk} /></div></div>))}</div>)}
    {tab === "exposure" && (<div className="space-y-3">
      {[{ secret: "AWS Access Key in public repo", risk: "critical", age: "14 days", blast: "Full AWS account access" },
        { secret: "DB password in git history", risk: "high", age: "45 days", blast: "Production database" },
        { secret: "Slack token in CI config", risk: "medium", age: "3 days", blast: "Workspace read access" },
      ].map((e, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><p className="text-white/90 font-medium">{e.secret}</p><StatusBadge status={e.risk} /></div>
        <p className="text-xs text-white/50">Age: {e.age} | Blast radius: {e.blast}</p></div>))}</div>)}
    {tab === "remediation" && (<div className="space-y-3">
      {[{ action: "Rotate AWS Access Key", priority: "critical", status: "pending", eta: "Immediate" },
        { action: "Move DB creds to Vault", priority: "high", status: "in_progress", eta: "2 hours" },
        { action: "Revoke leaked private key", priority: "critical", status: "completed", eta: "Done" },
      ].map((r, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{r.action}</p><p className="text-xs text-white/50">ETA: {r.eta}</p></div><StatusBadge status={r.status === "completed" ? "healthy" : r.priority} /></div>))}</div>)}
  </div>);
}
