import { useState } from "react";
import { Globe, ShieldAlert, Lock, Eye } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "sessions" | "breakouts" | "policies";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "sessions", label: "Sessions" }, { id: "breakouts", label: "Breakout Attempts" }, { id: "policies", label: "Policies" }];
export default function BrowserIsolation() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Browser Isolation" subtitle="Manage isolated browser sessions, detect breakout attempts, and sandbox web content" icon={<Globe className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Active Sessions" value="342" icon={<Globe className="h-5 w-5" />} />
      <MetricCard title="Isolated" value="98.2%" icon={<Lock className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Breakouts Blocked" value="7" icon={<ShieldAlert className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Content Sandboxed" value="156" icon={<Eye className="h-5 w-5 text-cyan-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Isolation Summary (24h)</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {[{ label: "Total Sessions", count: "4,521", color: "text-cyan-400" }, { label: "Threats Blocked", count: "23", color: "text-red-400" }, { label: "Data Sandboxed", count: "1.2GB", color: "text-emerald-400" }].map((s) => (
        <div key={s.label} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.label}</p><p className={clsx("text-3xl font-bold mt-1", s.color)}>{s.count}</p></div>))}</div></div>)}
    {tab === "sessions" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">User</th><th className="px-4 py-3">Domain</th><th className="px-4 py-3">Isolated</th><th className="px-4 py-3">Data</th><th className="px-4 py-3">Risk</th></tr></thead>
      <tbody>{[
        { user: "alice@corp.com", domain: "docs.google.com", isolated: "Yes", data: "45KB", risk: "safe" },
        { user: "bob@corp.com", domain: "suspicious-site.tk", isolated: "Yes", data: "250KB", risk: "critical" },
        { user: "charlie@corp.com", domain: "pastebin.com", isolated: "Yes", data: "12KB", risk: "high" },
        { user: "diana@corp.com", domain: "internal-wiki.corp.com", isolated: "No", data: "8KB", risk: "low" },
      ].map((s, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/60">{s.user}</td><td className="px-4 py-3 text-white/90 font-mono text-xs">{s.domain}</td><td className="px-4 py-3 text-white/80">{s.isolated}</td><td className="px-4 py-3 text-white/60">{s.data}</td><td className="px-4 py-3"><StatusBadge status={s.risk} /></td></tr>))}</tbody></table></div>)}
    {tab === "breakouts" && (<div className="space-y-3">
      {[{ id: "BRK-001", session: "SES-002", technique: "High-risk domain access", severity: "high", blocked: true, time: "5 min ago" },
        { id: "BRK-002", session: "SES-002", technique: "Large data transfer (250KB)", severity: "critical", blocked: true, time: "5 min ago" },
        { id: "BRK-003", session: "SES-005", technique: "WebRTC IP leak attempt", severity: "medium", blocked: true, time: "1h ago" },
      ].map((b) => (<div key={b.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{b.id}</span><span className="text-xs text-white/40 ml-2">{b.session}</span></div><StatusBadge status={b.severity} /></div>
        <p className="text-white/90 font-medium">{b.technique}</p><p className="text-xs text-white/50">{b.blocked ? "Blocked" : "Detected"} | {b.time}</p></div>))}</div>)}
    {tab === "policies" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Isolation Policies</h3>
      {[{ name: "Block .tk/.ru domains", pattern: "*.tk, *.ru", action: "Block", status: "active" },
        { name: "Sandbox pastebin", pattern: "pastebin.com", action: "Sandbox", status: "active" },
        { name: "Isolate all external", pattern: "!*.corp.com", action: "Isolate", status: "active" },
        { name: "Allow internal wiki", pattern: "*.corp.com", action: "Allow", status: "active" },
      ].map((p, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{p.name}</p><p className="text-xs text-white/50 font-mono">{p.pattern} | {p.action}</p></div><StatusBadge status={p.status} /></div>))}</div>)}
  </div>);
}
