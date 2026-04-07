import { useState } from "react";
import { ShieldAlert, Globe, Key, Users } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "indicators" | "responses" | "sessions";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "indicators", label: "Hijack Indicators" }, { id: "responses", label: "Responses" }, { id: "sessions", label: "Active Sessions" }];
export default function SessionHijackDetector() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Session Hijack Detector" subtitle="Detect token theft, impossible travel, session replay, and concurrent geo anomalies" icon={<ShieldAlert className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Hijacks Detected (7d)" value="8" icon={<ShieldAlert className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Impossible Travel" value="3" icon={<Globe className="h-5 w-5 text-cyan-400" />} />
      <MetricCard title="Token Theft" value="2" icon={<Key className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Sessions Monitored" value="14.2K" icon={<Users className="h-5 w-5 text-emerald-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Detection Summary (7d)</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {[{ label: "Token Theft", count: 2, color: "text-red-400" }, { label: "Impossible Travel", count: 3, color: "text-cyan-400" }, { label: "Concurrent Geo", count: 2, color: "text-yellow-400" }, { label: "Session Replay", count: 1, color: "text-orange-400" }, { label: "Sessions Invalidated", count: 6, color: "text-emerald-400" }, { label: "IPs Blocked", count: 4, color: "text-white/80" }].map((s) => (
        <div key={s.label} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.label}</p><p className={clsx("text-3xl font-bold mt-1", s.color)}>{s.count}</p></div>))}</div></div>)}
    {tab === "indicators" && (<div className="space-y-3">
      {[{ id: "SHD-008", type: "Token Theft", user: "admin@corp.io", source: "10.0.1.5 (NYC)", anomalous: "185.22.91.3 (Moscow)", risk: "critical", time: "12m ago", technique: "T1539" },
        { id: "SHD-007", type: "Impossible Travel", user: "dev@corp.io", source: "SF, US", anomalous: "London, UK", risk: "high", time: "1h ago", technique: "T1550.004" },
        { id: "SHD-006", type: "Concurrent Geo", user: "ops@corp.io", source: "US", anomalous: "Brazil + Germany", risk: "high", time: "3h ago", technique: "T1539" },
        { id: "SHD-005", type: "Session Replay", user: "finance@corp.io", source: "Normal UA", anomalous: "Replayed token from different UA", risk: "medium", time: "6h ago", technique: "T1550.004" },
      ].map((ind) => (<div key={ind.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{ind.id}</span><span className="text-xs text-white/40 ml-2">{ind.type}</span><span className="text-xs text-white/30 ml-2">{ind.technique}</span></div><StatusBadge status={ind.risk} /></div>
        <p className="text-white/90 font-medium">{ind.user}</p><p className="text-xs text-white/50">Source: {ind.source} | Anomalous: {ind.anomalous} | {ind.time}</p></div>))}</div>)}
    {tab === "responses" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Recent Response Actions</h3>
      {[{ action: "Session Invalidated", target: "admin@corp.io — sess_a1b2c3", type: "invalidate_session", time: "0.1s", status: "completed" },
        { action: "Forced Re-authentication", target: "dev@corp.io — all sessions", type: "force_reauth", time: "0.3s", status: "completed" },
        { action: "IP Blocked", target: "185.22.91.3", type: "block_ip", time: "0.2s", status: "completed" },
        { action: "Token Revoked", target: "ops@corp.io — tok_x9y8z7", type: "revoke_token", time: "0.1s", status: "completed" },
        { action: "User Notified", target: "finance@corp.io", type: "notify_user", time: "1.2s", status: "pending" },
      ].map((c, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{c.action}</p><p className="text-xs text-white/50">Target: {c.target} | Response: {c.time}</p></div><StatusBadge status={c.status} /></div>))}</div>)}
    {tab === "sessions" && (<div className="card-surface p-6"><h3 className="section-heading">Monitored Sessions</h3><div className="space-y-2">
      {[{ user: "admin@corp.io", ip: "10.0.1.5", geo: "New York, US", ua: "Chrome 121 / macOS", status: "active", risk: "low" },
        { user: "dev@corp.io", ip: "192.168.1.20", geo: "San Francisco, US", ua: "Firefox 122 / Linux", status: "active", risk: "low" },
        { user: "ops@corp.io", ip: "172.16.0.8", geo: "Austin, US", ua: "Safari 17 / macOS", status: "flagged", risk: "high" },
        { user: "finance@corp.io", ip: "10.0.2.15", geo: "Chicago, US", ua: "Chrome 121 / Windows", status: "invalidated", risk: "medium" },
      ].map((s, i) => (<div key={i} className="flex items-center justify-between gap-4 p-3 rounded bg-white/5"><div className="flex-1"><p className="text-white/90 text-sm font-medium">{s.user}</p><p className="text-xs text-white/50">{s.ip} | {s.geo} | {s.ua}</p></div><div className="flex items-center gap-2"><StatusBadge status={s.risk} /><StatusBadge status={s.status} /></div></div>))}</div></div>)}
  </div>);
}
