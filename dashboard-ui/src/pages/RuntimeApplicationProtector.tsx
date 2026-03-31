import { useState } from "react";
import { Shield, AlertTriangle, Bug, Activity, Zap, Lock } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "runtime_events" | "blocked_attacks" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "runtime_events", label: "Runtime Events" },
  { id: "blocked_attacks", label: "Blocked Attacks" },
  { id: "metrics", label: "Metrics" },
];

const EVENTS = [
  { id: "EVT-001", app: "payments-api", endpoint: "/api/v1/transfer", category: "SQL Injection", risk: 9.2, status: "blocked" },
  { id: "EVT-002", app: "user-portal", endpoint: "/profile/update", category: "XSS", risk: 7.5, status: "blocked" },
  { id: "EVT-003", app: "file-service", endpoint: "/download", category: "Path Traversal", risk: 8.1, status: "blocked" },
  { id: "EVT-004", app: "auth-service", endpoint: "/api/deserialize", category: "Deserialization", risk: 9.8, status: "blocked" },
  { id: "EVT-005", app: "payments-api", endpoint: "/api/v1/search", category: "SQL Injection", risk: 6.3, status: "sanitized" },
];

const BLOCKED = [
  { id: "BLK-001", app: "payments-api", payload: "' OR 1=1 --", category: "SQL Injection", cwe: "CWE-89", severity: "critical" },
  { id: "BLK-002", app: "user-portal", payload: "<script>alert(1)</script>", category: "XSS", cwe: "CWE-79", severity: "high" },
  { id: "BLK-003", app: "file-service", payload: "../../etc/passwd", category: "Path Traversal", cwe: "CWE-22", severity: "high" },
];

export default function RuntimeApplicationProtector() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Runtime Application Protector" subtitle="RASP — real-time attack detection and blocking" icon={<Shield className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Apps Protected" value="12" icon={<Lock className="h-5 w-5" />} />
        <MetricCard title="Attacks Blocked (24h)" value="847" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Events Processed" value="1.2M" icon={<Activity className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="False Positive Rate" value="0.3%" icon={<Bug className="h-5 w-5 text-emerald-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Attack Categories (24h)</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "SQL Injection", v: "312", c: "text-red-400" }, { l: "XSS", v: "218", c: "text-yellow-400" }, { l: "Path Traversal", v: "187", c: "text-cyan-400" }, { l: "Deserialization", v: "130", c: "text-white/70" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "runtime_events" && (<div className="space-y-3">{EVENTS.map((e) => (<div key={e.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{e.id}</span><span className="ml-2 text-xs text-white/40">{e.app}</span></div><StatusBadge status={e.status} /></div><p className="text-white/90 text-sm">{e.endpoint}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>{e.category}</span><span className={e.risk > 8 ? "text-red-400" : "text-yellow-400"}>Risk: {e.risk}</span></div></div>))}</div>)}
      {tab === "blocked_attacks" && (<div className="space-y-3">{BLOCKED.map((b) => (<div key={b.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{b.id}</span><span className="ml-2 text-xs text-white/40">{b.app}</span></div><StatusBadge status={b.severity} /></div><p className="text-white/90 text-sm font-mono text-xs">{b.payload}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>{b.category}</span><span className="text-cyan-400">{b.cwe}</span></div></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">RASP Performance</h3>{[{ m: "Detection Latency (p99)", v: "2.1ms", t: "-0.3ms" }, { m: "False Positive Rate", v: "0.3%", t: "-0.1%" }, { m: "Block Rate", v: "99.7%", t: "+0.2%" }, { m: "Apps Instrumented", v: "12/14", t: "+2" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
