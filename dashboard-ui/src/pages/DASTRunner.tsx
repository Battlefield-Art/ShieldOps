import { useState } from "react";
import { Globe, Shield, AlertTriangle, Bug, Crosshair, Lock } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "endpoints" | "auth" | "fuzzing";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "endpoints", label: "Endpoints" }, { id: "auth", label: "Auth Testing" }, { id: "fuzzing", label: "Fuzzing" }];
export default function DASTRunner() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="DAST Runner" subtitle="Dynamic application security testing — crawl, fuzz, and exploit running applications" icon={<Globe className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Endpoints Tested" value="89" icon={<Crosshair className="h-5 w-5" />} />
      <MetricCard title="Findings" value="34" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Confirmed Vulns" value="8" icon={<Bug className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Auth Bypasses" value="3" icon={<Lock className="h-5 w-5 text-red-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Attack Types Detected</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">
      {[{ cat: "Auth Bypass", count: 3, color: "text-red-400" }, { cat: "IDOR", count: 5, color: "text-yellow-400" }, { cat: "SQL Injection", count: 4, color: "text-red-400" }, { cat: "XSS", count: 8, color: "text-yellow-400" }].map((c) => (
        <div key={c.cat} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{c.cat}</p><p className={clsx("text-3xl font-bold mt-1", c.color)}>{c.count}</p></div>))}</div></div>)}
    {tab === "endpoints" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Endpoint</th><th className="px-4 py-3">Method</th><th className="px-4 py-3">Parameters</th><th className="px-4 py-3">Status</th></tr></thead>
      <tbody>{[
        { ep: "/api/v1/users", method: "GET", params: "id, role", status: "vulnerable" },
        { ep: "/api/v1/login", method: "POST", params: "username, password", status: "warning" },
        { ep: "/api/v1/upload", method: "POST", params: "file", status: "healthy" },
        { ep: "/admin/dashboard", method: "GET", params: "none", status: "vulnerable" },
      ].map((e, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 font-mono text-cyan-400">{e.ep}</td><td className="px-4 py-3 text-white/70">{e.method}</td><td className="px-4 py-3 text-white/60">{e.params}</td><td className="px-4 py-3"><StatusBadge status={e.status} /></td></tr>))}</tbody></table></div>)}
    {tab === "auth" && (<div className="space-y-3">
      {[{ ep: "/api/v1/users/123", vuln: "IDOR — user ID enumeration", sev: "high", evidence: "200 OK with other user data" },
        { ep: "/admin/dashboard", vuln: "Auth bypass — no token check", sev: "critical", evidence: "200 OK without auth header" },
        { ep: "/api/v1/users", vuln: "Broken access control", sev: "high", evidence: "Role escalation via param" },
      ].map((f, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><p className="text-white/90 font-medium">{f.vuln}</p><StatusBadge status={f.sev} /></div>
        <p className="text-xs text-white/50"><span className="font-mono text-cyan-400">{f.ep}</span> | {f.evidence}</p></div>))}</div>)}
    {tab === "fuzzing" && (<div className="space-y-3">
      {[{ param: "q", ep: "/api/v1/search", payload: "' OR 1=1--", type: "SQLi", sev: "critical" },
        { param: "page", ep: "/api/v1/search", payload: "<script>alert(1)</script>", type: "XSS", sev: "high" },
        { param: "id", ep: "/api/v1/users/{id}", payload: "../../etc/passwd", type: "Path Traversal", sev: "high" },
      ].map((f, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><p className="text-white/90 font-medium">{f.type} in <span className="font-mono text-cyan-400">{f.param}</span></p><StatusBadge status={f.sev} /></div>
        <p className="text-xs text-white/50">{f.ep} | Payload: <code className="bg-white/5 px-1 rounded">{f.payload}</code></p></div>))}</div>)}
  </div>);
}
