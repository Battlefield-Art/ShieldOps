import { useState } from "react";
import { Globe, Shield, AlertTriangle, Eye, Activity } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "threats" | "queries" | "response";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "threats", label: "DNS Threats" }, { id: "queries", label: "Query Analytics" }, { id: "response", label: "Response" }];
export default function DNSSecurity() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="DNS Security" subtitle="DNS monitoring for tunneling, DGA detection, and typosquatting" icon={<Globe className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Queries (24h)" value="2.4M" icon={<Activity className="h-5 w-5" />} />
      <MetricCard title="Threats Detected" value="7" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Domains Blocked" value="342" icon={<Shield className="h-5 w-5" />} />
      <MetricCard title="DGA Candidates" value="12" icon={<Eye className="h-5 w-5 text-yellow-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Threat Categories</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {[{ type: "DNS Tunneling", count: 2, sev: "critical" }, { type: "DGA Domains", count: 3, sev: "high" }, { type: "Typosquatting", count: 2, sev: "medium" }].map((t) => (
        <div key={t.type} className="card-interactive p-4"><div className="flex items-center justify-between"><span className="text-sm text-white/60">{t.type}</span><StatusBadge status={t.sev} /></div><p className="text-2xl font-bold text-white mt-1">{t.count}</p></div>))}</div></div>)}
    {tab === "threats" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Active DNS Threats</h3>
      {[{ domain: "xk4f9a2b.evil.com", type: "Tunneling", src: "10.0.5.42", sev: "critical", mitre: "T1071.004" },
        { domain: "g00gle-login.net", type: "Typosquatting", src: "10.0.3.18", sev: "high", mitre: "T1583.001" },
        { domain: "adf8x92k.xyz", type: "DGA", src: "10.0.7.33", sev: "high", mitre: "T1568.002" },
      ].map((t, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium font-mono text-sm">{t.domain}</p><p className="text-xs text-white/50">{t.type} | Source: {t.src} | {t.mitre}</p></div><StatusBadge status={t.sev} /></div>))}</div>)}
    {tab === "queries" && (<div className="card-surface p-6"><h3 className="section-heading">Query Analytics (24h)</h3><div className="grid grid-cols-2 gap-4">
      {[{ m: "Total Queries", v: "2.4M" }, { m: "Unique Domains", v: "48.2K" }, { m: "NXDOMAIN Rate", v: "2.1%" }, { m: "Avg Latency", v: "12ms" }].map((s) => (
        <div key={s.m} className="card-interactive p-4"><p className="text-sm text-white/60">{s.m}</p><p className="text-2xl font-bold text-white mt-1">{s.v}</p></div>))}</div></div>)}
    {tab === "response" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Response Actions</h3>
      {[{ action: "Sinkhole DNS tunneling domain", target: "xk4f9a2b.evil.com", status: "completed" },
        { action: "Block typosquatting domain", target: "g00gle-login.net", status: "completed" },
        { action: "Monitor DGA candidate", target: "adf8x92k.xyz", status: "monitoring" },
      ].map((r, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{r.action}</p><p className="text-xs text-white/50 font-mono">{r.target}</p></div><StatusBadge status={r.status} /></div>))}</div>)}
  </div>);
}
