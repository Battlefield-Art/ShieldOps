import { useState } from "react";
import { Link2, AlertTriangle, Zap, TrendingUp } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "clusters" | "incidents" | "metrics";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "clusters", label: "Correlation Clusters" }, { id: "incidents", label: "Prioritized Incidents" }, { id: "metrics", label: "Metrics" }];
export default function AlertCorrelation() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="Alert Correlation" subtitle="Multi-source alert correlation reducing noise by 50:1" icon={<Link2 className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Raw Alerts (24h)" value="2,847" icon={<AlertTriangle className="h-5 w-5" />} />
      <MetricCard title="Correlated Clusters" value="42" icon={<Link2 className="h-5 w-5" />} />
      <MetricCard title="Noise Reduction" value="68:1" icon={<TrendingUp className="h-5 w-5" />} />
      <MetricCard title="P1 Incidents" value="3" icon={<Zap className="h-5 w-5 text-red-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Correlation Summary</h3>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {[{ method: "Temporal", clusters: 18, conf: 89 }, { method: "Causal", clusters: 12, conf: 85 }, { method: "Kill Chain", clusters: 8, conf: 92 }].map((m) => (
          <div key={m.method} className="card-interactive p-4"><p className="text-sm text-white/60">{m.method} Correlation</p><p className="text-2xl font-bold text-white mt-1">{m.clusters} clusters</p><p className="text-xs text-white/40">Avg confidence: {m.conf}%</p></div>))}
      </div></div>)}
    {tab === "clusters" && (<div className="space-y-3">
      {[{ id: "CLU-001", alerts: 47, sources: ["CrowdStrike", "Defender", "Splunk"], type: "Kill Chain", root: "Lateral movement via compromised OAuth token", sev: "critical" },
        { id: "CLU-002", alerts: 23, sources: ["Datadog", "PagerDuty"], type: "Causal", root: "DB connection pool exhaustion cascading to API timeouts", sev: "high" },
        { id: "CLU-003", alerts: 12, sources: ["Elastic", "AWS GuardDuty"], type: "Temporal", root: "Concurrent port scan and brute force attempt", sev: "medium" },
      ].map((c) => (<div key={c.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{c.id}</span><span className="text-xs text-white/40 ml-2">{c.alerts} alerts from {c.sources.join(", ")}</span></div><StatusBadge status={c.sev} /></div>
        <p className="text-white/90 font-medium">{c.root}</p><p className="text-xs text-white/50 mt-1">{c.type} correlation</p></div>))}</div>)}
    {tab === "incidents" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Prioritized Incidents</h3>
      {[{ pri: "P1", title: "Active lateral movement across AWS → GCP", action: "Isolate compromised identity", auto: true },
        { pri: "P2", title: "Database cascading failure", action: "Scale connection pool + investigate root cause", auto: false },
        { pri: "P3", title: "Reconnaissance activity from external IP", action: "Block source IP range", auto: true },
      ].map((i, idx) => (<div key={idx} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium"><span className={clsx("font-bold mr-2", i.pri === "P1" ? "text-red-400" : i.pri === "P2" ? "text-orange-400" : "text-yellow-400")}>{i.pri}</span>{i.title}</p><p className="text-xs text-cyan-400 mt-1">{i.action}</p></div><span className="text-xs text-white/40">{i.auto ? "Auto" : "Manual"}</span></div>))}</div>)}
    {tab === "metrics" && (<div className="card-surface p-6"><h3 className="section-heading">Correlation Performance</h3>
      <div className="grid grid-cols-2 gap-4">
        {[{ m: "Noise Reduction Ratio", v: "68:1" }, { m: "Avg Correlation Time", v: "1.8s" }, { m: "Precision", v: "94%" }, { m: "False Positive Rate", v: "3.2%" }].map((s) => (
          <div key={s.m} className="card-interactive p-4"><p className="text-sm text-white/60">{s.m}</p><p className="text-2xl font-bold text-white mt-1">{s.v}</p></div>))}
      </div></div>)}
  </div>);
}
