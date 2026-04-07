import { useState } from "react";
import { Clock, Activity, AlertTriangle, Search } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "timeline" | "root_cause" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "timeline", label: "Timeline" },
  { id: "root_cause", label: "Root Cause" },
  { id: "metrics", label: "Metrics" },
];

const TIMELINE = [
  { time: "14:22:01", source: "SIEM", event: "Anomalous login from 185.143.xx.xx", severity: "high" },
  { time: "14:22:15", source: "EDR", event: "PowerShell execution with encoded command", severity: "critical" },
  { time: "14:22:34", source: "Network", event: "Lateral movement attempt to 10.0.3.12 via SMB", severity: "critical" },
  { time: "14:23:01", source: "Cloud Trail", event: "S3 bucket listing from compromised role", severity: "high" },
  { time: "14:23:45", source: "Identity", event: "Privilege escalation — assume-role to admin", severity: "critical" },
  { time: "14:24:12", source: "Application", event: "Database query for PII table — 4,200 rows exported", severity: "critical" },
];

export default function IncidentTimelineBuilder() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Incident Timeline Builder" subtitle="Automated incident reconstruction from multi-source correlation" icon={<Clock className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Active Incidents" value="3" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Events Correlated" value="12,400" icon={<Activity className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Sources" value="6" icon={<Search className="h-5 w-5" />} />
        <MetricCard title="Avg Build Time" value="34s" icon={<Clock className="h-5 w-5 text-emerald-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Correlation Summary</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "SIEM Events", v: "4,200", c: "text-cyan-400" }, { l: "EDR Telemetry", v: "3,800", c: "text-emerald-400" }, { l: "Network Flows", v: "2,400", c: "text-yellow-400" }, { l: "Cloud Logs", v: "2,000", c: "text-white/70" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "timeline" && (<div className="space-y-1">{TIMELINE.map((e, i) => (<div key={i} className="card-interactive p-4 flex items-start gap-4"><div className="flex-shrink-0 text-center"><span className="font-mono text-xs text-cyan-400">{e.time}</span><p className="text-xs text-white/40 mt-1">{e.source}</p></div><div className="flex-1"><div className="flex items-start justify-between"><p className="text-white/90 text-sm">{e.event}</p><StatusBadge status={e.severity} /></div></div></div>))}</div>)}
      {tab === "root_cause" && (<div className="card-surface p-6"><h3 className="section-heading">Root Cause Analysis</h3><div className="space-y-3"><div className="card-interactive p-4"><h4 className="text-white/90 font-medium mb-2">Initial Access</h4><p className="text-white/60 text-sm">Compromised VPN credentials (phishing) from 185.143.xx.xx at 14:22:01</p></div><div className="card-interactive p-4"><h4 className="text-white/90 font-medium mb-2">Privilege Escalation</h4><p className="text-white/60 text-sm">Exploited overprivileged IAM role to assume admin at 14:23:45</p></div><div className="card-interactive p-4"><h4 className="text-white/90 font-medium mb-2">Impact</h4><p className="text-white/60 text-sm">4,200 PII records exfiltrated from production database</p></div></div></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Timeline Performance</h3>{[{ m: "Avg Build Time", v: "34s", t: "-12s" }, { m: "Source Coverage", v: "6/6", t: "100%" }, { m: "Correlation Accuracy", v: "97.2%", t: "+1.4%" }, { m: "Root Cause Hit Rate", v: "89%", t: "+4%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
