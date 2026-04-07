import { useState } from "react";
import { Shield, Activity, AlertTriangle, Eye, Lock } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "data_flows" | "incidents" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "data_flows", label: "Data Flows" },
  { id: "incidents", label: "Incidents" },
  { id: "metrics", label: "Metrics" },
];

const INCIDENTS = [
  { id: "DEM-001", channel: "HTTPS", user: "jsmith@corp.io", volume: "2.4 GB", sensitivity: "Restricted", status: "critical", detail: "Large upload to personal Dropbox during off-hours" },
  { id: "DEM-002", channel: "DNS Tunnel", user: "svc-build-01", volume: "340 MB", sensitivity: "Confidential", status: "high", detail: "DNS tunneling to unknown C2 endpoint detected" },
  { id: "DEM-003", channel: "USB", user: "mwilson@corp.io", volume: "890 MB", sensitivity: "Confidential", status: "high", detail: "Bulk copy to unencrypted USB device" },
  { id: "DEM-004", channel: "Email", user: "agarcia@corp.io", volume: "45 MB", sensitivity: "Internal", status: "medium", detail: "Large attachment to external recipient" },
  { id: "DEM-005", channel: "Cloud Upload", user: "klee@corp.io", volume: "1.1 GB", sensitivity: "Restricted", status: "critical", detail: "Source code repo synced to personal GitHub" },
];

export default function DataExfiltrationMonitor() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Data Exfiltration Monitor" subtitle="Network DLP, USB monitoring, and exfiltration detection" icon={<Shield className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Channels Monitored" value="6" icon={<Activity className="h-5 w-5" />} />
        <MetricCard title="Exfil Detections" value="23" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Transfers Blocked" value="14" icon={<Lock className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Sensitive Matches" value="31" icon={<Eye className="h-5 w-5 text-orange-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Channel Activity</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">{[{ l: "Network/HTTPS", v: "4,200 flows", c: "text-cyan-400" }, { l: "USB", v: "34 events", c: "text-yellow-400" }, { l: "Cloud Upload", v: "189 transfers", c: "text-orange-400" }, { l: "Email", v: "1,240 messages", c: "text-emerald-400" }, { l: "DNS Tunnel", v: "3 detected", c: "text-red-400" }, { l: "Print", v: "12 jobs", c: "text-white/60" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "data_flows" && (<div className="card-surface p-6"><h3 className="section-heading">Active Data Flows</h3><div className="space-y-2">{[{ src: "10.0.1.50", dst: "203.0.113.10", proto: "HTTPS", bytes: "2.4 GB", risk: "high" }, { src: "10.0.2.12", dst: "dns.tunnel.cc", proto: "DNS", bytes: "340 MB", risk: "critical" }, { src: "10.0.3.8", dst: "drive.google.com", proto: "HTTPS", bytes: "1.1 GB", risk: "high" }, { src: "10.0.1.22", dst: "smtp.corp.io", proto: "SMTP", bytes: "45 MB", risk: "medium" }].map((f, i) => (<div key={i} className="card-interactive p-3 flex items-center justify-between text-sm"><div className="flex gap-4"><span className="text-white/70 font-mono">{f.src}</span><span className="text-white/40">→</span><span className="text-white/70 font-mono">{f.dst}</span></div><div className="flex gap-3"><span className="text-white/40">{f.proto}</span><span className="text-cyan-400 font-mono">{f.bytes}</span><StatusBadge status={f.risk} /></div></div>))}</div></div>)}
      {tab === "incidents" && (<div className="space-y-3">{INCIDENTS.map((inc) => (<div key={inc.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="text-white/90 font-medium font-mono text-sm">{inc.id}</span><span className="ml-2 text-xs text-white/40">{inc.channel}</span><span className="ml-2 text-xs text-white/40">{inc.user}</span></div><StatusBadge status={inc.status} /></div><p className="text-white/50 text-sm">{inc.detail}</p><div className="flex gap-4 mt-1 text-xs text-white/40"><span>Volume: {inc.volume}</span><span>Sensitivity: {inc.sensitivity}</span></div></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">DLP Metrics</h3>{[{ m: "Total Data Scanned", v: "12.4 TB", t: "+1.2 TB this week" }, { m: "Block Rate", v: "61%", t: "+8% vs last month" }, { m: "False Positive Rate", v: "3.2%", t: "-0.5%" }, { m: "Avg Detection Time", v: "1.4s", t: "-200ms" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
