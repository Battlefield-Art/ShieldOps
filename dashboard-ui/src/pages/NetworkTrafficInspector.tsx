import { useState } from "react";
import { Activity, Shield, AlertTriangle, Eye, Wifi } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "traffic_analysis" | "threat_map" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "traffic_analysis", label: "Traffic Analysis" },
  { id: "threat_map", label: "Threat Map" },
  { id: "metrics", label: "Metrics" },
];

const FLOWS = [
  { src: "10.0.1.100:49821", dst: "8.8.8.8:53", proto: "DNS", bytes: "4.2 KB", risk: "low", detail: "Standard DNS resolution — google.com" },
  { src: "10.0.2.55:38012", dst: "185.22.174.9:443", proto: "TLS", bytes: "128 KB", risk: "high", detail: "High-entropy payload to known C2 IP, beaconing interval 60s" },
  { src: "10.0.1.200:51003", dst: "10.0.3.50:5432", proto: "TCP", bytes: "12 MB", risk: "critical", detail: "Unusual lateral movement — bulk data transfer to internal DB" },
  { src: "10.0.4.10:60100", dst: "1.1.1.1:443", proto: "DoH", bytes: "890 KB", risk: "medium", detail: "DNS-over-HTTPS tunneling indicators — high query entropy" },
  { src: "10.0.1.15:22", dst: "203.0.113.5:4444", proto: "SSH", bytes: "2.1 MB", risk: "high", detail: "Reverse SSH tunnel to external host on non-standard port" },
];

export default function NetworkTrafficInspector() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Network Traffic Inspector" subtitle="Deep packet inspection and traffic anomaly detection" icon={<Activity className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Active Flows" value="12,847" icon={<Wifi className="h-5 w-5" />} />
        <MetricCard title="Anomalies Detected" value="23" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="C2 Beacons" value="3" icon={<Shield className="h-5 w-5 text-red-400" />} />
        <MetricCard title="DNS Tunneling" value="1" icon={<Eye className="h-5 w-5 text-orange-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Protocol Distribution</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "TLS/HTTPS", v: "8,421", c: "text-emerald-400" }, { l: "DNS", v: "2,190", c: "text-cyan-400" }, { l: "SSH", v: "412", c: "text-yellow-400" }, { l: "Other", v: "1,824", c: "text-white/60" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "traffic_analysis" && (<div className="space-y-3">{FLOWS.map((f, i) => (<div key={i} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="text-white/90 font-medium font-mono text-sm">{f.src} → {f.dst}</span><span className="ml-2 text-xs text-white/40">{f.proto}</span></div><StatusBadge status={f.risk} /></div><p className="text-white/50 text-sm">{f.detail}</p><span className="text-xs text-white/40">Transferred: {f.bytes}</span></div>))}</div>)}
      {tab === "threat_map" && (<div className="card-surface p-6"><h3 className="section-heading">Detected Threats</h3><div className="space-y-2">{[{ threat: "C2 Beacon — 185.22.174.9", technique: "T1071.001", severity: "high" }, { threat: "Lateral Movement — 10.0.1.200 → 10.0.3.50", technique: "T1021", severity: "critical" }, { threat: "DNS Tunneling — high-entropy DoH queries", technique: "T1572", severity: "medium" }, { threat: "Reverse Shell — SSH tunnel to 203.0.113.5", technique: "T1572", severity: "high" }].map((t, i) => (<div key={i} className="card-interactive p-3 flex items-center justify-between text-sm"><span className="text-white/70">{t.threat}</span><div className="flex gap-3"><span className="text-white/40 font-mono">{t.technique}</span><StatusBadge status={t.severity} /></div></div>))}</div></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Inspection Metrics</h3>{[{ m: "Total Bandwidth", v: "4.2 TB/day", t: "+8% vs yesterday" }, { m: "Anomaly Rate", v: "0.18%", t: "+0.03%" }, { m: "Mean Detection Time", v: "12s", t: "-3s improvement" }, { m: "False Positive Rate", v: "2.1%", t: "-0.5%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
