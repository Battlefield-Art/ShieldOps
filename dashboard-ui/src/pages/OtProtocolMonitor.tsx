import { useState } from "react";
import { Cpu, AlertTriangle, Shield, Activity, Server, Eye } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "device_inventory" | "protocol_anomalies" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "device_inventory", label: "Device Inventory" },
  { id: "protocol_anomalies", label: "Protocol Anomalies" },
  { id: "metrics", label: "Metrics" },
];

const DEVICES = [
  { id: "OT-001", name: "PLC Controller A-14", protocol: "Modbus/TCP", zone: "Zone 3", firmware: "v4.2.1", status: "online" },
  { id: "OT-002", name: "RTU Gateway B-07", protocol: "DNP3", zone: "Zone 2", firmware: "v3.8.0", status: "online" },
  { id: "OT-003", name: "HMI Station C-01", protocol: "OPC UA", zone: "Zone 1", firmware: "v6.1.3", status: "degraded" },
  { id: "OT-004", name: "Safety Controller D-22", protocol: "EtherNet/IP", zone: "Zone 4", firmware: "v2.9.7", status: "online" },
];

const ANOMALIES = [
  { id: "PA-001", device: "OT-003", protocol: "OPC UA", anomaly: "Unexpected write to safety register", severity: "critical", time: "5m ago" },
  { id: "PA-002", device: "OT-001", protocol: "Modbus/TCP", anomaly: "Function code 0x08 diagnostic scan", severity: "high", time: "18m ago" },
  { id: "PA-003", device: "OT-002", protocol: "DNP3", anomaly: "Unsolicited response from unknown source", severity: "medium", time: "42m ago" },
];

export default function OtProtocolMonitor() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="OT Protocol Monitor" subtitle="Industrial control system protocol monitoring and anomaly detection" icon={<Cpu className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Monitored Devices" value="186" icon={<Server className="h-5 w-5" />} />
        <MetricCard title="Protocol Anomalies (24h)" value="12" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Protocols Tracked" value="7" icon={<Activity className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Zone Coverage" value="100%" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Protocol Distribution</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Modbus/TCP", v: "62", c: "text-cyan-400" }, { l: "OPC UA", v: "48", c: "text-emerald-400" }, { l: "DNP3", v: "41", c: "text-yellow-400" }, { l: "EtherNet/IP", v: "35", c: "text-white/70" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "device_inventory" && (<div className="space-y-3">{DEVICES.map((d) => (<div key={d.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{d.id}</span><span className="ml-2 text-xs text-white/40">{d.zone}</span></div><StatusBadge status={d.status} /></div><p className="text-white/90 text-sm font-medium">{d.name}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>Protocol: {d.protocol}</span><span>Firmware: {d.firmware}</span></div></div>))}</div>)}
      {tab === "protocol_anomalies" && (<div className="space-y-3">{ANOMALIES.map((a) => (<div key={a.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{a.id}</span><span className="ml-2 text-xs text-white/40">{a.device}</span></div><StatusBadge status={a.severity} /></div><p className="text-white/90 text-sm"><Eye className="inline h-3 w-3 mr-1" />{a.anomaly}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>Protocol: {a.protocol}</span><span>{a.time}</span></div></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">OT Security Metrics</h3>{[{ m: "Anomaly Detection Rate", v: "96.4%", t: "+1.2%" }, { m: "Avg Detection Latency", v: "340ms", t: "-80ms" }, { m: "False Positive Rate", v: "2.1%", t: "-0.5%" }, { m: "Device Compliance", v: "91%", t: "+3%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
