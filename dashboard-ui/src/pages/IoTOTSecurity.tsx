import { useState } from "react";
import { Cpu, Wifi, AlertTriangle, Shield, Network, Eye } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "devices" | "threats" | "segmentation";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "devices", label: "Devices" }, { id: "threats", label: "Threats" }, { id: "segmentation", label: "Segmentation" }];
export default function IoTOTSecurity() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="IoT/OT Security" subtitle="Device discovery, behavioral profiling, and micro-segmentation for IoT and OT" icon={<Cpu className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Devices Discovered" value="847" icon={<Wifi className="h-5 w-5" />} />
      <MetricCard title="Unmanaged" value="34" icon={<AlertTriangle className="h-5 w-5 text-yellow-400" />} />
      <MetricCard title="Threats (7d)" value="5" icon={<Shield className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Segmented" value="91%" icon={<Network className="h-5 w-5 text-emerald-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Device Categories</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {[{ cat: "IoT Sensors", count: 423, managed: 402, color: "text-cyan-400" }, { cat: "OT Controllers", count: 156, managed: 148, color: "text-yellow-400" }, { cat: "Edge AI", count: 89, managed: 82, color: "text-emerald-400" }].map((c) => (
        <div key={c.cat} className="card-interactive p-4"><p className={clsx("font-bold", c.color)}>{c.cat}</p><p className="text-2xl font-bold text-white/80 mt-1">{c.count}</p><p className="text-xs text-white/40">{c.managed} managed | {c.count - c.managed} unmanaged</p></div>))}</div></div>)}
    {tab === "devices" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Device</th><th className="px-4 py-3">Category</th><th className="px-4 py-3">Protocol</th><th className="px-4 py-3">Risk</th><th className="px-4 py-3">Segmented</th></tr></thead>
      <tbody>{[
        { name: "PLC-Controller-01", cat: "ot_controller", proto: "Modbus/TCP", risk: "high", seg: true },
        { name: "Edge-AI-Cam-12", cat: "edge_ai", proto: "RTSP + MQTT", risk: "medium", seg: true },
        { name: "Unknown-Device-34", cat: "unknown", proto: "HTTP", risk: "critical", seg: false },
        { name: "HVAC-Sensor-07", cat: "building_automation", proto: "BACnet", risk: "low", seg: true },
      ].map((d, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90">{d.name}</td><td className="px-4 py-3"><StatusBadge status={d.cat} /></td><td className="px-4 py-3 text-white/60">{d.proto}</td><td className="px-4 py-3"><StatusBadge status={d.risk} /></td><td className="px-4 py-3">{d.seg ? <span className="text-emerald-400">Yes</span> : <span className="text-red-400">No</span>}</td></tr>))}</tbody></table></div>)}
    {tab === "threats" && (<div className="space-y-3">
      {[{ id: "IOT-005", device: "Unknown-Device-34", threat: "Unauthorized HTTP beacon to external IP", severity: "critical" },
        { id: "IOT-004", device: "PLC-Controller-01", threat: "Modbus write command from unauthorized source", severity: "high" },
        { id: "IOT-003", device: "Edge-AI-Cam-12", threat: "RTSP stream accessed from non-whitelisted IP", severity: "medium" },
      ].map((t) => (<div key={t.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{t.id}</span><span className="text-xs text-white/40 ml-2">{t.device}</span></div><StatusBadge status={t.severity} /></div>
        <p className="text-white/90 font-medium">{t.threat}</p></div>))}</div>)}
    {tab === "segmentation" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Micro-Segmentation Policies</h3>
      {[{ zone: "OT Controllers", policy: "Allow only SCADA traffic, block internet", devices: 156, status: "enforced" },
        { zone: "Edge AI Devices", policy: "Allow model updates + telemetry only", devices: 89, status: "enforced" },
        { zone: "IoT Sensors", policy: "Allow MQTT to broker only", devices: 423, status: "enforced" },
        { zone: "Unmanaged", policy: "Quarantine — no network access", devices: 34, status: "partially_enforced" },
      ].map((s, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{s.zone}</p><p className="text-xs text-white/50">{s.policy} | {s.devices} devices</p></div><StatusBadge status={s.status} /></div>))}</div>)}
  </div>);
}
