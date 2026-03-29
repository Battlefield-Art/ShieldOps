import { useState } from "react";
import { Usb, ShieldCheck, AlertTriangle, Ban } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
type TabId = "overview" | "devices" | "transfers" | "policies";
const TABS: { id: TabId; label: string }[] = [{ id: "overview", label: "Overview" }, { id: "devices", label: "Devices" }, { id: "transfers", label: "Transfers" }, { id: "policies", label: "Policy Enforcements" }];
export default function USBDeviceController() {
  const [tab, setTab] = useState<TabId>("overview");
  return (<div className="space-y-6">
    <PageHeader title="USB Device Controller" subtitle="Whitelist management, unauthorized detection, data transfer monitoring, and policy enforcement" icon={<Usb className="h-6 w-6" />} />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard title="Connected Devices" value="186" icon={<Usb className="h-5 w-5" />} />
      <MetricCard title="Whitelisted" value="142" icon={<ShieldCheck className="h-5 w-5 text-emerald-400" />} />
      <MetricCard title="Unauthorized" value="12" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
      <MetricCard title="Transfers Blocked" value="8" icon={<Ban className="h-5 w-5 text-yellow-400" />} />
    </div>
    <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
    {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">USB Security Summary</h3><div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {[{ label: "HID Devices", count: 98, color: "text-cyan-400" }, { label: "Storage Devices", count: 64, color: "text-yellow-400" }, { label: "Unknown Devices", count: 24, color: "text-red-400" }].map((s) => (
        <div key={s.label} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.label}</p><p className={clsx("text-3xl font-bold mt-1", s.color)}>{s.count}</p></div>))}</div></div>)}
    {tab === "devices" && (<div className="card-surface overflow-hidden"><table className="w-full text-sm"><thead><tr className="border-b border-white/10 text-left text-white/50"><th className="px-4 py-3">Device</th><th className="px-4 py-3">Type</th><th className="px-4 py-3">Endpoint</th><th className="px-4 py-3">User</th><th className="px-4 py-3">Status</th></tr></thead>
      <tbody>{[
        { name: "Logitech Receiver", type: "HID", endpoint: "EP-001", user: "alice@corp.com", status: "whitelisted" },
        { name: "SanDisk Cruzer", type: "Storage", endpoint: "EP-002", user: "bob@corp.com", status: "unauthorized" },
        { name: "Unknown Device", type: "Storage", endpoint: "EP-003", user: "charlie@corp.com", status: "blocked" },
        { name: "Dell Keyboard", type: "HID", endpoint: "EP-004", user: "diana@corp.com", status: "whitelisted" },
      ].map((d, i) => (<tr key={i} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-3 text-white/90 font-medium">{d.name}</td><td className="px-4 py-3 text-white/60">{d.type}</td><td className="px-4 py-3 text-white/60 font-mono text-xs">{d.endpoint}</td><td className="px-4 py-3 text-white/60">{d.user}</td><td className="px-4 py-3"><StatusBadge status={d.status} /></td></tr>))}</tbody></table></div>)}
    {tab === "transfers" && (<div className="space-y-3">
      {[{ id: "TXF-001", device: "SanDisk Cruzer", file: "report.xlsx", size: "2.5MB", direction: "Outbound", risk: "high", blocked: true },
        { id: "TXF-002", device: "Unknown Device", file: "database.sql", size: "150MB", direction: "Outbound", risk: "critical", blocked: true },
        { id: "TXF-003", device: "SanDisk Cruzer", file: "readme.txt", size: "4KB", direction: "Inbound", risk: "low", blocked: false },
      ].map((t) => (<div key={t.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{t.id}</span><span className="text-xs text-white/40 ml-2">{t.device}</span></div><StatusBadge status={t.risk} /></div>
        <p className="text-white/90 font-medium">{t.file} ({t.size})</p><p className="text-xs text-white/50">{t.direction} | {t.blocked ? "Blocked" : "Allowed"}</p></div>))}</div>)}
    {tab === "policies" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Recent Enforcements</h3>
      {[{ id: "ENF-001", device: "SanDisk Cruzer", action: "Block device", reason: "Unauthorized USB storage", endpoint: "EP-002" },
        { id: "ENF-002", device: "Unknown Device", action: "Block device + transfer", reason: "Unregistered mass storage", endpoint: "EP-003" },
        { id: "ENF-003", device: "SanDisk Cruzer", action: "Block transfer", reason: "Sensitive file: report.xlsx", endpoint: "EP-002" },
      ].map((e) => (<div key={e.id} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{e.action}</p><p className="text-xs text-white/50">{e.device} | {e.reason} | {e.endpoint}</p></div><StatusBadge status="enforced" /></div>))}</div>)}
  </div>);
}
