import { useState } from "react";
import { Smartphone, Shield, AlertTriangle, Wifi, BarChart3, Lock } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "devices" | "threats" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "devices", label: "Devices" },
  { id: "threats", label: "Threats" },
  { id: "metrics", label: "Metrics" },
];

const DEVICES = [
  { name: "iPhone 15 Pro (J.Smith)", platform: "iOS 17.4", status: "healthy", mdm: true, detail: "Encrypted, MDM enrolled, up to date" },
  { name: "Pixel 8 (M.Chen)", platform: "Android 14", status: "medium", mdm: true, detail: "Side-loaded app detected, pending review" },
  { name: "Galaxy S24 (R.Kumar)", platform: "Android 14", status: "critical", mdm: false, detail: "Rooted device, not MDM enrolled, outdated OS" },
  { name: "iPad Air (T.Wilson)", platform: "iOS 17.3", status: "low", mdm: true, detail: "Encrypted, minor patch pending" },
  { name: "OnePlus 12 (A.Park)", platform: "Android 13", status: "high", mdm: true, detail: "Malicious app detected, network threat active" },
];

export default function MobileThreatDefender() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Mobile Threat Defender" subtitle="Mobile device security and threat defense" icon={<Smartphone className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Devices Managed" value="3,412" icon={<Smartphone className="h-5 w-5" />} />
        <MetricCard title="Active Threats" value="23" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Compliance Rate" value="94%" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Network Threats" value="5" icon={<Wifi className="h-5 w-5 text-yellow-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Platform Distribution</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "iOS", v: "1,842", c: "text-cyan-400" }, { l: "Android", v: "1,456", c: "text-emerald-400" }, { l: "Rooted/JB", v: "14", c: "text-red-400" }, { l: "No MDM", v: "89", c: "text-yellow-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "devices" && (<div className="space-y-3">{DEVICES.map((d) => (<div key={d.name} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="text-white/90 font-medium text-sm">{d.name}</span><span className="ml-2 text-xs text-white/40">{d.platform}</span></div><StatusBadge status={d.status} /></div><p className="text-white/50 text-sm">{d.detail}</p><div className="mt-1 flex gap-2">{d.mdm ? <span className="text-xs text-emerald-400">MDM Enrolled</span> : <span className="text-xs text-red-400">No MDM</span>}</div></div>))}</div>)}
      {tab === "threats" && (<div className="card-surface p-6"><h3 className="section-heading">Active Threats</h3><div className="space-y-2">{[{ threat: "Rooted device accessing corporate data", category: "Root/Jailbreak", severity: "critical" }, { threat: "MITM attack on public WiFi — 2 devices", category: "Network Attack", severity: "critical" }, { threat: "Malicious app: FakeVPN Pro v2.1", category: "Malware", severity: "high" }, { threat: "Side-loaded messaging app with SMS perms", category: "Data Leakage", severity: "medium" }].map((t, i) => (<div key={i} className="card-interactive p-3 flex items-center justify-between text-sm"><div className="flex-1"><span className="text-white/70">{t.threat}</span><span className="ml-2 text-xs text-white/40">{t.category}</span></div><StatusBadge status={t.severity} /></div>))}</div></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Defense Trends</h3>{[{ m: "Devices Scanned/Day", v: "3,412", t: "+120 this week" }, { m: "Malicious Apps Blocked", v: "47", t: "+8" }, { m: "Network Threats Blocked", v: "23", t: "-5" }, { m: "Avg Response Time", v: "1.2s", t: "-0.3s" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
