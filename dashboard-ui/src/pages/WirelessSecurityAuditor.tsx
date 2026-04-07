import { useState } from "react";
import { Wifi, Radio, Lock, AlertTriangle, Shield } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "access_points" | "rogue_detection" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "access_points", label: "Access Points" },
  { id: "rogue_detection", label: "Rogue Detection" },
  { id: "metrics", label: "Metrics" },
];

const ACCESS_POINTS = [
  { id: "AP-001", ssid: "CorpNet-5G", bssid: "AA:BB:CC:DD:EE:01", encryption: "WPA3", status: "authorized", clients: 47 },
  { id: "AP-002", ssid: "CorpNet-2.4G", bssid: "AA:BB:CC:DD:EE:02", encryption: "WPA2", status: "authorized", clients: 23 },
  { id: "AP-003", ssid: "Guest-WiFi", bssid: "AA:BB:CC:DD:EE:03", encryption: "WPA2", status: "authorized", clients: 12 },
  { id: "AP-004", ssid: "CorpNet-5G", bssid: "FF:GG:HH:II:JJ:99", encryption: "Open", status: "evil_twin", clients: 3 },
];

const ROGUES = [
  { id: "RGE-001", ssid: "CorpNet-5G", bssid: "FF:GG:HH:II:JJ:99", type: "Evil Twin", threat: "critical", confidence: "98%" },
  { id: "RGE-002", ssid: "FreeWiFi-Corp", bssid: "XX:YY:ZZ:AA:BB:01", type: "Rogue", threat: "high", confidence: "92%" },
  { id: "RGE-003", ssid: "Neighbor-Office", bssid: "11:22:33:44:55:66", type: "Neighbor", threat: "low", confidence: "85%" },
];

export default function WirelessSecurityAuditor() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Wireless Security Auditor" subtitle="WiFi security auditing with rogue AP and evil twin detection" icon={<Wifi className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Access Points" value="156" icon={<Radio className="h-5 w-5" />} />
        <MetricCard title="Rogue APs" value="3" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="WPA3 Compliant" value="82%" icon={<Lock className="h-5 w-5 text-cyan-400" />} />
        <MetricCard title="Security Score" value="8.1" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Encryption Distribution</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "WPA3", v: "128", c: "text-cyan-400" }, { l: "WPA2-Enterprise", v: "18", c: "text-emerald-400" }, { l: "WPA2-Personal", v: "7", c: "text-yellow-400" }, { l: "Open/WEP", v: "3", c: "text-red-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "access_points" && (<div className="space-y-3">{ACCESS_POINTS.map((ap) => (<div key={ap.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{ap.id}</span><span className="ml-2 text-xs text-white/40">{ap.bssid}</span></div><StatusBadge status={ap.status} /></div><p className="text-white/90 text-sm font-medium">{ap.ssid}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>Encryption: {ap.encryption}</span><span>{ap.clients} clients</span></div></div>))}</div>)}
      {tab === "rogue_detection" && (<div className="space-y-3">{ROGUES.map((r) => (<div key={r.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{r.id}</span><span className="ml-2 text-xs text-white/40">{r.type}</span></div><StatusBadge status={r.threat} /></div><p className="text-white/90 text-sm font-medium">{r.ssid}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>BSSID: {r.bssid}</span><span>Confidence: {r.confidence}</span></div></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Wireless Audit Performance</h3>{[{ m: "WPA3 Adoption Rate", v: "82%", t: "+18%" }, { m: "Rogue AP Detection", v: "98%", t: "+3%" }, { m: "Avg Scan Duration", v: "4.2 min", t: "-1.1 min" }, { m: "Evil Twin Detection", v: "97%", t: "+5%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
