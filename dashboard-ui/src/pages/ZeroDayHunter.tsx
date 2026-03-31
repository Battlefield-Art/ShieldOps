import { useState } from "react";
import { Bug, Shield, AlertTriangle, Globe, Crosshair, FileText } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "zero_day_feed" | "exposure_map" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "zero_day_feed", label: "Zero-Day Feed" },
  { id: "exposure_map", label: "Exposure Map" },
  { id: "metrics", label: "Metrics" },
];

const ZERO_DAYS = [
  { cve: "CVE-2026-0001", title: "Critical RCE in web framework", severity: "critical", source: "NVD", exploitAvailable: true, assets: 142 },
  { cve: "CVE-2026-0002", title: "Auth bypass in SSO provider", severity: "high", source: "Vendor Advisory", exploitAvailable: false, assets: 67 },
  { cve: "CVE-2026-0003", title: "Privilege escalation in Linux kernel 6.x", severity: "high", source: "Researcher", exploitAvailable: true, assets: 312 },
  { cve: "CVE-2026-0004", title: "Memory corruption in TLS library", severity: "medium", source: "NVD", exploitAvailable: false, assets: 24 },
];

const EXPOSURES = [
  { cve: "CVE-2026-0001", assets: 142, internetFacing: 23, impact: "catastrophic", mitigated: true },
  { cve: "CVE-2026-0003", assets: 312, internetFacing: 0, impact: "severe", mitigated: true },
  { cve: "CVE-2026-0002", assets: 67, internetFacing: 12, impact: "severe", mitigated: false },
];

export default function ZeroDayHunter() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Zero-Day Hunter" subtitle="Zero-day vulnerability hunting, detection, and virtual patching" icon={<Bug className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Zero-Days Tracked" value="4" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Exposed Assets" value="545" icon={<Globe className="h-5 w-5 text-yellow-400" />} />
        <MetricCard title="Signatures Deployed" value="12" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Mitigations Active" value="9" icon={<Crosshair className="h-5 w-5 text-cyan-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Threat Posture</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Critical", v: "1", c: "text-red-400" }, { l: "High", v: "2", c: "text-orange-400" }, { l: "Medium", v: "1", c: "text-yellow-400" }, { l: "Mitigated", v: "3/4", c: "text-emerald-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "zero_day_feed" && (<div className="space-y-3">{ZERO_DAYS.map((z) => (<div key={z.cve} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{z.cve}</span><span className="ml-2 text-xs text-white/40">{z.source}</span></div><StatusBadge status={z.severity} /></div><p className="text-white/90 text-sm">{z.title}</p><div className="flex gap-4 mt-2 text-xs text-white/50"><span>{z.assets} exposed assets</span>{z.exploitAvailable && <span className="text-red-400">Exploit available</span>}</div></div>))}</div>)}
      {tab === "exposure_map" && (<div className="space-y-3">{EXPOSURES.map((e) => (<div key={e.cve} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{e.cve}</span><span className="ml-2 text-xs text-white/40">{e.impact}</span></div><StatusBadge status={e.mitigated ? "mitigated" : "exposed"} /></div><div className="flex gap-4 mt-2 text-xs text-white/50"><span>{e.assets} total assets</span><span className={e.internetFacing > 0 ? "text-red-400" : "text-white/40"}>{e.internetFacing} internet-facing</span></div></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Hunt Performance</h3>{[{ m: "Avg Detection Time", v: "2.4h", t: "-1.2h" }, { m: "Signature Coverage", v: "87%", t: "+12%" }, { m: "False Positive Rate", v: "3%", t: "-1%" }, { m: "Virtual Patches Active", v: "9", t: "+3" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
