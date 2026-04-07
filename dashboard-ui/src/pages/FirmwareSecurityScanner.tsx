import { useState } from "react";
import { Cpu, Shield, AlertTriangle, Lock, Package } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "firmware_inventory" | "vulnerabilities" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "firmware_inventory", label: "Firmware Inventory" },
  { id: "vulnerabilities", label: "Vulnerabilities" },
  { id: "metrics", label: "Metrics" },
];

const FIRMWARE = [
  { device: "Cisco ISR 4331", vendor: "Cisco", version: "16.12.4", arch: "arm64", risk: "high", vulns: 12 },
  { device: "Hikvision DS-2CD2", vendor: "Hikvision", version: "5.7.1", arch: "arm", risk: "critical", vulns: 23 },
  { device: "Siemens S7-1200", vendor: "Siemens", version: "4.5.2", arch: "mips", risk: "high", vulns: 8 },
  { device: "Ubiquiti USG Pro", vendor: "Ubiquiti", version: "6.2.49", arch: "arm64", risk: "medium", vulns: 3 },
  { device: "Honeywell T6 Pro", vendor: "Honeywell", version: "2.1.0", arch: "arm", risk: "critical", vulns: 17 },
];

const VULNS = [
  { cve: "CVE-2024-21762", component: "openssl", severity: "critical", cvss: 9.8, device: "Hikvision DS-2CD2", exploitable: true },
  { cve: "CVE-2024-3400", component: "busybox", severity: "critical", cvss: 9.1, device: "Honeywell T6 Pro", exploitable: true },
  { cve: "CVE-2024-1709", component: "dropbear", severity: "high", cvss: 8.4, device: "Cisco ISR 4331", exploitable: false },
  { cve: "CVE-2024-27198", component: "libcurl", severity: "high", cvss: 7.8, device: "Siemens S7-1200", exploitable: true },
  { cve: "CVE-2024-20353", component: "dnsmasq", severity: "medium", cvss: 5.9, device: "Ubiquiti USG Pro", exploitable: false },
];

export default function FirmwareSecurityScanner() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Firmware Security Scanner" subtitle="IoT/OT firmware vulnerability analysis and SBOM management" icon={<Cpu className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Firmware Images" value="156" icon={<Package className="h-5 w-5" />} />
        <MetricCard title="Critical CVEs" value="47" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Weak Crypto" value="23" icon={<Lock className="h-5 w-5 text-orange-400" />} />
        <MetricCard title="Outdated Components" value="312" icon={<Shield className="h-5 w-5 text-yellow-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Risk Distribution</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Critical", v: "23", c: "text-red-400" }, { l: "High", v: "45", c: "text-orange-400" }, { l: "Medium", v: "67", c: "text-yellow-400" }, { l: "Low", v: "21", c: "text-emerald-400" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-2xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "firmware_inventory" && (<div className="space-y-3">{FIRMWARE.map((f) => (<div key={f.device} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="text-white/90 font-medium text-sm">{f.device}</span><span className="ml-2 text-xs text-white/40">{f.vendor}</span></div><StatusBadge status={f.risk} /></div><div className="flex gap-4 text-xs text-white/50"><span>Version: {f.version}</span><span>Arch: {f.arch}</span><span>Vulns: {f.vulns}</span></div></div>))}</div>)}
      {tab === "vulnerabilities" && (<div className="space-y-3">{VULNS.map((v) => (<div key={v.cve} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="text-white/90 font-medium font-mono text-sm">{v.cve}</span><span className="ml-2 text-xs text-white/40">{v.component}</span></div><StatusBadge status={v.severity} /></div><div className="flex gap-4 text-xs text-white/50"><span>CVSS: {v.cvss}</span><span>Device: {v.device}</span>{v.exploitable && <span className="text-red-400">Exploitable</span>}</div></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Scanner Metrics</h3>{[{ m: "Images Scanned", v: "156", t: "+8 this week" }, { m: "Components Tracked", v: "2,847", t: "+124" }, { m: "Avg Risk Score", v: "7.1/10", t: "-0.3" }, { m: "Patch Coverage", v: "68%", t: "+5%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
