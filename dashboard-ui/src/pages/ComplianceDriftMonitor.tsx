import { useState } from "react";
import { ShieldCheck, AlertTriangle, FileCheck, Bell } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "control_status" | "drift_timeline" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "control_status", label: "Control Status" },
  { id: "drift_timeline", label: "Drift Timeline" },
  { id: "metrics", label: "Metrics" },
];

const DRIFTS = [
  { id: "DE-001", control: "SOC2-CC6.1", framework: "SOC 2", severity: "critical", type: "missing", detail: "Logical access control removed during infrastructure migration" },
  { id: "DE-002", control: "HIPAA-164.312(a)", framework: "HIPAA", severity: "high", type: "drifted", detail: "Access control policy weakened — MFA disabled for service accounts" },
  { id: "DE-003", control: "PCI-DSS-3.4", framework: "PCI DSS", severity: "high", type: "drifted", detail: "PAN rendering configuration changed in payment processing module" },
  { id: "DE-004", control: "NIST-AC-2", framework: "NIST 800-53", severity: "medium", type: "partially_compliant", detail: "Account management automation gap — manual reviews overdue" },
];

export default function ComplianceDriftMonitor() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Compliance Drift Monitor" subtitle="Continuous compliance baseline tracking and drift detection" icon={<ShieldCheck className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Controls Scanned" value="342" icon={<FileCheck className="h-5 w-5" />} />
        <MetricCard title="Drifts Detected" value="14" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Compliance Rate" value="95.9%" icon={<ShieldCheck className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Alerts Sent" value="8" icon={<Bell className="h-5 w-5 text-amber-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Compliance Health</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Compliant", v: "328", c: "text-emerald-400" }, { l: "Drifted", v: "8", c: "text-red-400" }, { l: "Partially", v: "4", c: "text-amber-400" }, { l: "Missing", v: "2", c: "text-red-500" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "control_status" && (<div className="space-y-3">{DRIFTS.map((d) => (<div key={d.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{d.id}</span><span className="ml-2 text-white/90 font-medium">{d.control}</span><span className="ml-2 text-white/50 text-xs">({d.framework})</span></div><StatusBadge status={d.severity} /></div><p className="text-white/50 text-xs">{d.detail}</p><p className="text-xs text-amber-400/80 mt-1">Type: {d.type}</p></div>))}</div>)}
      {tab === "drift_timeline" && (<div className="card-surface p-6"><h3 className="section-heading">Drift Events (Last 30 Days)</h3><div className="space-y-3">{[{ date: "2026-03-30", count: 3, frameworks: "SOC 2, HIPAA" }, { date: "2026-03-25", count: 2, frameworks: "PCI DSS" }, { date: "2026-03-18", count: 5, frameworks: "NIST, ISO 27001" }, { date: "2026-03-10", count: 4, frameworks: "GDPR, SOC 2" }].map((e, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{e.date}</p><p className="text-xs text-white/50">{e.frameworks}</p></div><span className="text-lg font-mono text-amber-400">{e.count} drifts</span></div>))}</div></div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Compliance Trends</h3>{[{ m: "Compliance Rate", v: "95.9%", t: "-0.4%" }, { m: "MTTR (Drift)", v: "4.2h", t: "-1.1h" }, { m: "Scan Frequency", v: "15min", t: "stable" }, { m: "Audit Readiness", v: "92%", t: "+1%" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
