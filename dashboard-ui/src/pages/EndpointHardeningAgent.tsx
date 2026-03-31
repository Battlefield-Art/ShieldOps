import { useState } from "react";
import { Monitor, Shield, AlertTriangle, CheckCircle, Wrench, Activity } from "lucide-react";
import clsx from "clsx";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";

type TabId = "overview" | "endpoint_compliance" | "hardening_tasks" | "metrics";
const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "endpoint_compliance", label: "Endpoint Compliance" },
  { id: "hardening_tasks", label: "Hardening Tasks" },
  { id: "metrics", label: "Metrics" },
];

const ENDPOINTS = [
  { id: "EP-001", hostname: "web-prod-01", os: "Ubuntu 22.04", score: "94%", status: "compliant", deviations: 2 },
  { id: "EP-002", hostname: "db-prod-02", os: "RHEL 9.1", score: "87%", status: "warning", deviations: 5 },
  { id: "EP-003", hostname: "win-dev-01", os: "Windows Server 2022", score: "62%", status: "critical", deviations: 14 },
  { id: "EP-004", hostname: "mac-eng-03", os: "macOS 15.2", score: "91%", status: "compliant", deviations: 3 },
];

export default function EndpointHardeningAgent() {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-6">
      <PageHeader title="Endpoint Hardening" subtitle="CIS benchmark compliance, deviation detection, and automated remediation" icon={<Monitor className="h-6 w-6" />} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard title="Endpoints Scanned" value="847" icon={<Monitor className="h-5 w-5" />} />
        <MetricCard title="Avg Compliance" value="86.4%" icon={<Shield className="h-5 w-5 text-emerald-400" />} />
        <MetricCard title="Deviations Found" value="1,247" icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <MetricCard title="Auto-Remediated" value="892" icon={<Wrench className="h-5 w-5 text-cyan-400" />} />
      </div>
      <div className="tab-bar">{TABS.map((t) => (<button key={t.id} onClick={() => setTab(t.id)} className={clsx("tab-item", tab === t.id && "tab-item-active")}>{t.label}</button>))}</div>
      {tab === "overview" && (<div className="card-surface p-6"><h3 className="section-heading">Compliance Posture</h3><div className="grid grid-cols-1 md:grid-cols-4 gap-4">{[{ l: "Compliant", v: "612", c: "text-emerald-400" }, { l: "Warning", v: "187", c: "text-yellow-400" }, { l: "Critical", v: "48", c: "text-red-400" }, { l: "Unscanned", v: "0", c: "text-white/40" }].map((s) => (<div key={s.l} className="card-interactive p-4 text-center"><p className="text-sm text-white/60">{s.l}</p><p className={clsx("text-xl font-bold mt-1", s.c)}>{s.v}</p></div>))}</div></div>)}
      {tab === "endpoint_compliance" && (<div className="space-y-3">{ENDPOINTS.map((ep) => (<div key={ep.id} className="card-interactive p-4"><div className="flex items-start justify-between mb-2"><div><span className="font-mono text-xs text-cyan-400">{ep.id}</span><span className="ml-2 text-white/90 font-medium">{ep.hostname}</span></div><StatusBadge status={ep.status} /></div><div className="grid grid-cols-3 gap-2 text-sm"><div><span className="text-white/50">OS:</span> <span className="text-white/80">{ep.os}</span></div><div><span className="text-white/50">Score:</span> <span className="text-white/80">{ep.score}</span></div><div><span className="text-white/50">Deviations:</span> <span className="text-white/80">{ep.deviations}</span></div></div></div>))}</div>)}
      {tab === "hardening_tasks" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Active Tasks</h3>{[{ n: "Disable SSH root login", h: "db-prod-02", s: "in_progress" }, { n: "Enable disk encryption", h: "win-dev-01", s: "pending" }, { n: "Configure password policy", h: "win-dev-01", s: "pending" }, { n: "Enable audit logging", h: "web-prod-01", s: "completed" }].map((t, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{t.n}</p><p className="text-xs text-white/50">{t.h}</p></div><StatusBadge status={t.s} /></div>))}</div>)}
      {tab === "metrics" && (<div className="card-surface p-6 space-y-3"><h3 className="section-heading">Hardening Trends</h3>{[{ m: "Compliance Score", v: "86.4%", t: "+3.2%" }, { m: "Critical Deviations", v: "48", t: "-12" }, { m: "Auto-Fix Success", v: "91.3%", t: "+2.1%" }, { m: "Avg Scan Time", v: "4.2s", t: "-0.8s" }].map((x, i) => (<div key={i} className="card-interactive p-4 flex items-center justify-between"><div><p className="text-white/90 font-medium">{x.m}</p><p className="text-xs text-white/50">{x.t}</p></div><span className="text-cyan-400 font-mono">{x.v}</span></div>))}</div>)}
    </div>
  );
}
